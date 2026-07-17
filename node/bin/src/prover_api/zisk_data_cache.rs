//! Cache for ZiSK batch data awaiting multi-proof composition.
//!
//! Stores serialized ZiSK prover input (`bincode`) per batch, populated by the
//! prover input generator when `second_proof_system` is enabled. Consumed by
//! `SnarkJobManager` after the Airbender SNARK is submitted: the data is removed
//! atomically and forwarded to `ZiskJobManager` for external ZiSK proving.
//!
//! Bounded: entries older than `max_age` are evicted, and at most `max_entries`
//! are retained. This prevents unbounded memory growth when Airbender provers
//! are slow or offline.

use crate::prover_api::metrics::{ZISK_DATA_CACHE_METRICS, ZiskCacheEvictionReason};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Default maximum number of cached entries.
const DEFAULT_MAX_ENTRIES: usize = 100;
/// Default maximum age for cached entries.
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(86400); // 24 hours

struct CacheEntry {
    data: Vec<u8>,
    inserted_at: Instant,
}

/// Thread-safe, bounded cache for ZiSK batch data.
///
/// Data flows:
/// - **In**: `FriJobManager` stores data via [`insert`] when a batch enters FRI proving.
/// - **Out**: `SnarkJobManager` removes via [`remove`] when the Airbender SNARK arrives,
///   forwarding the data to `ZiskJobManager` for external proving.
///
/// Entries are evicted when:
/// - The cache exceeds `max_entries` (oldest evicted first).
/// - An entry is older than `max_age` (evicted lazily on access).
pub struct ZiskDataCache {
    inner: Mutex<HashMap<u64, CacheEntry>>,
    max_entries: usize,
    max_age: Duration,
}

impl Default for ZiskDataCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ZiskDataCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_age: DEFAULT_MAX_AGE,
        }
    }

    pub fn with_limits(max_entries: usize, max_age: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries,
            max_age,
        }
    }

    /// Store ZiSK data for a batch. Called when the batch enters the FRI proving pipeline.
    ///
    /// Eviction is lazy: only triggered when cache exceeds `max_entries`,
    /// not on every insert.
    pub async fn insert(&self, batch_number: u64, data: Vec<u8>) {
        let mut cache = self.inner.lock().await;
        cache.insert(
            batch_number,
            CacheEntry {
                data,
                inserted_at: Instant::now(),
            },
        );
        // Only evict when over capacity — avoids O(n) scan on every insert.
        if cache.len() > self.max_entries {
            Self::evict(&mut cache, self.max_entries, self.max_age);
        }
        Self::record_gauges(&cache);
    }

    /// Check whether ZiSK data exists for a batch (non-destructive).
    pub async fn contains(&self, batch_number: u64) -> bool {
        let cache = self.inner.lock().await;
        cache
            .get(&batch_number)
            .is_some_and(|e| e.inserted_at.elapsed() < self.max_age)
    }

    /// Remove ZiSK data for a batch after successful proof generation.
    pub async fn remove(&self, batch_number: u64) -> Option<Vec<u8>> {
        let mut cache = self.inner.lock().await;
        let removed = match cache.remove(&batch_number) {
            Some(entry) if entry.inserted_at.elapsed() < self.max_age => Some(entry.data),
            Some(_) => {
                tracing::warn!(batch_number, "ZiSK data expired before consumption");
                ZISK_DATA_CACHE_METRICS.expired_on_access.inc();
                None
            }
            None => None,
        };
        Self::record_gauges(&cache);
        removed
    }

    /// Number of entries currently cached (including potentially expired ones).
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Evict expired entries and overflow (oldest first).
    fn evict(cache: &mut HashMap<u64, CacheEntry>, max_entries: usize, max_age: Duration) {
        // Remove expired entries
        let expired: Vec<u64> = cache
            .iter()
            .filter(|(_, e)| e.inserted_at.elapsed() >= max_age)
            .map(|(&k, _)| k)
            .collect();
        for k in &expired {
            tracing::warn!(batch_number = k, "evicting expired ZiSK data from cache");
            cache.remove(k);
            ZISK_DATA_CACHE_METRICS.evictions[&ZiskCacheEvictionReason::Expired].inc();
        }

        // Remove oldest entries if over capacity
        while cache.len() > max_entries {
            if let Some((&oldest_key, _)) = cache.iter().min_by_key(|(_, e)| e.inserted_at) {
                tracing::warn!(
                    batch_number = oldest_key,
                    "evicting ZiSK data (cache full, max_entries={})",
                    max_entries
                );
                cache.remove(&oldest_key);
                ZISK_DATA_CACHE_METRICS.evictions[&ZiskCacheEvictionReason::Overflow].inc();
            } else {
                break;
            }
        }
    }

    /// Refresh the size/age gauges after a mutation, under the cache lock.
    fn record_gauges(cache: &HashMap<u64, CacheEntry>) {
        ZISK_DATA_CACHE_METRICS.entries.set(cache.len() as u64);
        let oldest = cache.iter().min_by_key(|(_, e)| e.inserted_at);
        ZISK_DATA_CACHE_METRICS
            .oldest_batch_number
            .set(oldest.map(|(&k, _)| k).unwrap_or(0));
        ZISK_DATA_CACHE_METRICS.oldest_entry_age_seconds.set(
            oldest
                .map(|(_, e)| e.inserted_at.elapsed().as_secs())
                .unwrap_or(0),
        );
    }

    /// Refresh the gauges without mutating the cache. Ages only advance on
    /// mutation otherwise — a stalled pipeline would freeze them at their
    /// last (low) values, hiding exactly the condition worth alerting on.
    pub async fn refresh_gauges(&self) {
        Self::record_gauges(&*self.inner.lock().await);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Overflow evicts the oldest entry; expired entries are dropped on
    /// consumption. (Metric counters are process-global; behavior is what
    /// unit tests can assert.)
    #[tokio::test]
    async fn overflow_evicts_oldest_and_expiry_drops_on_access() {
        let cache = ZiskDataCache::with_limits(2, Duration::from_secs(3600));
        cache.insert(1, vec![1]).await;
        cache.insert(2, vec![2]).await;
        cache.insert(3, vec![3]).await;

        assert_eq!(cache.len().await, 2);
        assert!(!cache.contains(1).await, "oldest entry must be evicted");
        assert_eq!(cache.remove(2).await, Some(vec![2]));
        assert_eq!(cache.remove(3).await, Some(vec![3]));

        let expiring = ZiskDataCache::with_limits(2, Duration::ZERO);
        expiring.insert(4, vec![4]).await;
        assert!(!expiring.contains(4).await);
        assert_eq!(
            expiring.remove(4).await,
            None,
            "expired data must not be served"
        );
    }
}
