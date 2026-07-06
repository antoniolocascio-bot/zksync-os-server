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
        cache.insert(batch_number, CacheEntry {
            data,
            inserted_at: Instant::now(),
        });
        // Only evict when over capacity — avoids O(n) scan on every insert.
        if cache.len() > self.max_entries {
            Self::evict(&mut cache, self.max_entries, self.max_age);
        }
    }

    /// Check whether ZiSK data exists for a batch (non-destructive).
    pub async fn contains(&self, batch_number: u64) -> bool {
        let cache = self.inner.lock().await;
        cache.get(&batch_number)
            .is_some_and(|e| e.inserted_at.elapsed() < self.max_age)
    }

    /// Remove ZiSK data for a batch after successful proof generation.
    pub async fn remove(&self, batch_number: u64) -> Option<Vec<u8>> {
        let mut cache = self.inner.lock().await;
        match cache.remove(&batch_number) {
            Some(entry) if entry.inserted_at.elapsed() < self.max_age => Some(entry.data),
            Some(_) => {
                tracing::warn!(batch_number, "ZiSK data expired before consumption");
                None
            }
            None => None,
        }
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
        let expired: Vec<u64> = cache.iter()
            .filter(|(_, e)| e.inserted_at.elapsed() >= max_age)
            .map(|(&k, _)| k)
            .collect();
        for k in &expired {
            tracing::warn!(batch_number = k, "evicting expired ZiSK data from cache");
            cache.remove(k);
        }

        // Remove oldest entries if over capacity
        while cache.len() > max_entries {
            if let Some((&oldest_key, _)) = cache.iter()
                .min_by_key(|(_, e)| e.inserted_at)
            {
                tracing::warn!(batch_number = oldest_key, "evicting ZiSK data (cache full, max_entries={})", max_entries);
                cache.remove(&oldest_key);
            } else {
                break;
            }
        }
    }
}
