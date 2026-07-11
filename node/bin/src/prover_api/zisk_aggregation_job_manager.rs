//! Job-manager SCAFFOLDING for the ZiSK AGGREGATION stage (plan 2.7).
//!
//! Mirrors the Airbender FRI→SNARK split on the ZiSK lane: per-batch ZiSK
//! proofs keep the existing pick/submit flow (`ZiskJobManager`), and an
//! aggregation job consumes a RANGE of contiguous completed per-batch
//! proofs to produce one range proof for L1 — the aggregator guest, which
//! verifies N `vadcop_final` proofs and chains their batch commitments
//! (`zksync-os-zisk/guest-aggregator`).
//!
//! Scaffolding boundaries (all deliberate, revisited with era-contracts
//! task 8):
//! - Inputs are fed as COPIES of accepted per-batch proofs
//!   (`ZiskJobManager::submit_proof` → [`Self::on_proof_completed`]); the
//!   per-batch `completed` map and its MultiProof rendezvous are untouched,
//!   so enabling this stage cannot disturb the existing L1 flow.
//! - The payload hands out the per-batch PLONK-wrapped proofs the server
//!   holds today. The real aggregator guest consumes the pre-wrap
//!   `vadcop_final` streams (~328 KiB each), which the daemon currently
//!   discards after wrapping — extending the daemon to retain/submit them
//!   is part of the aggregator rollout, not this scaffolding.
//! - An accepted aggregated proof is validated (sizes + the aggregator
//!   guest's binding-digest math over the buffered per-batch public
//!   values) and then only recorded/logged; nothing is sent downstream.
//!
//! Range formation: ranges are `[from..from + range_size - 1]`, strictly
//! sequential. The first range starts at the lowest buffered batch at the
//! moment a full contiguous run exists; each accepted (or discarded) range
//! advances the floor. Per-batch proofs arriving below the floor — e.g. a
//! slow prover finishing after its neighbours already formed a range — are
//! dropped: their batches can no longer join any future range.

use alloy::primitives::{B256, keccak256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::prover_api::zisk_proof_constants::{ZISK_PUBLIC_VALUES_BYTES, ZISK_SNARK_PROOF_BYTES};

/// Cap on buffered per-batch inputs (each ~1.1 KiB today, ~330 KiB once
/// the payload switches to vadcop_final streams). When full, new arrivals
/// are dropped with a warning — aggregation is best-effort scaffolding.
const MAX_BUFFERED_INPUTS: usize = 64;

/// Accepted aggregated proofs kept for inspection (`take_recorded`).
const MAX_RECORDED: usize = 16;

/// Offsets inside a 320-byte per-batch public-values blob:
/// `programVK(32, u64 words BE) ‖ publics(256) ‖ vadcopVK(32, u64 words BE)`;
/// the batch commitment is publics bytes [0..32], i.e. blob bytes [32..64].
const PV_PROGRAM_VK: std::ops::Range<usize> = 0..32;
const PV_COMMITMENT: std::ops::Range<usize> = 32..64;
const PV_VADCOP_VK: std::ops::Range<usize> = 288..320;

/// A copy of an accepted per-batch ZiSK proof, buffered as aggregation input.
#[derive(Clone)]
pub struct PerBatchProof {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
}

/// An aggregation job handed to a prover: the N per-batch proofs of a
/// contiguous range, in batch order.
pub struct ZiskAggregationJob {
    pub from_batch: u64,
    pub to_batch: u64,
    pub proofs: Vec<(u64, PerBatchProof)>,
}

/// An accepted aggregated range proof (recorded only — L1 wiring is task 8).
pub struct RecordedAggregatedProof {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum ZiskAggregationSubmitError {
    #[error("unknown or unassigned range {from}..{to}")]
    UnknownRange { from: u64, to: u64 },
    #[error("invalid proof size: {got} bytes, expected {expected}")]
    InvalidProofSize { got: usize, expected: usize },
    #[error("invalid public values size: {got} bytes, expected {expected}")]
    InvalidPublicValuesSize { got: usize, expected: usize },
    #[error("aggregated commitment mismatch: {0}")]
    CommitmentMismatch(String),
}

struct State {
    /// Buffered per-batch proofs, keyed by batch number.
    inputs: BTreeMap<u64, PerBatchProof>,
    /// First batch of the next range to form. `None` until the first range
    /// forms (then: lowest buffered batch at formation time).
    next_from: Option<u64>,
    /// Formed ranges awaiting (re)assignment.
    pickable: VecDeque<(u64, u64)>,
    /// Assigned ranges: (prover id, assigned at). Inputs stay buffered
    /// while assigned so a timed-out range is re-served identically.
    assigned: HashMap<(u64, u64), (String, Instant)>,
    /// Accepted aggregated proofs, newest last, bounded by `MAX_RECORDED`.
    recorded: BTreeMap<(u64, u64), RecordedAggregatedProof>,
}

/// Manages ZiSK aggregation jobs with the same pick/submit assignment
/// model as the other prover stages.
pub struct ZiskAggregationJobManager {
    state: Mutex<State>,
    range_size: u64,
    assignment_timeout: Duration,
}

impl ZiskAggregationJobManager {
    pub fn new(range_size: usize, assignment_timeout: Duration) -> Self {
        assert!(range_size >= 1, "zisk_aggregation.range_size must be >= 1");
        Self {
            state: Mutex::new(State {
                inputs: BTreeMap::new(),
                next_from: None,
                pickable: VecDeque::new(),
                assigned: HashMap::new(),
                recorded: BTreeMap::new(),
            }),
            range_size: range_size as u64,
            assignment_timeout,
        }
    }

    /// Feed one accepted per-batch ZiSK proof (called by
    /// `ZiskJobManager::submit_proof` with a copy; validation already done
    /// there). Idempotent per batch; arrivals below the range floor or
    /// beyond the buffer cap are dropped.
    pub async fn on_proof_completed(&self, batch_number: u64, proof: Vec<u8>, public_values: Vec<u8>) {
        let mut state = self.state.lock().await;
        if let Some(next_from) = state.next_from
            && batch_number < next_from
        {
            tracing::warn!(
                batch = batch_number,
                next_from,
                "ZiSK aggregation: proof arrived below the range floor — batch can no longer join a range, dropping"
            );
            return;
        }
        if state.inputs.contains_key(&batch_number) {
            return;
        }
        if state.inputs.len() >= MAX_BUFFERED_INPUTS {
            tracing::warn!(
                batch = batch_number,
                buffered = state.inputs.len(),
                "ZiSK aggregation input buffer full — dropping proof (aggregation provers offline?)"
            );
            return;
        }
        tracing::debug!(batch = batch_number, "ZiSK aggregation input buffered");
        state.inputs.insert(batch_number, PerBatchProof { proof, public_values });
    }

    /// Pick the next aggregation job: first re-offer timed-out assignments,
    /// then try to form one new range from contiguous buffered inputs.
    pub async fn pick_next_job(&self, prover_id: &str) -> Option<ZiskAggregationJob> {
        let now = Instant::now();
        let mut state = self.state.lock().await;

        // Return timed-out assigned ranges to the pickable queue.
        let timed_out: Vec<(u64, u64)> = state
            .assigned
            .iter()
            .filter(|(_, (_, at))| now.duration_since(*at) >= self.assignment_timeout)
            .map(|(&range, _)| range)
            .collect();
        for range in timed_out {
            if let Some((old_prover, _)) = state.assigned.remove(&range) {
                tracing::warn!(
                    from = range.0,
                    to = range.1,
                    old_prover,
                    "ZiSK aggregation job timed out, returning to queue"
                );
                state.pickable.push_back(range);
            }
        }

        // Form at most one new range: [from..from+K-1] where `from` is the
        // floor (or the lowest buffered batch before the first formation)
        // and every batch of the range is buffered.
        if state.pickable.is_empty() {
            let from = state.next_from.or_else(|| state.inputs.keys().next().copied())?;
            let to = from + self.range_size - 1;
            if (from..=to).all(|b| state.inputs.contains_key(&b)) {
                tracing::info!(from, to, "ZiSK aggregation range formed");
                state.pickable.push_back((from, to));
                state.next_from = Some(to + 1);
            }
        }

        let (from, to) = state.pickable.pop_front()?;
        let proofs: Vec<(u64, PerBatchProof)> = (from..=to)
            .map(|b| {
                let input = state
                    .inputs
                    .get(&b)
                    .expect("formed range implies buffered inputs; discards drop overlapping ranges")
                    .clone();
                (b, input)
            })
            .collect();
        state.assigned.insert((from, to), (prover_id.to_string(), now));
        tracing::info!(from, to, prover_id, "ZiSK aggregation job assigned");
        Some(ZiskAggregationJob { from_batch: from, to_batch: to, proofs })
    }

    /// Submit an aggregated range proof. Validates sizes and that the
    /// proof's committed value equals the aggregator guest's binding
    /// digest over the buffered per-batch public values, then records it.
    /// L1 submission is explicitly out of scope until era-contracts task 8.
    pub async fn submit_proof(
        &self,
        from_batch: u64,
        to_batch: u64,
        proof: Vec<u8>,
        public_values: Vec<u8>,
        prover_id: &str,
    ) -> Result<(), ZiskAggregationSubmitError> {
        if proof.len() != ZISK_SNARK_PROOF_BYTES {
            return Err(ZiskAggregationSubmitError::InvalidProofSize {
                got: proof.len(),
                expected: ZISK_SNARK_PROOF_BYTES,
            });
        }
        if public_values.len() != ZISK_PUBLIC_VALUES_BYTES {
            return Err(ZiskAggregationSubmitError::InvalidPublicValuesSize {
                got: public_values.len(),
                expected: ZISK_PUBLIC_VALUES_BYTES,
            });
        }

        let mut state = self.state.lock().await;
        let range = (from_batch, to_batch);
        if state.assigned.remove(&range).is_none() {
            return Err(ZiskAggregationSubmitError::UnknownRange {
                from: from_batch,
                to: to_batch,
            });
        }

        // The guest binds (inner program VK, vadcop VK, rolling commitment
        // keccak) into its single committed word — recompute it from the
        // per-batch public values this manager buffered.
        let per_batch_pvs: Vec<&[u8]> = match (from_batch..=to_batch)
            .map(|b| state.inputs.get(&b).map(|i| i.public_values.as_slice()))
            .collect::<Option<Vec<_>>>()
        {
            Some(pvs) => pvs,
            None => {
                // Cannot happen while discards drop overlapping ranges;
                // defensive so a logic slip fails loudly, not silently.
                return Err(ZiskAggregationSubmitError::UnknownRange {
                    from: from_batch,
                    to: to_batch,
                });
            }
        };
        let expected = match expected_aggregated_commitment(&per_batch_pvs) {
            Ok(digest) => digest,
            Err(msg) => {
                state.pickable.push_back(range);
                return Err(ZiskAggregationSubmitError::CommitmentMismatch(msg));
            }
        };
        let got = B256::from_slice(&public_values[PV_COMMITMENT]);
        if got != expected {
            tracing::error!(
                from = from_batch,
                to = to_batch,
                prover_id,
                %got,
                %expected,
                "aggregated ZiSK proof commitment mismatch — requeueing range"
            );
            state.pickable.push_back(range);
            return Err(ZiskAggregationSubmitError::CommitmentMismatch(format!(
                "committed digest {got} does not match expected {expected}"
            )));
        }

        for b in from_batch..=to_batch {
            state.inputs.remove(&b);
        }
        tracing::info!(
            from = from_batch,
            to = to_batch,
            prover_id,
            aggregated_program_vk = %B256::from_slice(&public_values[PV_PROGRAM_VK]),
            commitment = %got,
            "aggregated ZiSK proof accepted and recorded (L1 wiring pending — era-contracts task 8)"
        );
        state.recorded.insert(range, RecordedAggregatedProof { proof, public_values });
        while state.recorded.len() > MAX_RECORDED {
            let oldest = *state.recorded.keys().next().expect("non-empty");
            state.recorded.remove(&oldest);
        }
        Ok(())
    }

    /// Take a recorded aggregated proof (tests + future L1 wiring).
    pub async fn take_recorded(&self, from_batch: u64, to_batch: u64) -> Option<RecordedAggregatedProof> {
        self.state.lock().await.recorded.remove(&(from_batch, to_batch))
    }

    /// Drop aggregation state for batches at or below `batch_to`: called
    /// when those batches were consumed without a (multi-)proof (fake-SNARK
    /// pass, degraded sends) — they can never join a range anymore. Formed
    /// or assigned ranges overlapping the cut are dropped whole, including
    /// their above-the-cut inputs (a broken range never completes), and the
    /// floor advances past the cut.
    pub async fn discard_up_to(&self, batch_to: u64) {
        let mut state = self.state.lock().await;

        let broken: Vec<(u64, u64)> = state
            .pickable
            .iter()
            .copied()
            .chain(state.assigned.keys().copied())
            .filter(|&(from, _)| from <= batch_to)
            .collect();
        for (from, to) in &broken {
            state.pickable.retain(|r| r != &(*from, *to));
            state.assigned.remove(&(*from, *to));
            for b in *from..=*to {
                state.inputs.remove(&b);
            }
            // Undo the formation's floor advance: the range never completed,
            // so the floor rolls back to its start before the cut applies.
            // (Broken ranges sit above every ACCEPTED range, whose floor
            // advance must stick — ranges are strictly sequential.)
            if let Some(next_from) = state.next_from
                && *from < next_from
            {
                state.next_from = Some(*from);
            }
            tracing::info!(
                from,
                to,
                batch_to,
                "ZiSK aggregation range dropped — overlaps batches sent without aggregation"
            );
        }

        let stale: Vec<u64> = state.inputs.range(..=batch_to).map(|(&b, _)| b).collect();
        for b in stale {
            state.inputs.remove(&b);
        }
        if let Some(next_from) = state.next_from
            && next_from <= batch_to
        {
            state.next_from = Some(batch_to + 1);
        }
    }
}

/// The aggregator guest's binding digest, recomputed server-side from the
/// per-batch 320-byte public-values blobs of a range (in batch order):
///
/// ```text
/// keccak256(inner_program_vk LE ‖ inner_vadcop_vk LE ‖ rolling)
/// rolling = fold(keccak256, [0u8; 32], commitment_1 .. commitment_N)
/// ```
///
/// The wire blobs carry the VK words BIG-endian; the guest hashes them as
/// 8-byte LITTLE-endian words, so each 8-byte word is reversed here. All
/// batches must share one inner (program VK, vadcop VK) pair — the guest
/// enforces the same rule.
///
/// Must match `Aggregator::finalize` in
/// `zksync-os-zisk/guest-aggregator/src/lib.rs`; the shared test vector
/// (`shared_vector_digest_matches_guest`) pins the two together.
pub fn expected_aggregated_commitment(per_batch_public_values: &[&[u8]]) -> Result<B256, String> {
    if per_batch_public_values.is_empty() {
        return Err("empty range".into());
    }
    let mut rolling = [0u8; 32];
    let first = per_batch_public_values[0];
    for (i, pv) in per_batch_public_values.iter().enumerate() {
        if pv.len() != ZISK_PUBLIC_VALUES_BYTES {
            return Err(format!(
                "batch #{i} public values are {} bytes, expected {ZISK_PUBLIC_VALUES_BYTES}",
                pv.len()
            ));
        }
        if pv[PV_PROGRAM_VK] != first[PV_PROGRAM_VK] {
            return Err(format!("batch #{i} inner program VK differs within the range"));
        }
        if pv[PV_VADCOP_VK] != first[PV_VADCOP_VK] {
            return Err(format!("batch #{i} inner vadcop VK differs within the range"));
        }
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&rolling);
        preimage[32..].copy_from_slice(&pv[PV_COMMITMENT]);
        rolling = keccak256(preimage).0;
    }

    let mut binding = [0u8; 96];
    for (be_word, le_out) in first[PV_PROGRAM_VK]
        .chunks_exact(8)
        .zip(binding[..32].chunks_exact_mut(8))
    {
        for (i, b) in be_word.iter().rev().enumerate() {
            le_out[i] = *b;
        }
    }
    for (be_word, le_out) in first[PV_VADCOP_VK]
        .chunks_exact(8)
        .zip(binding[32..64].chunks_exact_mut(8))
    {
        for (i, b) in be_word.iter().rev().enumerate() {
            le_out[i] = *b;
        }
    }
    binding[64..].copy_from_slice(&rolling);
    Ok(keccak256(binding))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: usize = 4;

    fn manager() -> ZiskAggregationJobManager {
        ZiskAggregationJobManager::new(K, Duration::from_secs(60))
    }

    /// A 320-byte per-batch public-values blob with the shared-vector
    /// inner VKs (program VK words 1..4, vadcop VK words 5..8, big-endian
    /// on the wire) and a commitment of 32 repeated `commitment_byte`s.
    fn pv(commitment_byte: u8) -> Vec<u8> {
        let mut pv = vec![0u8; ZISK_PUBLIC_VALUES_BYTES];
        for (i, w) in [1u64, 2, 3, 4].iter().enumerate() {
            pv[i * 8..(i + 1) * 8].copy_from_slice(&w.to_be_bytes());
        }
        pv[PV_COMMITMENT].fill(commitment_byte);
        for (i, w) in [5u64, 6, 7, 8].iter().enumerate() {
            pv[288 + i * 8..288 + (i + 1) * 8].copy_from_slice(&w.to_be_bytes());
        }
        pv
    }

    async fn feed(manager: &ZiskAggregationJobManager, batch: u64) {
        manager
            .on_proof_completed(batch, vec![batch as u8; ZISK_SNARK_PROOF_BYTES], pv(batch as u8))
            .await;
    }

    /// Valid aggregated public values for a range: the binding digest in
    /// the commitment slot.
    fn aggregated_pv(digest: B256) -> Vec<u8> {
        let mut pv = vec![0u8; ZISK_PUBLIC_VALUES_BYTES];
        pv[PV_COMMITMENT].copy_from_slice(digest.as_slice());
        pv
    }

    /// Shared cross-crate test vector: the aggregator guest's lib test
    /// (`binding_digest_shared_vector` in
    /// zksync-os-zisk/guest-aggregator/src/lib.rs) asserts the same digest
    /// for the same inputs. Update both together.
    #[test]
    fn shared_vector_digest_matches_guest() {
        let pvs = [pv(0x11), pv(0x22)];
        let refs: Vec<&[u8]> = pvs.iter().map(|p| p.as_slice()).collect();
        let digest = expected_aggregated_commitment(&refs).unwrap();
        assert_eq!(
            format!("{digest:x}"),
            // Same un-prefixed literal as SHARED_VECTOR_DIGEST in the guest test.
            "f73b9b6beae4a1c5e9597a42e7c51a8ab67a0e234f0c03e488cc604fd2b711a5"
        );
    }

    #[test]
    fn commitment_rejects_mixed_inner_vks() {
        let a = pv(0x11);
        let mut b = pv(0x22);
        b[0] ^= 0xFF; // program VK
        let err = expected_aggregated_commitment(&[&a, &b]).unwrap_err();
        assert!(err.contains("program VK"), "{err}");

        let mut c = pv(0x22);
        c[289] ^= 0xFF; // vadcop VK
        let err = expected_aggregated_commitment(&[&a, &c]).unwrap_err();
        assert!(err.contains("vadcop VK"), "{err}");
    }

    /// Out-of-order per-batch completion still forms the range once the
    /// contiguous run is complete, and the job carries the proofs in batch
    /// order.
    #[tokio::test]
    async fn out_of_order_completion_forms_range() {
        let manager = manager();
        for batch in [9u64, 7, 10, 8] {
            feed(&manager, batch).await;
            if batch != 8 {
                assert!(
                    manager.pick_next_job("agg-1").await.is_none(),
                    "incomplete run must not form a range (after batch {batch})"
                );
            }
        }
        let job = manager.pick_next_job("agg-1").await.expect("range formed");
        assert_eq!((job.from_batch, job.to_batch), (7, 10));
        let batches: Vec<u64> = job.proofs.iter().map(|(b, _)| *b).collect();
        assert_eq!(batches, vec![7, 8, 9, 10]);
        assert!(manager.pick_next_job("agg-2").await.is_none(), "no second range yet");
    }

    /// A gap blocks formation until it fills; batches beyond the gap wait.
    #[tokio::test]
    async fn gap_blocks_range_formation() {
        let manager = manager();
        for batch in [1u64, 2, 4, 5] {
            feed(&manager, batch).await;
        }
        assert!(manager.pick_next_job("agg-1").await.is_none(), "gap at 3");
        feed(&manager, 3).await;
        let job = manager.pick_next_job("agg-1").await.expect("gap filled");
        assert_eq!((job.from_batch, job.to_batch), (1, 4));
    }

    /// Accepted ranges advance the floor: the next range continues where
    /// the previous ended, and a proof arriving below the floor is dropped.
    #[tokio::test]
    async fn sequential_ranges_and_floor() {
        let manager = manager();
        for batch in 5..=8u64 {
            feed(&manager, batch).await;
        }
        let job = manager.pick_next_job("agg-1").await.expect("range 5..8");
        let pvs: Vec<&[u8]> = job.proofs.iter().map(|(_, p)| p.public_values.as_slice()).collect();
        let digest = expected_aggregated_commitment(&pvs).unwrap();
        manager
            .submit_proof(5, 8, vec![0; ZISK_SNARK_PROOF_BYTES], aggregated_pv(digest), "agg-1")
            .await
            .expect("valid aggregated proof accepted");
        assert!(manager.take_recorded(5, 8).await.is_some(), "recorded exactly once");
        assert!(manager.take_recorded(5, 8).await.is_none());

        // Late arrival below the floor is dropped: it can never range.
        feed(&manager, 4).await;
        for batch in 9..=11u64 {
            feed(&manager, batch).await;
        }
        assert!(
            manager.pick_next_job("agg-1").await.is_none(),
            "9..12 incomplete; 4 must not resurrect a lower range"
        );
        feed(&manager, 12).await;
        let job = manager.pick_next_job("agg-1").await.expect("range 9..12");
        assert_eq!((job.from_batch, job.to_batch), (9, 12));
    }

    /// Timeout reassignment: an assigned range whose prover vanished is
    /// re-offered with identical proofs.
    #[tokio::test]
    async fn timeout_reassigns_range() {
        let manager = ZiskAggregationJobManager::new(K, Duration::ZERO);
        for batch in 1..=4u64 {
            feed(&manager, batch).await;
        }
        let job_a = manager.pick_next_job("agg-a").await.expect("assigned to A");
        // Zero timeout: immediately reassignable.
        let job_b = manager.pick_next_job("agg-b").await.expect("reassigned to B");
        assert_eq!((job_b.from_batch, job_b.to_batch), (job_a.from_batch, job_a.to_batch));
        assert_eq!(job_b.proofs[0].1.proof, job_a.proofs[0].1.proof);
    }

    /// Submissions for unknown/unassigned ranges are rejected; a wrong
    /// aggregated commitment requeues the range for another prover.
    #[tokio::test]
    async fn submit_validation() {
        let manager = manager();
        for batch in 1..=4u64 {
            feed(&manager, batch).await;
        }
        // Not picked yet -> unknown.
        let err = manager
            .submit_proof(1, 4, vec![0; ZISK_SNARK_PROOF_BYTES], aggregated_pv(B256::ZERO), "agg-1")
            .await
            .expect_err("unassigned range");
        assert!(matches!(err, ZiskAggregationSubmitError::UnknownRange { .. }));

        let job = manager.pick_next_job("agg-1").await.expect("job");

        // Bad sizes.
        let err = manager
            .submit_proof(1, 4, vec![0; 3], aggregated_pv(B256::ZERO), "agg-1")
            .await
            .expect_err("bad proof size");
        assert!(matches!(err, ZiskAggregationSubmitError::InvalidProofSize { .. }));

        // Wrong digest -> rejected, range requeued and re-pickable.
        let err = manager
            .submit_proof(1, 4, vec![0; ZISK_SNARK_PROOF_BYTES], aggregated_pv(B256::ZERO), "agg-1")
            .await
            .expect_err("wrong digest");
        assert!(matches!(err, ZiskAggregationSubmitError::CommitmentMismatch(_)));
        let requeued = manager.pick_next_job("agg-2").await.expect("requeued range");
        assert_eq!((requeued.from_batch, requeued.to_batch), (1, 4));

        // Correct digest accepted.
        let pvs: Vec<&[u8]> = job.proofs.iter().map(|(_, p)| p.public_values.as_slice()).collect();
        let digest = expected_aggregated_commitment(&pvs).unwrap();
        manager
            .submit_proof(1, 4, vec![0; ZISK_SNARK_PROOF_BYTES], aggregated_pv(digest), "agg-2")
            .await
            .expect("accepted");
        assert!(manager.take_recorded(1, 4).await.is_some());
    }

    /// Discards drop overlapping formed/assigned ranges whole (including
    /// their above-the-cut inputs) and advance the floor; unaffected
    /// buffered inputs still form later ranges.
    #[tokio::test]
    async fn discard_interactions() {
        let manager = manager();

        // Discard before any formation: buffered inputs at/below the cut go.
        for batch in 1..=3u64 {
            feed(&manager, batch).await;
        }
        manager.discard_up_to(2).await;
        // Batch 3 survives and anchors the first range at 3.
        for batch in 4..=6u64 {
            feed(&manager, batch).await;
        }
        let job = manager.pick_next_job("agg-1").await.expect("range 3..6");
        assert_eq!((job.from_batch, job.to_batch), (3, 6));

        // Discard cutting into the assigned range drops it whole: the
        // submit is rejected and its above-the-cut inputs (5, 6) are gone.
        manager.discard_up_to(4).await;
        let pvs: Vec<&[u8]> = job.proofs.iter().map(|(_, p)| p.public_values.as_slice()).collect();
        let digest = expected_aggregated_commitment(&pvs).unwrap();
        let err = manager
            .submit_proof(3, 6, vec![0; ZISK_SNARK_PROOF_BYTES], aggregated_pv(digest), "agg-1")
            .await
            .expect_err("range dropped by discard");
        assert!(matches!(err, ZiskAggregationSubmitError::UnknownRange { .. }));

        // Next range starts past the cut with fresh inputs.
        for batch in 5..=8u64 {
            feed(&manager, batch).await;
        }
        // 5..8 would overlap the dropped range's tail — the floor moved to
        // 5 (past the cut at 4), so it forms cleanly.
        let job = manager.pick_next_job("agg-1").await.expect("range 5..8");
        assert_eq!((job.from_batch, job.to_batch), (5, 8));
    }

    /// Feeding the same batch twice keeps the first proof (idempotence).
    #[tokio::test]
    async fn duplicate_feed_is_idempotent() {
        let manager = manager();
        manager
            .on_proof_completed(1, vec![0xAA; ZISK_SNARK_PROOF_BYTES], pv(0xAA))
            .await;
        manager
            .on_proof_completed(1, vec![0xBB; ZISK_SNARK_PROOF_BYTES], pv(0xBB))
            .await;
        for batch in 2..=4u64 {
            feed(&manager, batch).await;
        }
        let job = manager.pick_next_job("agg-1").await.expect("range");
        assert_eq!(job.proofs[0].1.proof, vec![0xAA; ZISK_SNARK_PROOF_BYTES]);
    }
}
