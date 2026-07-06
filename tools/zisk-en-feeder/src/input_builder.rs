//! Bridge to the existing `zisk_input_builder` in `node/bin`.
//!
//! TODO(blocked): the real builder (`zksync_os_server::prover_input_generator::
//! zisk_input_builder::build_block_data`) needs two handles we do not yet
//! construct here:
//!   - `ReadStateHistory` — RocksDB-backed state view, matching the EN's
//!     storage layout.
//!   - `MerkleTreeVersion<RocksDBWrapper>` — secondary-mode state tree.
//!
//! Both are internal to the server today. To finish the port we either:
//!   (a) expose constructors on the storage_api / merkle_tree crates that
//!       accept a secondary-mode RocksDB handle, then call `build_block_data`
//!       directly from here — zero logic duplication, and
//!   (b) run the input build inline inside the EN process (single-process
//!       mode), skipping the secondary-mode read entirely.
//!
//! For now this function returns `None` so the feeder still runs end-to-end
//! (polls RocksDB, logs heights, posts metadata-only heartbeats to the
//! sidecar) while the heavy-lifting path is finalised.

use crate::replay_reader::ReplayData;

pub struct BuiltInputs {
    pub zisk_bincode: Vec<u8>,
    pub airbender_witness_bytes: Vec<u8>,
}

pub fn build_inputs_for_block(_replay: &ReplayData) -> Option<BuiltInputs> {
    tracing::debug!("build_inputs_for_block: not implemented yet (see input_builder.rs TODO)");
    None
}
