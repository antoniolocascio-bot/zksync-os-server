//! Shared constants for ZiSK proof sizes and system contract addresses.
//!
//! These are invariants of the ZiSK Plonk verifier circuit and the ZKsync OS
//! storage layout. Imported by `zisk_prover`, `prove.rs`, and `zisk_input_builder`.

/// ZiSK SNARK proof size: 24 BN254 points × 32 bytes = 768 bytes.
pub const ZISK_SNARK_PROOF_BYTES: usize = 768;

/// ZiSK public values size: 320 bytes.
// 320 = programVK(32) + guest publics(256: ziskos's full 64-word output
// region, the guest's 8 commitment words first, zeros after) + vadcopVK(32).
// Settled against a real cargo-zisk v0.18 proof file (plan 2.1): the
// draft-era 256/192 assumption undercounted the publics region. The
// commitment stays at [32..64]. NOTE: the on-chain ZiskVerifier's digest
// reconstruction must use the same 320-byte preimage (task 7.x/8).
pub const ZISK_PUBLIC_VALUES_BYTES: usize = 320;

/// ERC-1967 implementation storage slot.
/// `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`
pub const ERC1967_IMPLEMENTATION_SLOT: &str =
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/// ZKsync OS ComplexUpgrader proxy address (system contract at 0x800f).
pub const COMPLEX_UPGRADER_ADDRESS: &str = "0x000000000000000000000000000000000000800f";
