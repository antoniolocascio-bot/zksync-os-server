//! Shared constants for ZiSK proof sizes and system contract addresses.
//!
//! These are invariants of the ZiSK Plonk verifier circuit and the ZKsync OS
//! storage layout. Imported by `zisk_prover`, `prove.rs`, and `zisk_input_builder`.

/// ZiSK SNARK proof size: 24 BN254 points × 32 bytes = 768 bytes.
pub const ZISK_SNARK_PROOF_BYTES: usize = 768;

/// ZiSK public values size: 8 × 32-byte uint256 slots = 256 bytes.
pub const ZISK_PUBLIC_VALUES_BYTES: usize = 256;

/// ERC-1967 implementation storage slot.
/// `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`
pub const ERC1967_IMPLEMENTATION_SLOT: &str =
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";

/// ZKsync OS ComplexUpgrader proxy address (system contract at 0x800f).
pub const COMPLEX_UPGRADER_ADDRESS: &str = "0x000000000000000000000000000000000000800f";
