// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal stand-in for the v31 `SystemContext` (0x800b), for upgrade tests
/// on chains whose genesis predates it. The genesis deployment is a
/// transparent proxy plus a delegate-only implementation and seeded EIP-1967
/// storage slots — force deployments can install code but not storage, so
/// the real pair cannot be reproduced by an upgrade tx. This contract keeps
/// the two properties the protocol actually depends on:
///
/// - `setSettlementLayerChainId` stores the chain id in storage slot 0 (the
///   slot the STF's batch-output computation reads), and
/// - emits `SettlementLayerChainIdUpdated(uint256 indexed)` — byte-exact
///   signature `0x208daf0b…`, one indexed topic, empty data — which the
///   STF's system-context event hook mirrors into its in-block tracker.
contract SystemContextV31 {
    event SettlementLayerChainIdUpdated(uint256 indexed newChainId);

    uint256 public settlementLayerChainId; // slot 0

    function setSettlementLayerChainId(uint256 _newChainId) external {
        settlementLayerChainId = _newChainId;
        emit SettlementLayerChainIdUpdated(_newChainId);
    }
}
