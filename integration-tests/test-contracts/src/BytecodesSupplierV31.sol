// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal, event-compatible stand-in for the v31 `BytecodesSupplier`
/// (era-contracts `draft-v31-with-zksync-os`): lets tests exercise the
/// production force-deployment preimage flow on a v30-era L1, where the
/// real supplier is only deployed by the v31 ecosystem upgrade itself.
/// The server discovers preimages purely from `EVMBytecodePublished`
/// events (`bytecodeHash = keccak256(bytecode)`), which this contract
/// emits with the exact production signature.
contract BytecodesSupplierV31 {
    event EVMBytecodePublished(bytes32 indexed bytecodeHash, bytes bytecode);

    /// bytecodeHash => L1 block number of publication (0 = unpublished).
    mapping(bytes32 => uint256) public publishingBlock;

    function publishEVMBytecode(bytes calldata _bytecode) public {
        bytes32 bytecodeHash = keccak256(_bytecode);
        if (publishingBlock[bytecodeHash] == 0) {
            publishingBlock[bytecodeHash] = block.number;
            emit EVMBytecodePublished(bytecodeHash, _bytecode);
        }
    }

    function publishEVMBytecodes(bytes[] calldata _bytecodes) external {
        for (uint256 i = 0; i < _bytecodes.length; ++i) {
            publishEVMBytecode(_bytecodes[i]);
        }
    }
}
