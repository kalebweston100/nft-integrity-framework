// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../hooks/HooksERC1155.sol";

/**
 * @title TestHooksERC1155
 * @notice Concrete ERC-1155 hooks for testing. Records every accessible hook invocation
 *         and exposes admin toggles to drive every branch in the token's pipeline.
 *
 * Inherits HooksERC1155Minter, so it declares IHookMinter via ERC-165 and can
 * exercise IntegrityERC1155.hookMint(). A hooks contract that does NOT need
 * minting authority should inherit plain HooksERC1155 instead.
 *
 * Transfer denial goes through _onValidateTransfer, the authoritative deny gate —
 * not through a revert in _onBeforeTransfer, which IHooksERC20 rule 2 reserves for
 * settle-only notification.
 */
contract TestHooksERC1155 is HooksERC1155Minter {
    // ─── Call Record Structs ─────────────────────────────────────────────────

    struct TransferRecord {
        address from;
        address to;
        uint256 id;
        uint256 amount;
    }

    struct MintRecord {
        address to;
        uint256 id;
        uint256 amount;
    }

    struct BurnRecord {
        address from;
        uint256 id;
        uint256 amount;
    }

    // ─── Call Logs ───────────────────────────────────────────────────────────

    TransferRecord[] public beforeTransferLog;
    TransferRecord[] public afterTransferLog;
    MintRecord[] public beforeMintLog;
    MintRecord[] public afterMintLog;
    BurnRecord[] public beforeBurnLog;
    BurnRecord[] public afterBurnLog;

    // ─── Behavior Flags (global) ─────────────────────────────────────────────

    bool public blockTransfers;
    string public blockTransferReason = "TestHooks: transfer blocked";

    bool public blockMints;
    string public blockMintReason = "TestHooks: mint blocked";

    bool public blockBurns;
    string public blockBurnReason = "TestHooks: burn blocked";

    // ─── Behavior Flags (per-tokenId) ────────────────────────────────────────

    mapping(uint256 => bool) public blockTransfersById;
    mapping(uint256 => bool) public blockMintsById;
    mapping(uint256 => bool) public blockBurnsById;
    mapping(uint256 => string) public blockMintReasonById;
    mapping(uint256 => string) public blockBurnReasonById;
    mapping(uint256 => string) public blockTransferReasonById;

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(address _issuerAdmin, string memory baseTokenURI, string memory contractURI_)
        HooksERC1155Minter(_issuerAdmin, baseTokenURI, contractURI_)
    {}

    // ─── Admin Controls (global) ─────────────────────────────────────────────

    function setBlockTransfers(bool blocked, string calldata reason) external onlyIssuerAdmin {
        blockTransfers = blocked;
        blockTransferReason = reason;
    }

    function setBlockMints(bool blocked, string calldata reason) external onlyIssuerAdmin {
        blockMints = blocked;
        blockMintReason = reason;
    }

    function setBlockBurns(bool blocked, string calldata reason) external onlyIssuerAdmin {
        blockBurns = blocked;
        blockBurnReason = reason;
    }

    // ─── Admin Controls (per-tokenId) ────────────────────────────────────────

    function setBlockTransfersById(uint256 id, bool blocked, string calldata reason) external onlyIssuerAdmin {
        blockTransfersById[id] = blocked;
        blockTransferReasonById[id] = reason;
    }

    function setBlockMintsById(uint256 id, bool blocked, string calldata reason) external onlyIssuerAdmin {
        blockMintsById[id] = blocked;
        blockMintReasonById[id] = reason;
    }

    function setBlockBurnsById(uint256 id, bool blocked, string calldata reason) external onlyIssuerAdmin {
        blockBurnsById[id] = blocked;
        blockBurnReasonById[id] = reason;
    }

    /// @notice Exercises IntegrityERC1155.hookMint() — direct hook-gated mint.
    function issuerMint(address to, uint256 id, uint256 amount) external onlyIssuerAdmin {
        _mintFromHooks(to, id, amount);
    }

    // ─── Deny Gates ──────────────────────────────────────────────────────────

    function _onValidateTransfer(address, address, uint256 id, uint256)
        internal
        view
        override
        returns (bool, string memory)
    {
        if (blockTransfersById[id]) return (false, blockTransferReasonById[id]);
        if (blockTransfers) return (false, blockTransferReason);
        return (true, "");
    }

    // ─── Notifications ───────────────────────────────────────────────────────

    function _onBeforeTransfer(address from, address to, uint256 id, uint256 amount) internal override {
        beforeTransferLog.push(TransferRecord(from, to, id, amount));
    }

    function _onAfterTransfer(address from, address to, uint256 id, uint256 amount) internal override {
        afterTransferLog.push(TransferRecord(from, to, id, amount));
    }

    function _onBeforeMint(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata /*data*/
    )
        internal
        override
        returns (bool, string memory)
    {
        beforeMintLog.push(MintRecord(to, id, amount));
        if (blockMintsById[id]) return (false, blockMintReasonById[id]);
        if (blockMints) return (false, blockMintReason);
        return (true, "");
    }

    // Called by HooksERC1155.afterMint.
    function _onAfterMint(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata /*data*/
    )
        internal
        override
    {
        afterMintLog.push(MintRecord(to, id, amount));
    }

    function _onBeforeBurn(address from, uint256 id, uint256 amount) internal override returns (bool, string memory) {
        beforeBurnLog.push(BurnRecord(from, id, amount));
        if (blockBurnsById[id]) return (false, blockBurnReasonById[id]);
        if (blockBurns) return (false, blockBurnReason);
        return (true, "");
    }

    // Called by HooksERC1155.afterBurn.
    function _onAfterBurn(address from, uint256 id, uint256 amount) internal override {
        afterBurnLog.push(BurnRecord(from, id, amount));
    }

    // ─── View Helpers ─────────────────────────────────────────────────────────

    function beforeTransferCount() external view returns (uint256) {
        return beforeTransferLog.length;
    }

    function afterTransferCount() external view returns (uint256) {
        return afterTransferLog.length;
    }

    function beforeMintCount() external view returns (uint256) {
        return beforeMintLog.length;
    }

    function afterMintCount() external view returns (uint256) {
        return afterMintLog.length;
    }

    function beforeBurnCount() external view returns (uint256) {
        return beforeBurnLog.length;
    }

    function afterBurnCount() external view returns (uint256) {
        return afterBurnLog.length;
    }

    function lastBeforeTransfer() external view returns (TransferRecord memory) {
        require(beforeTransferLog.length > 0, "No transfers recorded");
        return beforeTransferLog[beforeTransferLog.length - 1];
    }

    function lastAfterTransfer() external view returns (TransferRecord memory) {
        require(afterTransferLog.length > 0, "No after-transfers recorded");
        return afterTransferLog[afterTransferLog.length - 1];
    }

    function lastBeforeMint() external view returns (MintRecord memory) {
        require(beforeMintLog.length > 0, "No mints recorded");
        return beforeMintLog[beforeMintLog.length - 1];
    }

    function lastAfterMint() external view returns (MintRecord memory) {
        require(afterMintLog.length > 0, "No after-mints recorded");
        return afterMintLog[afterMintLog.length - 1];
    }

    function lastBeforeBurn() external view returns (BurnRecord memory) {
        require(beforeBurnLog.length > 0, "No burns recorded");
        return beforeBurnLog[beforeBurnLog.length - 1];
    }

    function lastAfterBurn() external view returns (BurnRecord memory) {
        require(afterBurnLog.length > 0, "No after-burns recorded");
        return afterBurnLog[afterBurnLog.length - 1];
    }
}
