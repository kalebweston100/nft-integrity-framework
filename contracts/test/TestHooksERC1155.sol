// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../hooks/HooksERC1155.sol";

/**
 * @title TestHooksERC1155
 * @notice Concrete ERC-1155 hooks for testing. Records every accessible hook invocation
 *         and exposes admin toggles to drive every branch in the token's pipeline.
 *
 * HOOK COVERAGE:
 *   beforeTransfer  – recorded; optional revert (global or per-tokenId)
 *   afterTransfer   – recorded (virtual in base, not overridden by HooksERC1155)
 *   beforeMint      – recorded; optional (false, reason) global or per-tokenId
 *   afterMint       – recorded via _onAfterMint
 *   beforeBurn      – recorded; optional (false, reason) global or per-tokenId
 *   afterBurn       – recorded via _onAfterBurn
 *   hookMint path   – issuerMint() exercises IntegrityERC1155.hookMint()
 *
 * LIMITATIONS:
 *   validateTransfer, beforeSetURI, afterSetURI, onTransferBlocked are not
 *   virtual in HooksERC1155 and cannot be overridden; test those paths via
 *   token-side effects.
 */
contract TestHooksERC1155 is HooksERC1155 {
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

    bool public revertOnTransfer;
    string public transferRevertReason = "TestHooks: transfer blocked";

    bool public blockMints;
    string public blockMintReason = "TestHooks: mint blocked";

    bool public blockBurns;
    string public blockBurnReason = "TestHooks: burn blocked";

    // ─── Behavior Flags (per-tokenId) ────────────────────────────────────────

    mapping(uint256 => bool) public revertOnTransferById;
    mapping(uint256 => bool) public blockMintsById;
    mapping(uint256 => bool) public blockBurnsById;
    mapping(uint256 => string) public blockMintReasonById;
    mapping(uint256 => string) public blockBurnReasonById;
    mapping(uint256 => string) public transferRevertReasonById;

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(address _issuerAdmin, string memory baseTokenURI, string memory contractURI_)
        HooksERC1155(_issuerAdmin, baseTokenURI, contractURI_)
    {}

    // ─── Admin Controls (global) ─────────────────────────────────────────────

    function setRevertOnTransfer(bool blocked, string calldata reason) external onlyIssuerAdmin {
        revertOnTransfer = blocked;
        transferRevertReason = reason;
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

    function setRevertOnTransferById(uint256 id, bool blocked, string calldata reason) external onlyIssuerAdmin {
        revertOnTransferById[id] = blocked;
        transferRevertReasonById[id] = reason;
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
    function issuerMint(address to, uint256 id, uint256 amount, uint256 flags, bytes32 metadataHash)
        external
        onlyIssuerAdmin
    {
        _mintFromHooks(to, id, amount, flags, metadataHash);
    }

    // ─── Hook Overrides ──────────────────────────────────────────────────────

    function _onBeforeTransfer(address from, address to, uint256 id, uint256 amount) internal override {
        beforeTransferLog.push(TransferRecord(from, to, id, amount));
        if (revertOnTransfer || revertOnTransferById[id]) {
            string memory reason = revertOnTransferById[id] ? transferRevertReasonById[id] : transferRevertReason;
            revert(reason);
        }
    }

    // afterTransfer is virtual in HooksERC1155 (unlike ERC-20/721) so a hooks
    // author can override it directly for custom post-transfer logic.
    function afterTransfer(address from, address to, uint256 id, uint256 amount) external override onlyToken {
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
