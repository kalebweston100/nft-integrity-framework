// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../hooks/HooksLogicERC721.sol";

/**
 * @title TestHooksERC721
 * @notice Concrete ERC-721 hooks logic for testing. Records every hook
 *         invocation and exposes admin toggles to drive every branch in the
 *         token's pipeline. Deployed as Logic → Wrapper → Token; this contract
 *         never calls the wrapper or token — the wrapper calls it.
 *
 * Transfer denial goes through _onValidateTransfer, the authoritative deny gate —
 * not through a revert in _onBeforeTransfer, which IHooksERC20 rule 2 reserves for
 * settle-only notification.
 */
contract TestHooksERC721 is HooksLogicERC721 {
    // ─── Call Record Structs ─────────────────────────────────────────────────

    struct TransferRecord {
        address from;
        address to;
        uint256 tokenId;
    }

    struct MintRecord {
        address to;
        uint256 tokenId;
    }

    struct BurnRecord {
        uint256 tokenId;
    }

    // ─── Call Logs ───────────────────────────────────────────────────────────

    TransferRecord[] public beforeTransferLog;
    TransferRecord[] public afterTransferLog;
    MintRecord[] public beforeMintLog;
    MintRecord[] public afterMintLog;
    BurnRecord[] public beforeBurnLog;
    BurnRecord[] public afterBurnLog;

    // ─── Behavior Flags ──────────────────────────────────────────────────────

    bool public blockTransfers;
    string public blockTransferReason = "TestHooks: transfer blocked";

    bool public blockMints;
    string public blockMintReason = "TestHooks: mint blocked";

    bool public blockBurns;
    string public blockBurnReason = "TestHooks: burn blocked";

    bool public revertInAfterHooks;

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(
        address _issuerAdmin,
        string memory tokenName,
        string memory tokenSymbol,
        string memory contractURI_,
        string memory baseURI_
    ) HooksLogicERC721(_issuerAdmin, tokenName, tokenSymbol, contractURI_, baseURI_) {}

    // ─── Admin Controls ──────────────────────────────────────────────────────

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

    /// @notice Make every after-hook revert, to prove the token's try/catch keeps
    ///         a broken hooks contract from bricking the token.
    function setRevertInAfterHooks(bool enabled) external onlyIssuerAdmin {
        revertInAfterHooks = enabled;
    }

    // ─── Deny Gates ──────────────────────────────────────────────────────────

    function _onValidateTransfer(address, address, uint256) internal view override returns (bool, string memory) {
        if (blockTransfers) return (false, blockTransferReason);
        return (true, "");
    }

    function _onBeforeMint(address to, uint256 tokenId, bytes calldata)
        internal
        override
        returns (bool, string memory)
    {
        beforeMintLog.push(MintRecord(to, tokenId));
        if (blockMints) return (false, blockMintReason);
        return (true, "");
    }

    function _onBeforeBurn(uint256 tokenId) internal override returns (bool, string memory) {
        beforeBurnLog.push(BurnRecord(tokenId));
        if (blockBurns) return (false, blockBurnReason);
        return (true, "");
    }

    // ─── Notifications ───────────────────────────────────────────────────────

    function _onBeforeTransfer(address from, address to, uint256 tokenId) internal override {
        beforeTransferLog.push(TransferRecord(from, to, tokenId));
    }

    function _onAfterTransfer(address from, address to, uint256 tokenId) internal override {
        require(!revertInAfterHooks, "TestHooks: afterTransfer exploded");
        afterTransferLog.push(TransferRecord(from, to, tokenId));
    }

    function _onAfterMint(address to, uint256 tokenId, bytes calldata) internal override {
        require(!revertInAfterHooks, "TestHooks: afterMint exploded");
        afterMintLog.push(MintRecord(to, tokenId));
    }

    function _onAfterBurn(uint256 tokenId) internal override {
        require(!revertInAfterHooks, "TestHooks: afterBurn exploded");
        afterBurnLog.push(BurnRecord(tokenId));
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

    function lastBeforeMint() external view returns (MintRecord memory) {
        require(beforeMintLog.length > 0, "No mints recorded");
        return beforeMintLog[beforeMintLog.length - 1];
    }

    function lastBeforeBurn() external view returns (BurnRecord memory) {
        require(beforeBurnLog.length > 0, "No burns recorded");
        return beforeBurnLog[beforeBurnLog.length - 1];
    }
}
