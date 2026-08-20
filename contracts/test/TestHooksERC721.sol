// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../hooks/HooksERC721.sol";

/**
 * @title TestHooksERC721
 * @notice Concrete ERC-721 hooks for testing. Records every accessible hook invocation
 *         and exposes admin toggles to drive every branch in the token's pipeline.
 *
 * HOOK COVERAGE:
 *   beforeTransfer721  – recorded; optional revert to test transfer blocking
 *   beforeMint721      – recorded; optional (false, reason) to test mint blocking
 *   beforeBurn721      – recorded; optional (false, reason) to test burn blocking
 *   hookMint path      – issuerMint() exercises IntegrityERC721.hookMint()
 *
 * LIMITATIONS:
 *   validateTransfer721, afterTransfer721, afterMint721, afterBurn721,
 *   beforeSetBaseURI, afterSetBaseURI, onTransferBlocked721 are not virtual in
 *   HooksERC721 and cannot be overridden; test those paths via token-side effects.
 */
contract TestHooksERC721 is HooksERC721 {
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
    MintRecord[] public beforeMintLog;
    BurnRecord[] public beforeBurnLog;

    // ─── Behavior Flags ──────────────────────────────────────────────────────

    bool public revertOnTransfer;
    string public transferRevertReason = "TestHooks: transfer blocked";

    bool public blockMints;
    string public blockMintReason = "TestHooks: mint blocked";

    bool public blockBurns;
    string public blockBurnReason = "TestHooks: burn blocked";

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(
        address _issuerAdmin,
        string memory tokenName,
        string memory tokenSymbol,
        string memory contractURI_,
        string memory baseURI_
    ) HooksERC721(_issuerAdmin, tokenName, tokenSymbol, contractURI_, baseURI_) {}

    // ─── Admin Controls ──────────────────────────────────────────────────────

    /// @notice Toggle whether beforeTransfer721 reverts (blocks all transfers via hook).
    function setRevertOnTransfer(bool blocked, string calldata reason) external onlyIssuerAdmin {
        revertOnTransfer = blocked;
        transferRevertReason = reason;
    }

    /// @notice Toggle whether beforeMint721 returns (false, reason) (blocks all mints via hook).
    function setBlockMints(bool blocked, string calldata reason) external onlyIssuerAdmin {
        blockMints = blocked;
        blockMintReason = reason;
    }

    /// @notice Toggle whether beforeBurn721 returns (false, reason) (blocks all burns via hook).
    function setBlockBurns(bool blocked, string calldata reason) external onlyIssuerAdmin {
        blockBurns = blocked;
        blockBurnReason = reason;
    }

    /// @notice Exercises IntegrityERC721.hookMint() — direct hook-gated mint by tokenId.
    function issuerMint(address to, uint256 tokenId, uint256 flags, bytes32 metadataHash) external onlyIssuerAdmin {
        _mintFromHooks(to, tokenId, flags, metadataHash);
    }

    // ─── Hook Overrides ──────────────────────────────────────────────────────

    function _onBeforeTransfer721(address from, address to, uint256 tokenId) internal override {
        beforeTransferLog.push(TransferRecord(from, to, tokenId));
        if (revertOnTransfer) revert(transferRevertReason);
    }

    function _onBeforeMint721(
        address to,
        uint256 tokenId,
        bytes calldata /*data*/
    )
        internal
        override
        returns (bool, string memory)
    {
        beforeMintLog.push(MintRecord(to, tokenId));
        if (blockMints) return (false, blockMintReason);
        return (true, "");
    }

    function _onBeforeBurn721(uint256 tokenId) internal override returns (bool, string memory) {
        beforeBurnLog.push(BurnRecord(tokenId));
        if (blockBurns) return (false, blockBurnReason);
        return (true, "");
    }

    // ─── View Helpers ─────────────────────────────────────────────────────────

    function beforeTransferCount() external view returns (uint256) {
        return beforeTransferLog.length;
    }

    function beforeMintCount() external view returns (uint256) {
        return beforeMintLog.length;
    }

    function beforeBurnCount() external view returns (uint256) {
        return beforeBurnLog.length;
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
