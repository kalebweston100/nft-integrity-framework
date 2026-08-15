// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../hooks/HooksERC20.sol";

/**
 * @title TestHooksERC20
 * @notice Concrete ERC-20 hooks for testing. Records every accessible hook invocation
 *         and exposes admin toggles to drive every branch in the token's pipeline.
 *
 * HOOK COVERAGE:
 *   beforeTransfer  – recorded; optional revert to test transfer blocking
 *   beforeMint      – recorded; optional (false, reason) to test mint blocking
 *   beforeBurn      – recorded; optional (false, reason) to test burn blocking
 *   royalties       – full HooksERC20 accumulator (distribute → settle → claim)
 *   hookMint path   – issuerMint() exercises IntegrityERC20.hookMint()
 *
 * LIMITATIONS:
 *   validateTransfer, afterTransfer, afterMint, afterBurn, onTransferBlocked are
 *   not virtual in HooksERC20Base and cannot be overridden; those paths are tested
 *   by observing token-side effects rather than hook-side recording.
 */
contract TestHooksERC20 is HooksERC20 {

    // ─── Call Record Structs ─────────────────────────────────────────────────

    struct TransferRecord { address from; address to; uint256 amount; }
    struct MintRecord     { address to; uint256 amount; }
    struct BurnRecord     { address from; uint256 amount; }

    // ─── Call Logs ───────────────────────────────────────────────────────────

    TransferRecord[] public beforeTransferLog;
    MintRecord[]     public beforeMintLog;
    BurnRecord[]     public beforeBurnLog;

    // ─── Behavior Flags ──────────────────────────────────────────────────────

    bool   public revertOnTransfer;
    string public transferRevertReason = "TestHooks: transfer blocked";

    bool   public blockMints;
    string public blockMintReason = "TestHooks: mint blocked";

    bool   public blockBurns;
    string public blockBurnReason = "TestHooks: burn blocked";

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(address _factory, address _issuerAdmin)
        HooksERC20Base(_factory, _issuerAdmin)
    {}

    // ─── Admin Controls ──────────────────────────────────────────────────────

    /// @notice Toggle whether beforeTransfer reverts (blocks all transfers via hook).
    function setRevertOnTransfer(bool blocked, string calldata reason) external onlyIssuerAdmin {
        revertOnTransfer = blocked;
        transferRevertReason = reason;
    }

    /// @notice Toggle whether beforeMint returns (false, reason) (blocks all mints via hook).
    function setBlockMints(bool blocked, string calldata reason) external onlyIssuerAdmin {
        blockMints = blocked;
        blockMintReason = reason;
    }

    /// @notice Toggle whether beforeBurn returns (false, reason) (blocks all burns via hook).
    function setBlockBurns(bool blocked, string calldata reason) external onlyIssuerAdmin {
        blockBurns = blocked;
        blockBurnReason = reason;
    }

    /// @notice Exercises IntegrityERC20.hookMint() — only callable from hooks.
    function issuerMint(address to, uint256 amount) external onlyIssuerAdmin {
        _mintFromHooks(to, amount);
    }

    // ─── Hook Overrides ──────────────────────────────────────────────────────

    function _onBeforeTransfer(address from, address to, uint256 amount) internal override {
        beforeTransferLog.push(TransferRecord(from, to, amount));
        if (revertOnTransfer) revert(transferRevertReason);
    }

    function _onBeforeMint(
        address to,
        uint256 amount,
        bytes calldata /*data*/
    ) internal override returns (bool, string memory) {
        beforeMintLog.push(MintRecord(to, amount));
        if (blockMints) return (false, blockMintReason);
        return (true, "");
    }

    function _onBeforeBurn(
        address from,
        uint256 amount
    ) internal override returns (bool, string memory) {
        beforeBurnLog.push(BurnRecord(from, amount));
        if (blockBurns) return (false, blockBurnReason);
        return (true, "");
    }

    // ─── View Helpers ─────────────────────────────────────────────────────────

    function beforeTransferCount() external view returns (uint256) { return beforeTransferLog.length; }
    function beforeMintCount()     external view returns (uint256) { return beforeMintLog.length; }
    function beforeBurnCount()     external view returns (uint256) { return beforeBurnLog.length; }

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
