// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title RoyaltyBase
 * @notice Shared state and payout infrastructure for accumulator-based pull royalties.
 *         Inherited by HooksERC20, HooksERC721, and HooksERC1155.
 *
 *         Each hook base class adds its own accumulator, distributeRoyalties(),
 *         claimRoyalties(), and pendingRoyaltiesFor() on top of this foundation.
 *
 * PULL MODEL:
 *   Revenue is deposited via distributeRoyalties() on the concrete hook class,
 *   which increases a global accumulator proportional to current token supply.
 *   Pipeline hooks (beforeTransfer, beforeMint, beforeBurn) settle each holder's
 *   earned-but-not-yet-recorded royalties into pendingRoyalties before their
 *   balance changes — ensuring ownership at distribution time determines earnings.
 *   Holders call claimRoyalties() at their convenience to withdraw accumulated ETH.
 *
 * REENTRANCY:
 *   ReentrancyGuard is provided here so all claimRoyalties() implementations
 *   in subclasses can use the nonReentrant modifier without importing it separately.
 */
abstract contract RoyaltyBase is ReentrancyGuard {

    uint256 internal constant ROYALTY_PRECISION = 1e18;

    /// @notice Settled but unclaimed royalties per holder (in wei).
    mapping(address => uint256) public pendingRoyalties;

    /// @notice Cumulative ETH added to the pool across all distributeRoyalties() calls.
    uint256 public totalRoyaltiesDistributed;

    /// @notice Cumulative ETH paid out via claimRoyalties().
    uint256 public totalRoyaltiesClaimed;

    event RoyaltiesClaimed(address indexed holder, uint256 amount);

    /// @dev Credits settled royalties to a holder's claimable balance.
    function _addPending(address holder, uint256 amount) internal {
        if (amount > 0) pendingRoyalties[holder] += amount;
    }

    /// @dev Transfers ETH to a holder. Must only be called from a nonReentrant claim function
    ///      after all state updates are complete (CEI pattern).
    function _sendRoyalties(address holder, uint256 amount) internal {
        totalRoyaltiesClaimed += amount;
        (bool success,) = payable(holder).call{value: amount}("");
        require(success, "Royalty: transfer failed");
    }
}
