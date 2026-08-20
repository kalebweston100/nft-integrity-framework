// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Errors.sol";

/**
 * @title HooksFactory
 * @notice Abstract base for platform contracts that want to charge their own fee for
 *         deploying hooks+token pairs on behalf of users, on top of this framework's
 *         hooks contracts (which deploy their own token directly — see
 *         HooksERC20Base/HooksERC721Base/HooksERC1155Base).
 *
 * Provides two-step ownership and platform fee accumulation/withdrawal. Deployment
 * itself needs no helper here: a concrete platform factory just does
 * `address(new MyHooks(...))`, exactly like deploying any other contract, since the
 * hooks contract's own constructor deploys its token as a side effect. There is no
 * separate token-factory deploy fee to forward anymore — a platform wanting a fee
 * simply requires it directly on its own payable deploy function.
 *
 * USAGE:
 *   contract MyPlatform is HooksFactory {
 *       uint256 public platformDeployFee;
 *
 *       function createThing(...) external payable returns (address hooksAddr) {
 *           require(msg.value >= platformDeployFee, "insufficient fee");
 *           platformFeeBalance += msg.value;
 *           hooksAddr = address(new MyHooks(...));
 *       }
 *   }
 */
abstract contract HooksFactory {
    event PlatformFeesWithdrawn(address indexed to, uint256 amount);
    event OwnershipTransferStarted(address indexed currentOwner, address indexed pendingOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    address public owner;
    address private _pendingOwner;
    uint256 public platformFeeBalance;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // =========================================================================
    //                          PLATFORM FEES
    // =========================================================================

    /// @notice Accepts ETH forwarded by deployed contracts as platform commission.
    receive() external payable virtual {
        platformFeeBalance += msg.value;
    }

    /// @notice Withdraws accumulated platform fees to `to`.
    function withdrawPlatformFees(address to) external onlyOwner {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = platformFeeBalance;
        if (amount == 0) revert NothingToWithdraw();
        platformFeeBalance = 0;
        (bool success,) = payable(to).call{value: amount}("");
        if (!success) revert WithdrawalFailed();
        emit PlatformFeesWithdrawn(to, amount);
    }

    // =========================================================================
    //                            OWNERSHIP
    // =========================================================================

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != _pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, _pendingOwner);
        owner = _pendingOwner;
        _pendingOwner = address(0);
    }

    function pendingOwner() external view returns (address) {
        return _pendingOwner;
    }
}
