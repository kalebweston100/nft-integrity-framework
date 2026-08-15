// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/ITokenFactory.sol";
import "../interfaces/Errors.sol";

/**
 * @title HooksFactory
 * @notice Abstract base for factory contracts that deploy tokens using the
 *         TokenLFG compliance hooks system.
 *
 * Provides two-step ownership, platform fee accumulation/withdrawal, a typed
 * reference to the underlying token factory, and protected helpers for each
 * token standard. The helpers automatically forward the token factory's deploy
 * fee so concrete factories never need to handle the ETH forwarding themselves.
 *
 * USAGE:
 *   contract MyFactory is HooksFactory {
 *       constructor(address tokenFactoryAddr) HooksFactory(tokenFactoryAddr) { ... }
 *
 *       // Make the function payable; the base forwards the fee automatically.
 *       function createThing(...) external payable {
 *           require(msg.value >= deployFee(), "insufficient fee");
 *           address hooksAddr = address(new MyHooks(...));
 *           address token = _deployERC1155Pair(hooksAddr, baseURI, contractURI);
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

    ITokenFactory public immutable tokenFactory;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _tokenFactory) {
        if (_tokenFactory == address(0)) revert ZeroAddress();
        owner = msg.sender;
        tokenFactory = ITokenFactory(_tokenFactory);
    }

    // =========================================================================
    //                       TOKEN DEPLOYMENT HELPERS
    // =========================================================================

    /// @notice Returns the current per-deploy fee charged by the token factory.
    /// @dev Concrete factories should expose this (or call it in a payable function)
    ///      so callers know how much ETH to send.
    function deployFee() public view returns (uint256) {
        return tokenFactory.deployFee();
    }

    /// @notice Deploys an IntegrityERC20 linked to an already-deployed hooks contract.
    ///         Forwards the token factory's deploy fee automatically.
    function _deployERC20Pair(
        address issuerAdmin,
        address hooksAddr,
        string memory tokenName,
        string memory tokenSymbol,
        string memory contractURI
    ) internal returns (address token) {
        if (hooksAddr == address(0)) revert ZeroAddress();
        uint256 fee = tokenFactory.deployFee();
        return IFactoryERC20(address(tokenFactory)).deployTokenERC20{value: fee}(
            issuerAdmin, hooksAddr, tokenName, tokenSymbol, contractURI
        );
    }

    /// @notice Deploys an IntegrityERC721 linked to an already-deployed hooks contract.
    ///         Forwards the token factory's deploy fee automatically.
    function _deployERC721Pair(
        address issuerAdmin,
        address hooksAddr,
        string memory tokenName,
        string memory tokenSymbol,
        string memory contractURI,
        string memory baseURI
    ) internal returns (address token) {
        if (hooksAddr == address(0)) revert ZeroAddress();
        uint256 fee = tokenFactory.deployFee();
        return IFactoryERC721(address(tokenFactory)).deployTokenERC721{value: fee}(
            issuerAdmin, hooksAddr, tokenName, tokenSymbol, contractURI, baseURI
        );
    }

    /// @notice Deploys an IntegrityERC1155 linked to an already-deployed hooks contract.
    ///         Forwards the token factory's deploy fee automatically.
    function _deployERC1155Pair(
        address issuerAdmin,
        address hooksAddr,
        string memory baseTokenURI,
        string memory contractURI
    ) internal returns (address token) {
        if (hooksAddr == address(0)) revert ZeroAddress();
        uint256 fee = tokenFactory.deployFee();
        return IFactoryERC1155(address(tokenFactory)).deployTokenERC1155{value: fee}(
            issuerAdmin, hooksAddr, baseTokenURI, contractURI
        );
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
        (bool success, ) = payable(to).call{value: amount}("");
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
