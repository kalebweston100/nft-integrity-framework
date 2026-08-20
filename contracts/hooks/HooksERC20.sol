//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../token/IntegrityERC20.sol";
import "./RoyaltyBase.sol";

/**
 * @title HooksERC20Base
 * @notice Abstract base for ERC-20 hooks contracts without built-in royalty distribution.
 *         Provides the full hook framework, access control, and deploys its own token.
 *         Inherit HooksERC20 instead if you also need the royalty accumulator.
 *
 * DEPLOYMENT FLOW:
 *   1. Deploy MyHooks(issuerAdmin, name, symbol, contractURI) inheriting HooksERC20Base
 *      or HooksERC20 — its constructor deploys the IntegrityERC20 token directly
 *      (`new IntegrityERC20(...)`) and wires itself as governor. There is no factory
 *      and no separate initialization step: `token` is set once, synchronously, as
 *      the return value of `new`.
 *
 * EXTENSION:
 *   Override _onBeforeTransfer / _onBeforeMint / _onBeforeBurn for custom logic.
 *   After-hooks are wrapped in try/catch by the token — bugs won't brick the token.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer → validateTransfer → balance → afterTransfer
 *   MINT:     beforeMint → balance → afterMint
 *   BURN:     balance check → beforeBurn → balance → afterBurn
 */
abstract contract HooksERC20Base {
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    /// @notice The IntegrityERC20 this hooks contract deployed and governs.
    IntegrityERC20 public immutable token;
    address public issuerAdmin;

    modifier onlyToken() {
        require(msg.sender == address(token), "Hooks: Not token contract");
        _;
    }

    modifier onlyIssuerAdmin() {
        require(msg.sender == issuerAdmin, "Hooks: Not issuer admin");
        _;
    }

    constructor(address _issuerAdmin, string memory tokenName, string memory tokenSymbol, string memory contractURI_) {
        require(_issuerAdmin != address(0), "Hooks: Zero admin address");
        issuerAdmin = _issuerAdmin;
        token = new IntegrityERC20(_issuerAdmin, tokenName, tokenSymbol, contractURI_);
    }

    function transferAdmin(address newAdmin) external onlyIssuerAdmin {
        require(newAdmin != address(0), "Hooks: Zero address");
        address oldAdmin = issuerAdmin;
        issuerAdmin = newAdmin;
        emit AdminTransferred(oldAdmin, newAdmin);
    }

    function _tokenBalanceOf(address account) internal view returns (uint256) {
        return token.balanceOf(account);
    }

    function _tokenTotalSupply() internal view returns (uint256) {
        return token.totalSupply();
    }

    // Called before beforeTransfer/beforeMint/beforeBurn — no-op here, overridden by HooksERC20
    function _beforeTransferSettle(address from, address to) internal virtual {}
    function _beforeMintSettle(address to) internal virtual {}
    function _beforeBurnSettle(address from) internal virtual {}

    function _mintFromHooks(address to, uint256 amount) internal {
        token.hookMint(to, amount);
    }

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    /// @notice Override _onBeforeTransfer to add custom pre-transfer logic. Revert to block.
    function beforeTransfer(address from, address to, uint256 amount) external onlyToken {
        _beforeTransferSettle(from, to);
        _onBeforeTransfer(from, to, amount);
    }

    function _onBeforeTransfer(address from, address to, uint256 amount) internal virtual {}

    function validateTransfer(address from, address to, uint256 amount)
        external
        view
        onlyToken
        returns (bool valid, string memory reason)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 amount) external onlyToken {}

    function onTransferBlocked(address from, address to, uint256 amount, string calldata reason) external onlyToken {}

    // =========================================================================
    //                            MINT HOOKS
    // =========================================================================

    /// @notice Override _onBeforeMint to add custom pre-mint logic. Return (false, reason) to block.
    function beforeMint(address to, uint256 amount, bytes calldata data)
        external
        onlyToken
        returns (bool allowed, string memory reason)
    {
        _beforeMintSettle(to);
        return _onBeforeMint(to, amount, data);
    }

    function _onBeforeMint(address to, uint256 amount, bytes calldata data)
        internal
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterMint(address to, uint256 amount, bytes calldata data) external onlyToken {}

    // =========================================================================
    //                            BURN HOOKS
    // =========================================================================

    /// @notice Override _onBeforeBurn to add custom pre-burn logic. Return (false, reason) to block.
    function beforeBurn(address from, uint256 amount) external onlyToken returns (bool allowed, string memory reason) {
        _beforeBurnSettle(from);
        return _onBeforeBurn(from, amount);
    }

    function _onBeforeBurn(address from, uint256 amount) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(address from, uint256 amount) external onlyToken {}
}

/**
 * @title HooksERC20
 * @notice HooksERC20Base with built-in pro-rata ETH royalty distribution.
 *         Revenue deposited via distributeRoyalties() is settled before each balance
 *         change, ensuring ownership at distribution time determines earnings.
 *         Inherit this if you want royalties; use HooksERC20Base if you do not.
 */
abstract contract HooksERC20 is HooksERC20Base, RoyaltyBase {
    event RoyaltiesDistributed(uint256 amount);

    uint256 public accumulatedRoyaltiesPerToken;
    mapping(address => uint256) public royaltyDebt;

    function _beforeTransferSettle(address from, address to) internal override {
        if (from != address(0)) _settleHolder(from);
        if (to != address(0)) _settleHolder(to);
    }

    function _beforeMintSettle(address to) internal override {
        _settleHolder(to);
    }

    function _beforeBurnSettle(address from) internal override {
        _settleHolder(from);
    }

    function _settleHolder(address holder) internal {
        uint256 earned =
            (_tokenBalanceOf(holder) * (accumulatedRoyaltiesPerToken - royaltyDebt[holder])) / ROYALTY_PRECISION;
        _addPending(holder, earned);
        royaltyDebt[holder] = accumulatedRoyaltiesPerToken;
    }

    function _distributeToAccumulator(uint256 amount) internal {
        uint256 supply = _tokenTotalSupply();
        require(supply > 0, "Royalty: no supply");
        accumulatedRoyaltiesPerToken += (amount * ROYALTY_PRECISION) / supply;
        totalRoyaltiesDistributed += amount;
        emit RoyaltiesDistributed(amount);
    }

    /// @notice Deposit ETH to distribute royalties pro-rata to all current token holders.
    function distributeRoyalties() external payable virtual {
        require(msg.value > 0, "Royalty: zero amount");
        _distributeToAccumulator(msg.value);
    }

    function claimRoyalties() external nonReentrant {
        _settleHolder(msg.sender);
        uint256 amount = pendingRoyalties[msg.sender];
        require(amount > 0, "Royalty: nothing to claim");
        pendingRoyalties[msg.sender] = 0;
        emit RoyaltiesClaimed(msg.sender, amount);
        _sendRoyalties(msg.sender, amount);
    }

    function pendingRoyaltiesFor(address holder) external view returns (uint256) {
        uint256 unsettled =
            (_tokenBalanceOf(holder) * (accumulatedRoyaltiesPerToken - royaltyDebt[holder])) / ROYALTY_PRECISION;
        return pendingRoyalties[holder] + unsettled;
    }
}
