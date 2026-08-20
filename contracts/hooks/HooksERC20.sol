//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../token/IntegrityERC20.sol";

/**
 * @title HooksERC20
 * @notice Abstract base for ERC-20 hooks contracts. Provides the full hook
 *         framework, access control, and deploys its own token.
 *
 * DEPLOYMENT FLOW:
 *   1. Deploy MyHooks(issuerAdmin, name, symbol, contractURI) inheriting HooksERC20
 *      — its constructor deploys the IntegrityERC20 token directly
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
abstract contract HooksERC20 {
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

    function _mintFromHooks(address to, uint256 amount) internal {
        token.hookMint(to, amount);
    }

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    /// @notice Override _onBeforeTransfer to add custom pre-transfer logic. Revert to block.
    function beforeTransfer(address from, address to, uint256 amount) external onlyToken {
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
        return _onBeforeBurn(from, amount);
    }

    function _onBeforeBurn(address from, uint256 amount) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(address from, uint256 amount) external onlyToken {}
}
