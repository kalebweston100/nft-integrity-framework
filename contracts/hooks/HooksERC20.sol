//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC20.sol";
import "../interfaces/IHooksERC20.sol";
import "../interfaces/IHooks.sol";
import "./HooksAdmin.sol";

/**
 * @title HooksERC20
 * @notice Abstract base for ERC-20 hooks contracts. Provides the full hook
 *         framework, access control, and deploys its own token. Implements
 *         IHooksERC20 — see that interface for the normative rules this
 *         contract's calling convention follows.
 *
 * DEPLOYMENT FLOW:
 *   Deploy MyHooks(issuerAdmin, name, symbol, contractURI) inheriting HooksERC20
 *   — its constructor deploys the IntegrityERC20 token directly
 *   (`new IntegrityERC20(...)`) and wires itself as governor. There is no factory
 *   and no separate initialization step: `token` is set once, synchronously, as
 *   the return value of `new`.
 *
 * EXTENSION:
 *   Every hook in the calling convention has an internal `virtual` counterpart.
 *   Override the `_on*` function, never the external one — the external functions
 *   carry `onlyToken` and are deliberately non-virtual so an override cannot
 *   remove that check.
 *
 *     Deny gates (fail-closed):
 *       _onValidateTransfer  → return (false, reason) to block a transfer
 *       _onBeforeMint        → return (false, reason) to block a mint
 *       _onBeforeBurn        → return (false, reason) to block a burn
 *
 *     Notifications (fail-open, try/catch-wrapped by the token):
 *       _onBeforeTransfer, _onAfterTransfer, _onAfterMint, _onAfterBurn
 *
 *   Use _onValidateTransfer — not a revert in _onBeforeTransfer — to deny a
 *   transfer. beforeTransfer is a settle-only notification per IHooksERC20 rule 2.
 *
 * MINTING AUTHORITY:
 *   _mintFromHooks(to, amount) calls IntegrityERC20.hookMint, which is real
 *   minting authority over the token — a deliberate, narrow capability for use
 *   cases like mint-on-deposit. Nothing requires a subclass to call it; document
 *   prominently if yours does. See IHooks.sol for why this isn't split into a
 *   separately declared ERC-165 capability.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer → validateTransfer → balance → afterTransfer
 *   MINT:     beforeMint → balance → afterMint
 *   BURN:     balance check → beforeBurn → balance → afterBurn
 */
abstract contract HooksERC20 is IHooksERC20, ERC165, HooksAdmin {
    /// @notice The IntegrityERC20 this hooks contract deployed and governs.
    IntegrityERC20 public immutable token;

    modifier onlyToken() {
        require(msg.sender == address(token), "Hooks: Not token contract");
        _;
    }

    constructor(address _issuerAdmin, string memory tokenName, string memory tokenSymbol, string memory contractURI_)
        HooksAdmin(_issuerAdmin)
    {
        token = new IntegrityERC20(_issuerAdmin, tokenName, tokenSymbol, contractURI_);
    }

    function _mintFromHooks(address to, uint256 amount) internal {
        token.hookMint(to, amount);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IHooksERC20).interfaceId || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 amount) external override onlyToken {
        _onBeforeTransfer(from, to, amount);
    }

    /// @dev Settle-only notification. Do not use a revert here to signal policy —
    ///      override _onValidateTransfer instead.
    function _onBeforeTransfer(address from, address to, uint256 amount) internal virtual {}

    function validateTransfer(address from, address to, uint256 amount)
        external
        view
        override
        onlyToken
        returns (bool valid, string memory reason)
    {
        return _onValidateTransfer(from, to, amount);
    }

    /// @dev The authoritative deny gate for transfers. Return (false, reason) to block.
    function _onValidateTransfer(address from, address to, uint256 amount)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 amount) external override onlyToken {
        _onAfterTransfer(from, to, amount);
    }

    function _onAfterTransfer(address from, address to, uint256 amount) internal virtual {}

    // =========================================================================
    //                            MINT HOOKS
    // =========================================================================

    function beforeMint(address to, uint256 amount, bytes calldata data)
        external
        override
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

    function afterMint(address to, uint256 amount, bytes calldata data) external override onlyToken {
        _onAfterMint(to, amount, data);
    }

    function _onAfterMint(address to, uint256 amount, bytes calldata data) internal virtual {}

    // =========================================================================
    //                            BURN HOOKS
    // =========================================================================

    function beforeBurn(address from, uint256 amount)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeBurn(from, amount);
    }

    function _onBeforeBurn(address from, uint256 amount) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(address from, uint256 amount) external override onlyToken {
        _onAfterBurn(from, amount);
    }

    function _onAfterBurn(address from, uint256 amount) internal virtual {}
}
