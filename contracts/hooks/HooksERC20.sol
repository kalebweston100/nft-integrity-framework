//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC20.sol";
import "../interfaces/IHooksERC20.sol";
import "../interfaces/IHooks.sol";

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
 *   This base grants none. To let the hooks contract initiate mints, inherit
 *   HooksERC20Minter (below), which declares IHookMinter via ERC-165 so the
 *   capability is discoverable from the hooks address alone.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer → validateTransfer → balance → afterTransfer
 *   MINT:     beforeMint → balance → afterMint
 *   BURN:     balance check → beforeBurn → balance → afterBurn
 */
abstract contract HooksERC20 is IHooksERC20, ERC165 {
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

/**
 * @title HooksERC20Minter
 * @notice HooksERC20 plus hook-initiated minting authority, declared via ERC-165.
 *
 * Inherit this instead of HooksERC20 when your hooks contract needs to mint
 * (e.g. mint-on-deposit). Doing so makes `supportsInterface(IHookMinter)` return
 * true, so an integrator can tell from the hooks address alone that this contract
 * is part of the token's supply policy.
 *
 * This is a disclosure mechanism, not a security boundary — see IHookMinter.
 */
abstract contract HooksERC20Minter is HooksERC20, IHookMinter {
    constructor(address _issuerAdmin, string memory tokenName, string memory tokenSymbol, string memory contractURI_)
        HooksERC20(_issuerAdmin, tokenName, tokenSymbol, contractURI_)
    {}

    /// @inheritdoc IHookMinter
    function mintingAuthorityOver() external view override returns (address) {
        return address(token);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IHookMinter).interfaceId || super.supportsInterface(interfaceId);
    }

    function _mintFromHooks(address to, uint256 amount) internal {
        token.hookMint(to, amount);
    }
}
