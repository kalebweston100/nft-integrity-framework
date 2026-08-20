//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC1155.sol";
import "../interfaces/IHooksERC1155.sol";
import "../interfaces/IHooks.sol";

/**
 * @title HooksERC1155
 * @notice Abstract base for ERC-1155 hooks contracts. Provides the full hook
 *         framework, access control, and deploys its own token. Implements
 *         IHooksERC1155 — see that interface for the normative rules this
 *         contract's calling convention follows.
 *
 * DEPLOYMENT FLOW:
 *   Deploy MyHooks(issuerAdmin, baseTokenURI, contractURI) inheriting HooksERC1155
 *   — its constructor deploys the IntegrityERC1155 token directly
 *   (`new IntegrityERC1155(...)`) and wires itself as governor. There is no factory
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
 *       _onBeforeSetURI / _onBeforeSetTokenURI
 *
 *     Notifications (fail-open, try/catch-wrapped by the token):
 *       _onBeforeTransfer, _onAfterTransfer, _onAfterMint, _onAfterBurn,
 *       _onAfterSetURI, _onAfterSetTokenURI
 *
 *   Use _onValidateTransfer — not a revert in _onBeforeTransfer — to deny a
 *   transfer. beforeTransfer is a settle-only notification per IHooksERC20 rule 2.
 *
 * MINTING AUTHORITY:
 *   This base grants none. To let the hooks contract initiate mints, inherit
 *   HooksERC1155Minter (below), which declares IHookMinter via ERC-165 so the
 *   capability is discoverable from the hooks address alone.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer → validateTransfer → balance → afterTransfer
 *   MINT:     beforeMint → balance → afterMint
 *   BURN:     balance check → beforeBurn → balance → afterBurn
 */
abstract contract HooksERC1155 is IHooksERC1155, ERC165 {
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    /// @notice The IntegrityERC1155 this hooks contract deployed and governs.
    IntegrityERC1155 public immutable token;
    address public issuerAdmin;

    modifier onlyToken() {
        require(msg.sender == address(token), "Hooks: Not token contract");
        _;
    }

    modifier onlyIssuerAdmin() {
        require(msg.sender == issuerAdmin, "Hooks: Not issuer admin");
        _;
    }

    constructor(address _issuerAdmin, string memory baseTokenURI, string memory contractURI_) {
        require(_issuerAdmin != address(0), "Hooks: Zero admin address");
        issuerAdmin = _issuerAdmin;
        token = new IntegrityERC1155(_issuerAdmin, baseTokenURI, contractURI_);
    }

    function transferAdmin(address newAdmin) external onlyIssuerAdmin {
        require(newAdmin != address(0), "Hooks: Zero address");
        address oldAdmin = issuerAdmin;
        issuerAdmin = newAdmin;
        emit AdminTransferred(oldAdmin, newAdmin);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IHooksERC1155).interfaceId || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 id, uint256 amount) external override onlyToken {
        _onBeforeTransfer(from, to, id, amount);
    }

    /// @dev Settle-only notification. Do not use a revert here to signal policy —
    ///      override _onValidateTransfer instead.
    function _onBeforeTransfer(address from, address to, uint256 id, uint256 amount) internal virtual {}

    function validateTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        override
        onlyToken
        returns (bool valid, string memory reason)
    {
        return _onValidateTransfer(from, to, id, amount);
    }

    /// @dev The authoritative deny gate for transfers. Return (false, reason) to block.
    function _onValidateTransfer(address from, address to, uint256 id, uint256 amount)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 id, uint256 amount) external override onlyToken {
        _onAfterTransfer(from, to, id, amount);
    }

    function _onAfterTransfer(address from, address to, uint256 id, uint256 amount) internal virtual {}

    // =========================================================================
    //                            MINT HOOKS
    // =========================================================================

    function beforeMint(address to, uint256 id, uint256 amount, bytes calldata data)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeMint(to, id, amount, data);
    }

    function _onBeforeMint(address to, uint256 id, uint256 amount, bytes calldata data)
        internal
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterMint(address to, uint256 id, uint256 amount, bytes calldata data) external override onlyToken {
        _onAfterMint(to, id, amount, data);
    }

    function _onAfterMint(address to, uint256 id, uint256 amount, bytes calldata data) internal virtual {}

    // =========================================================================
    //                            BURN HOOKS
    // =========================================================================

    function beforeBurn(address from, uint256 id, uint256 amount)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeBurn(from, id, amount);
    }

    function _onBeforeBurn(address from, uint256 id, uint256 amount) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(address from, uint256 id, uint256 amount) external override onlyToken {
        _onAfterBurn(from, id, amount);
    }

    function _onAfterBurn(address from, uint256 id, uint256 amount) internal virtual {}

    // =========================================================================
    //                          METADATA HOOKS
    // =========================================================================

    function beforeSetURI(string calldata newUri) external view onlyToken returns (bool allowed, string memory reason) {
        return _onBeforeSetURI(newUri);
    }

    function _onBeforeSetURI(string calldata newUri) internal view virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterSetURI(string calldata newUri) external onlyToken {
        _onAfterSetURI(newUri);
    }

    function _onAfterSetURI(string calldata newUri) internal virtual {}

    function beforeSetTokenURI(uint256 id, string calldata newURI)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeSetTokenURI(id, newURI);
    }

    function _onBeforeSetTokenURI(uint256 id, string calldata newURI)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterSetTokenURI(uint256 id, string calldata newURI) external onlyToken {
        _onAfterSetTokenURI(id, newURI);
    }

    function _onAfterSetTokenURI(uint256 id, string calldata newURI) internal virtual {}
}

/**
 * @title HooksERC1155Minter
 * @notice HooksERC1155 plus hook-initiated minting authority, declared via ERC-165.
 *
 * Inherit this instead of HooksERC1155 when your hooks contract needs to mint
 * (e.g. mint-on-deposit). Doing so makes `supportsInterface(IHookMinter)` return
 * true, so an integrator can tell from the hooks address alone that this contract
 * is part of the token's supply policy.
 *
 * This is a disclosure mechanism, not a security boundary — see IHookMinter.
 */
abstract contract HooksERC1155Minter is HooksERC1155, IHookMinter {
    constructor(address _issuerAdmin, string memory baseTokenURI, string memory contractURI_)
        HooksERC1155(_issuerAdmin, baseTokenURI, contractURI_)
    {}

    /// @inheritdoc IHookMinter
    function mintingAuthorityOver() external view override returns (address) {
        return address(token);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IHookMinter).interfaceId || super.supportsInterface(interfaceId);
    }

    function _mintFromHooks(address to, uint256 id, uint256 amount) internal {
        token.hookMint(to, id, amount);
    }

    function _setTokenURIFromHooks(uint256 id, string memory newURI) internal {
        token.hookSetTokenURI(id, newURI);
    }
}
