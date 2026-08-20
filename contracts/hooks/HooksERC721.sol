//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC721.sol";
import "../interfaces/IHooksERC721.sol";
import "../interfaces/IHooks.sol";

/**
 * @title HooksERC721
 * @notice Abstract base for ERC-721 hooks contracts. Provides the full hook
 *         framework, access control, and deploys its own token. Implements
 *         IHooksERC721 — see that interface for the normative rules this
 *         contract's calling convention follows.
 *
 * DEPLOYMENT FLOW:
 *   Deploy MyHooks(issuerAdmin, name, symbol, contractURI, baseURI) inheriting
 *   HooksERC721 — its constructor deploys the IntegrityERC721 token directly
 *   (`new IntegrityERC721(...)`) and wires itself as governor. There is no
 *   factory and no separate initialization step: `token` is set once,
 *   synchronously, as the return value of `new`.
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
 *       _onBeforeSetBaseURI / _onBeforeSetTokenURI
 *
 *     Notifications (fail-open, try/catch-wrapped by the token):
 *       _onBeforeTransfer, _onAfterTransfer, _onAfterMint, _onAfterBurn,
 *       _onAfterSetBaseURI, _onAfterSetTokenURI
 *
 *   Use _onValidateTransfer — not a revert in _onBeforeTransfer — to deny a
 *   transfer. beforeTransfer is a settle-only notification per IHooksERC20 rule 2.
 *
 * MINTING AUTHORITY:
 *   This base grants none. To let the hooks contract initiate mints, inherit
 *   HooksERC721Minter (below) instead, which declares IHookMinter via ERC-165 so
 *   the capability is discoverable from the hooks address alone.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer → validateTransfer → ownership → afterTransfer
 *   MINT:     beforeMint → ownership → afterMint
 *   BURN:     ownership check → beforeBurn → ownership → afterBurn
 */
abstract contract HooksERC721 is IHooksERC721, ERC165 {
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    /// @notice The IntegrityERC721 this hooks contract deployed and governs. Immutable
    ///         and set once, in the constructor, as the direct result of `new` — cheap
    ///         to read here since (unlike the token's own hooks-address storage) hooks
    ///         contracts are expected to carry per-developer state and were never going
    ///         to have one universal codehash across the ecosystem anyway.
    IntegrityERC721 public immutable token;
    address public issuerAdmin;

    modifier onlyToken() {
        require(msg.sender == address(token), "Hooks: Not token contract");
        _;
    }

    modifier onlyIssuerAdmin() {
        require(msg.sender == issuerAdmin, "Hooks: Not issuer admin");
        _;
    }

    constructor(
        address _issuerAdmin,
        string memory tokenName,
        string memory tokenSymbol,
        string memory contractURI_,
        string memory baseURI_
    ) {
        require(_issuerAdmin != address(0), "Hooks: Zero admin address");
        issuerAdmin = _issuerAdmin;
        token = new IntegrityERC721(_issuerAdmin, tokenName, tokenSymbol, contractURI_, baseURI_);
    }

    function transferAdmin(address newAdmin) external onlyIssuerAdmin {
        require(newAdmin != address(0), "Hooks: Zero address");
        address oldAdmin = issuerAdmin;
        issuerAdmin = newAdmin;
        emit AdminTransferred(oldAdmin, newAdmin);
    }

    function _tokenOwnerOf(uint256 tokenId) internal view returns (address) {
        return token.ownerOf(tokenId);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IHooksERC721).interfaceId || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 tokenId) external override onlyToken {
        _onBeforeTransfer(from, to, tokenId);
    }

    /// @dev Settle-only notification. Do not use a revert here to signal policy —
    ///      override _onValidateTransfer instead.
    function _onBeforeTransfer(address from, address to, uint256 tokenId) internal virtual {}

    function validateTransfer(address from, address to, uint256 tokenId)
        external
        view
        override
        onlyToken
        returns (bool valid, string memory reason)
    {
        return _onValidateTransfer(from, to, tokenId);
    }

    /// @dev The authoritative deny gate for transfers. Return (false, reason) to block.
    function _onValidateTransfer(address from, address to, uint256 tokenId)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 tokenId) external override onlyToken {
        _onAfterTransfer(from, to, tokenId);
    }

    function _onAfterTransfer(address from, address to, uint256 tokenId) internal virtual {}

    // =========================================================================
    //                            MINT HOOKS
    // =========================================================================

    function beforeMint(address to, uint256 tokenId, bytes calldata data)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeMint(to, tokenId, data);
    }

    function _onBeforeMint(address to, uint256 tokenId, bytes calldata data)
        internal
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterMint(address to, uint256 tokenId, bytes calldata data) external override onlyToken {
        _onAfterMint(to, tokenId, data);
    }

    function _onAfterMint(address to, uint256 tokenId, bytes calldata data) internal virtual {}

    // =========================================================================
    //                            BURN HOOKS
    // =========================================================================

    function beforeBurn(uint256 tokenId) external override onlyToken returns (bool allowed, string memory reason) {
        return _onBeforeBurn(tokenId);
    }

    function _onBeforeBurn(uint256 tokenId) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(uint256 tokenId) external override onlyToken {
        _onAfterBurn(tokenId);
    }

    function _onAfterBurn(uint256 tokenId) internal virtual {}

    // =========================================================================
    //                          METADATA HOOKS
    // =========================================================================

    function beforeSetBaseURI(string calldata newBaseURI)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeSetBaseURI(newBaseURI);
    }

    function _onBeforeSetBaseURI(string calldata newBaseURI) internal view virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterSetBaseURI(string calldata newBaseURI) external onlyToken {
        _onAfterSetBaseURI(newBaseURI);
    }

    function _onAfterSetBaseURI(string calldata newBaseURI) internal virtual {}

    function beforeSetTokenURI(uint256 tokenId, string calldata newURI)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeSetTokenURI(tokenId, newURI);
    }

    function _onBeforeSetTokenURI(uint256 tokenId, string calldata newURI)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterSetTokenURI(uint256 tokenId, string calldata newURI) external onlyToken {
        _onAfterSetTokenURI(tokenId, newURI);
    }

    function _onAfterSetTokenURI(uint256 tokenId, string calldata newURI) internal virtual {}
}

/**
 * @title HooksERC721Minter
 * @notice HooksERC721 plus hook-initiated minting authority, declared via ERC-165.
 *
 * Inherit this instead of HooksERC721 when your hooks contract needs to mint
 * (e.g. mint-on-deposit). Doing so makes `supportsInterface(IHookMinter)` return
 * true, so an integrator can tell from the hooks address alone that this contract
 * is part of the token's supply policy.
 *
 * This is a disclosure mechanism, not a security boundary — `token` is public and
 * `hookMint` is gated on the caller being this contract, so a determined author
 * could mint without inheriting this. The point is that the honest path is also
 * the discoverable one. Verifying what a hooks contract actually does still means
 * reading its code; see IntegrityVerifier.sol for confirming a deployment runs it.
 */
abstract contract HooksERC721Minter is HooksERC721, IHookMinter {
    constructor(
        address _issuerAdmin,
        string memory tokenName,
        string memory tokenSymbol,
        string memory contractURI_,
        string memory baseURI_
    ) HooksERC721(_issuerAdmin, tokenName, tokenSymbol, contractURI_, baseURI_) {}

    /// @inheritdoc IHookMinter
    function mintingAuthorityOver() external view override returns (address) {
        return address(token);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IHookMinter).interfaceId || super.supportsInterface(interfaceId);
    }

    function _mintFromHooks(address to, uint256 tokenId) internal {
        token.hookMint(to, tokenId);
    }

    function _setTokenURIFromHooks(uint256 tokenId, string memory newURI) internal {
        token.hookSetTokenURI(tokenId, newURI);
    }
}
