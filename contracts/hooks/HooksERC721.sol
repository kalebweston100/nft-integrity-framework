//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../token/IntegrityERC721.sol";

/**
 * @title HooksERC721
 * @notice Abstract base for ERC-721 hooks contracts. Provides the full hook
 *         framework, access control, and deploys its own token.
 *
 * DEPLOYMENT FLOW:
 *   1. Deploy MyHooks(issuerAdmin, name, symbol, contractURI, baseURI) inheriting
 *      HooksERC721 — its constructor deploys the IntegrityERC721 token directly
 *      (`new IntegrityERC721(...)`) and wires itself as governor. There is no
 *      factory and no separate initialization step: `token` is set once,
 *      synchronously, as the return value of `new`.
 *
 * EXTENSION:
 *   Override _onBeforeTransfer721 / _onBeforeMint721 / _onBeforeBurn721 for custom logic.
 *   After-hooks are wrapped in try/catch by the token — bugs won't brick the token.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer721 → validateTransfer721 → ownership → afterTransfer721
 *   MINT:     beforeMint721 → validateFlags721 → flags commit → ownership → afterMint721
 *   BURN:     ownership check → beforeBurn721 → ownership → afterBurn721
 */
abstract contract HooksERC721 {
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
        issuerAdmin = newAdmin;
    }

    function _tokenOwnerOf(uint256 tokenId) internal view returns (address) {
        return token.ownerOf(tokenId);
    }

    function _mintFromHooks(address to, uint256 tokenId, uint256 flags, bytes32 metadataHash) internal {
        token.hookMint(to, tokenId, flags, metadataHash);
    }

    function _setTokenURIFromHooks(uint256 tokenId, string memory newURI) internal {
        token.hookSetTokenURI(tokenId, newURI);
    }

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    function beforeTransfer721(address from, address to, uint256 tokenId) external onlyToken {
        _onBeforeTransfer721(from, to, tokenId);
    }

    function _onBeforeTransfer721(address from, address to, uint256 tokenId) internal virtual {}

    function validateTransfer721(address from, address to, uint256 tokenId)
        external
        view
        onlyToken
        returns (bool valid, string memory reason)
    {
        return (true, "");
    }

    function afterTransfer721(address from, address to, uint256 tokenId) external onlyToken {}

    function onTransferBlocked721(address from, address to, uint256 tokenId, string calldata reason)
        external
        onlyToken
    {}

    // =========================================================================
    //                            MINT HOOKS
    // =========================================================================

    function beforeMint721(address to, uint256 tokenId, bytes calldata data)
        external
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeMint721(to, tokenId, data);
    }

    function _onBeforeMint721(address to, uint256 tokenId, bytes calldata data)
        internal
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterMint721(address to, uint256 tokenId, bytes calldata data) external onlyToken {}

    /// @notice Called before the token commits a mint's flag bitmap. Override to enforce
    ///         custom flag policy (e.g. cap how many tokens can carry a given flag). This
    ///         hook can only allow/deny — it has no access to token storage and cannot
    ///         write flags itself; only the token contract ever writes flag storage.
    function validateFlags721(address to, uint256 tokenId, uint256 flags)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateFlags721(to, tokenId, flags);
    }

    function _onValidateFlags721(address to, uint256 tokenId, uint256 flags)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    // =========================================================================
    //                            BURN HOOKS
    // =========================================================================

    function beforeBurn721(uint256 tokenId) external onlyToken returns (bool allowed, string memory reason) {
        return _onBeforeBurn721(tokenId);
    }

    function _onBeforeBurn721(uint256 tokenId) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn721(uint256 tokenId) external onlyToken {}

    // =========================================================================
    //                          METADATA HOOKS
    // =========================================================================

    function beforeSetBaseURI(string calldata newBaseURI)
        external
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return (true, "");
    }

    function afterSetBaseURI(string calldata newBaseURI) external onlyToken {}

    function beforeSetTokenURI721(uint256, string calldata)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return (true, "");
    }

    function afterSetTokenURI721(uint256, string calldata) external onlyToken {}
}
