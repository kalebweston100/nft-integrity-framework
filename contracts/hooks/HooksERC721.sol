//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC721.sol";
import "../interfaces/IHooksERC721.sol";

/**
 * @title HooksERC721
 * @notice Abstract base for ERC-721 hooks contracts. Provides the full hook
 *         framework, access control, and deploys its own token. Implements
 *         IHooksERC721 — see that interface for the normative rules this
 *         contract's calling convention follows.
 *
 * DEPLOYMENT FLOW:
 *   1. Deploy MyHooks(issuerAdmin, name, symbol, contractURI, baseURI) inheriting
 *      HooksERC721 — its constructor deploys the IntegrityERC721 token directly
 *      (`new IntegrityERC721(...)`) and wires itself as governor. There is no
 *      factory and no separate initialization step: `token` is set once,
 *      synchronously, as the return value of `new`.
 *
 * EXTENSION:
 *   Override _onBeforeTransfer / _onBeforeMint / _onBeforeBurn for custom logic.
 *   After-hooks are wrapped in try/catch by the token — bugs won't brick the token.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer → validateTransfer → ownership → afterTransfer
 *   MINT:     beforeMint → validateFlags → flags commit → ownership → afterMint
 *   BURN:     ownership check → beforeBurn → ownership → afterBurn
 */
abstract contract HooksERC721 is IHooksERC721, ERC165 {
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

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IHooksERC721).interfaceId || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 tokenId) external override onlyToken {
        _onBeforeTransfer(from, to, tokenId);
    }

    function _onBeforeTransfer(address from, address to, uint256 tokenId) internal virtual {}

    function validateTransfer(address from, address to, uint256 tokenId)
        external
        view
        override
        onlyToken
        returns (bool valid, string memory reason)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 tokenId) external override onlyToken {}

    function onTransferBlocked(address from, address to, uint256 tokenId, string calldata reason) external onlyToken {}

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

    function afterMint(address to, uint256 tokenId, bytes calldata data) external override onlyToken {}

    /// @notice Called before the token commits a mint's flag bitmap. Override to enforce
    ///         custom flag policy (e.g. cap how many tokens can carry a given flag). This
    ///         hook can only allow/deny — it has no access to token storage and cannot
    ///         write flags itself; only the token contract ever writes flag storage.
    function validateFlags(address to, uint256 tokenId, uint256 flags)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateFlags(to, tokenId, flags);
    }

    function _onValidateFlags(address to, uint256 tokenId, uint256 flags)
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

    function beforeBurn(uint256 tokenId) external override onlyToken returns (bool allowed, string memory reason) {
        return _onBeforeBurn(tokenId);
    }

    function _onBeforeBurn(uint256 tokenId) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(uint256 tokenId) external override onlyToken {}

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

    function beforeSetTokenURI(uint256, string calldata)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return (true, "");
    }

    function afterSetTokenURI(uint256, string calldata) external onlyToken {}
}
