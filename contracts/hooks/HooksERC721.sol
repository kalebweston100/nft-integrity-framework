//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "../interfaces/IHooks.sol";
import "./RoyaltyBase.sol";

/// @dev IntegrityERC721 tracks totalSupply internally; this surfaces it.
interface IERC721TotalSupply {
    function totalSupply() external view returns (uint256);
}

/**
 * @title HooksERC721Base
 * @notice Abstract base for ERC-721 hooks contracts without built-in royalty distribution.
 *         Provides the full hook framework, access control, and factory initialization.
 *         Inherit HooksERC721 instead if you also need the royalty accumulator.
 *
 * DEPLOYMENT FLOW:
 *   1. Deploy MyHooks(factoryAddr, issuerAdmin) inheriting HooksERC721Base or HooksERC721
 *   2. Call factory.deployTokenERC721(myHooksAddr, name, symbol, contractURI, baseURI)
 *   3. Factory deploys IntegrityERC721 and calls hooks.initializeToken(tokenAddress)
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
abstract contract HooksERC721Base is IInitializableHooks {

    event TokenInitialized(address indexed tokenContract, address indexed factory);

    address public immutable factory;
    address public tokenContract;
    bool private _initialized;
    address public issuerAdmin;

    modifier onlyFactory() {
        require(msg.sender == factory, "Hooks: Not factory");
        _;
    }

    modifier onlyToken() {
        require(msg.sender == tokenContract, "Hooks: Not token contract");
        _;
    }

    modifier onlyIssuerAdmin() {
        require(msg.sender == issuerAdmin, "Hooks: Not issuer admin");
        _;
    }

    constructor(address _factory, address _issuerAdmin) {
        require(_factory != address(0), "Hooks: Zero factory address");
        require(_issuerAdmin != address(0), "Hooks: Zero admin address");
        factory = _factory;
        issuerAdmin = _issuerAdmin;
    }

    function initializeToken(address _tokenContract) external override onlyFactory {
        require(!_initialized, "Hooks: Already initialized");
        require(_tokenContract != address(0), "Hooks: Zero token address");
        tokenContract = _tokenContract;
        _initialized = true;
        emit TokenInitialized(_tokenContract, factory);
    }

    function transferAdmin(address newAdmin) external onlyIssuerAdmin {
        require(newAdmin != address(0), "Hooks: Zero address");
        issuerAdmin = newAdmin;
    }

    function _tokenBalanceOf(address account) internal view returns (uint256) {
        return IERC721(tokenContract).balanceOf(account);
    }

    function _tokenOwnerOf(uint256 tokenId) internal view returns (address) {
        return IERC721(tokenContract).ownerOf(tokenId);
    }

    function _tokenTotalSupply() internal view returns (uint256) {
        return IERC721TotalSupply(tokenContract).totalSupply();
    }

    // Called before each hook — no-op here, overridden by HooksERC721.
    // _beforeBurnSettle receives tokenId because ownership must be resolved before it clears.
    function _beforeTransferSettle(address from, address to) internal virtual {}
    function _beforeMintSettle(address to) internal virtual {}
    function _beforeBurnSettle(uint256 tokenId) internal virtual {}

    function _mintFromHooks(address to, uint256 tokenId, uint256 flags, bytes32 metadataHash) internal {
        IHookMintERC721(tokenContract).hookMint(to, tokenId, flags, metadataHash);
    }

    function _setTokenURIFromHooks(uint256 tokenId, string memory newURI) internal {
        IHookMintERC721(tokenContract).hookSetTokenURI(tokenId, newURI);
    }

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    function beforeTransfer721(address from, address to, uint256 tokenId) external onlyToken {
        _beforeTransferSettle(from, to);
        _onBeforeTransfer721(from, to, tokenId);
    }

    function _onBeforeTransfer721(address from, address to, uint256 tokenId) internal virtual {}

    function validateTransfer721(
        address from,
        address to,
        uint256 tokenId
    ) external view onlyToken returns (bool valid, string memory reason) {
        return (true, "");
    }

    function afterTransfer721(address from, address to, uint256 tokenId) external onlyToken {}

    function onTransferBlocked721(
        address from,
        address to,
        uint256 tokenId,
        string calldata reason
    ) external onlyToken {}

    // =========================================================================
    //                            MINT HOOKS
    // =========================================================================

    function beforeMint721(
        address to,
        uint256 tokenId,
        bytes calldata data
    ) external onlyToken returns (bool allowed, string memory reason) {
        _beforeMintSettle(to);
        return _onBeforeMint721(to, tokenId, data);
    }

    function _onBeforeMint721(
        address to,
        uint256 tokenId,
        bytes calldata data
    ) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterMint721(address to, uint256 tokenId, bytes calldata data) external onlyToken {}

    /// @notice Called before the token commits a mint's flag bitmap. Override to enforce
    ///         custom flag policy (e.g. cap how many tokens can carry a given flag). This
    ///         hook can only allow/deny — it has no access to token storage and cannot
    ///         write flags itself; only the token contract ever writes flag storage.
    function validateFlags721(
        address to,
        uint256 tokenId,
        uint256 flags
    ) external view onlyToken returns (bool allowed, string memory reason) {
        return _onValidateFlags721(to, tokenId, flags);
    }

    function _onValidateFlags721(
        address to,
        uint256 tokenId,
        uint256 flags
    ) internal view virtual returns (bool, string memory) {
        return (true, "");
    }

    // =========================================================================
    //                            BURN HOOKS
    // =========================================================================

    function beforeBurn721(
        uint256 tokenId
    ) external onlyToken returns (bool allowed, string memory reason) {
        _beforeBurnSettle(tokenId);
        return _onBeforeBurn721(tokenId);
    }

    function _onBeforeBurn721(uint256 tokenId) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn721(uint256 tokenId) external onlyToken {}

    // =========================================================================
    //                          METADATA HOOKS
    // =========================================================================

    function beforeSetBaseURI(
        string calldata newBaseURI
    ) external onlyToken returns (bool allowed, string memory reason) {
        return (true, "");
    }

    function afterSetBaseURI(string calldata newBaseURI) external onlyToken {}

    function beforeSetTokenURI721(
        uint256,
        string calldata
    ) external view onlyToken returns (bool allowed, string memory reason) {
        return (true, "");
    }

    function afterSetTokenURI721(uint256, string calldata) external onlyToken {}
}

/**
 * @title HooksERC721
 * @notice HooksERC721Base with built-in pro-rata ETH royalty distribution.
 *         Each NFT counts as one unit. Royalties are settled before each balance change.
 *         Inherit this if you want royalties; use HooksERC721Base if you do not.
 */
abstract contract HooksERC721 is HooksERC721Base, RoyaltyBase {

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

    // Resolves the owner via ownerOf before the token clears ownership on burn.
    function _beforeBurnSettle(uint256 tokenId) internal override {
        _settleHolder(_tokenOwnerOf(tokenId));
    }

    function _settleHolder(address holder) internal {
        uint256 earned = (_tokenBalanceOf(holder) * (accumulatedRoyaltiesPerToken - royaltyDebt[holder])) / ROYALTY_PRECISION;
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
        uint256 unsettled = (_tokenBalanceOf(holder) * (accumulatedRoyaltiesPerToken - royaltyDebt[holder])) / ROYALTY_PRECISION;
        return pendingRoyalties[holder] + unsettled;
    }
}
