//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "../interfaces/IHooks.sol";
import "./RoyaltyBase.sol";

/**
 * @title HooksERC1155Base
 * @notice Abstract base for ERC-1155 hooks contracts without built-in royalty distribution.
 *         Provides the full hook framework, access control, and factory initialization.
 *         Inherit HooksERC1155 instead if you also need the per-tokenId royalty accumulator.
 *
 * DEPLOYMENT FLOW:
 *   1. Deploy MyHooks(factoryAddr, issuerAdmin) inheriting HooksERC1155Base or HooksERC1155
 *   2. Call factory.deployTokenERC1155(myHooksAddr, baseTokenURI, contractURI)
 *   3. Factory deploys IntegrityERC1155 and calls hooks.initializeToken(tokenAddress)
 *
 * EXTENSION:
 *   Override _onBeforeTransfer1155 / _onBeforeMint1155 / _onBeforeBurn1155 for custom logic.
 *   Override _onAfterMint1155 / _onAfterBurn1155 for post-mutation logic.
 *   After-hooks are wrapped in try/catch by the token — bugs won't brick the token.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer1155 → validateTransfer1155 → balance → afterTransfer1155
 *   MINT:     beforeMint1155 → validateFlags1155 → flags commit/check → balance → afterMint1155
 *   BURN:     balance check → beforeBurn1155 → balance → afterBurn1155
 */
abstract contract HooksERC1155Base is IInitializableHooks {

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

    function _tokenBalanceOf(address account, uint256 id) internal view returns (uint256) {
        return IERC1155(tokenContract).balanceOf(account, id);
    }

    // Called before each hook — no-ops here, overridden by HooksERC1155 to run royalty settlement
    function _beforeTransferSettle(address from, address to, uint256 id) internal virtual {}
    function _beforeMintSettle(address to, uint256 id) internal virtual {}
    function _beforeBurnSettle(address from, uint256 id) internal virtual {}

    function _mintFromHooks(address to, uint256 id, uint256 amount, uint256 flags, bytes32 metadataHash) internal {
        IHookMintERC1155(tokenContract).hookMint(to, id, amount, flags, metadataHash);
    }

    function _setTokenURIFromHooks(uint256 id, string memory newURI) internal {
        IHookMintERC1155(tokenContract).hookSetTokenURI(id, newURI);
    }

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    function beforeTransfer1155(address from, address to, uint256 id, uint256 amount) external onlyToken {
        _beforeTransferSettle(from, to, id);
        _onBeforeTransfer1155(from, to, id, amount);
    }

    function _onBeforeTransfer1155(address from, address to, uint256 id, uint256 amount) internal virtual {}

    function validateTransfer1155(
        address from,
        address to,
        uint256 id,
        uint256 amount
    ) external view onlyToken returns (bool valid, string memory reason) {
        return (true, "");
    }

    function afterTransfer1155(address from, address to, uint256 id, uint256 amount) external virtual onlyToken {}

    function onTransferBlocked1155(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        string calldata reason
    ) external onlyToken {}

    // =========================================================================
    //                            MINT HOOKS
    // =========================================================================

    function beforeMint1155(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external onlyToken returns (bool allowed, string memory reason) {
        _beforeMintSettle(to, id);
        return _onBeforeMint1155(to, id, amount, data);
    }

    function _onBeforeMint1155(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterMint1155(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external virtual onlyToken {
        _onAfterMint1155(to, id, amount, data);
    }

    function _onAfterMint1155(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) internal virtual {}

    /// @notice Called before the token commits/checks a mint's flag bitmap for an id.
    ///         Override to enforce custom flag policy. This hook can only allow/deny —
    ///         it has no access to token storage and cannot write flags itself; only the
    ///         token contract ever writes flag storage.
    function validateFlags1155(
        address to,
        uint256 id,
        uint256 flags
    ) external view onlyToken returns (bool allowed, string memory reason) {
        return _onValidateFlags1155(to, id, flags);
    }

    function _onValidateFlags1155(
        address to,
        uint256 id,
        uint256 flags
    ) internal view virtual returns (bool, string memory) {
        return (true, "");
    }

    // =========================================================================
    //                            BURN HOOKS
    // =========================================================================

    function beforeBurn1155(
        address from,
        uint256 id,
        uint256 amount
    ) external onlyToken returns (bool allowed, string memory reason) {
        _beforeBurnSettle(from, id);
        return _onBeforeBurn1155(from, id, amount);
    }

    function _onBeforeBurn1155(
        address from,
        uint256 id,
        uint256 amount
    ) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn1155(
        address from,
        uint256 id,
        uint256 amount
    ) external virtual onlyToken {
        _onAfterBurn1155(from, id, amount);
    }

    function _onAfterBurn1155(address from, uint256 id, uint256 amount) internal virtual {}

    // =========================================================================
    //                          METADATA HOOKS
    // =========================================================================

    function beforeSetURI(
        string calldata newUri
    ) external onlyToken returns (bool allowed, string memory reason) {
        return (true, "");
    }

    function afterSetURI(string calldata newUri) external onlyToken {}

    function beforeSetTokenURI1155(
        uint256,
        string calldata
    ) external view onlyToken returns (bool allowed, string memory reason) {
        return (true, "");
    }

    function afterSetTokenURI1155(uint256, string calldata) external onlyToken {}
}

/**
 * @title HooksERC1155
 * @notice HooksERC1155Base with optional per-tokenId pro-rata ETH royalty distribution.
 *         Pass `enableRoyalties = true` in the constructor to activate the royalty pool;
 *         pass `false` for a pure hooks contract with no royalty overhead at runtime.
 *
 * Per-tokenId supply is tracked internally via afterMint1155/afterBurn1155 since
 * IntegrityERC1155 only exposes a global totalSupply. Supply tracking is skipped when
 * royalties are disabled.
 *
 * CLAIMING: call claimRoyalties(uint256[] tokenIds) with all tokenIds the caller
 * holds (or has held) to ensure a complete payout.
 */
abstract contract HooksERC1155 is HooksERC1155Base, RoyaltyBase {

    event RoyaltiesDistributed(uint256 indexed tokenId, uint256 amount);

    /// @notice Whether royalty distribution is active for this deployment.
    bool public immutable royaltiesEnabled;

    /// @notice Accumulated royalties per token unit for each tokenId, scaled by ROYALTY_PRECISION.
    mapping(uint256 => uint256) public accumulatedRoyaltiesPerToken;

    /// @notice Per-holder, per-tokenId snapshot of the accumulator at last settlement.
    mapping(address => mapping(uint256 => uint256)) public royaltyDebt;

    mapping(uint256 => uint256) private _tokenSupplyById;

    constructor(address _factory, address _issuerAdmin, bool _royaltiesEnabled)
        HooksERC1155Base(_factory, _issuerAdmin)
    {
        royaltiesEnabled = _royaltiesEnabled;
    }

    function tokenSupply(uint256 tokenId) external view returns (uint256) {
        return _tokenSupplyById[tokenId];
    }

    function _beforeTransferSettle(address from, address to, uint256 id) internal override {
        if (!royaltiesEnabled) return;
        if (from != address(0)) _settleHolderForToken(from, id);
        if (to != address(0)) _settleHolderForToken(to, id);
    }

    function _beforeMintSettle(address to, uint256 id) internal override {
        if (!royaltiesEnabled) return;
        _settleHolderForToken(to, id);
    }

    function _beforeBurnSettle(address from, uint256 id) internal override {
        if (!royaltiesEnabled) return;
        _settleHolderForToken(from, id);
    }

    function _settleHolderForToken(address holder, uint256 tokenId) internal {
        uint256 balance = _tokenBalanceOf(holder, tokenId);
        uint256 accRate = accumulatedRoyaltiesPerToken[tokenId];
        uint256 earned = (balance * (accRate - royaltyDebt[holder][tokenId])) / ROYALTY_PRECISION;
        _addPending(holder, earned);
        royaltyDebt[holder][tokenId] = accRate;
    }

    function afterMint1155(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external override onlyToken {
        if (royaltiesEnabled) _tokenSupplyById[id] += amount;
        _onAfterMint1155(to, id, amount, data);
    }

    function afterBurn1155(
        address from,
        uint256 id,
        uint256 amount
    ) external override onlyToken {
        if (royaltiesEnabled) _tokenSupplyById[id] -= amount;
        _onAfterBurn1155(from, id, amount);
    }

    /// @dev Adds `amount` into the per-tokenId accumulator. Called by distributeRoyalties
    ///      and by subclass overrides that split off an artist cut first.
    function _distributeToAccumulator(uint256 tokenId, uint256 amount) internal {
        uint256 supply = _tokenSupplyById[tokenId];
        require(supply > 0, "Royalty: no supply for token");
        accumulatedRoyaltiesPerToken[tokenId] += (amount * ROYALTY_PRECISION) / supply;
        totalRoyaltiesDistributed += amount;
        emit RoyaltiesDistributed(tokenId, amount);
    }

    /// @notice Deposit ETH into the royalty pool for a specific tokenId.
    function distributeRoyalties(uint256 tokenId) external payable virtual {
        require(royaltiesEnabled, "Royalty: not enabled");
        require(msg.value > 0, "Royalty: zero amount");
        _distributeToAccumulator(tokenId, msg.value);
    }

    /// @notice Settle and claim royalties across the given tokenIds.
    function claimRoyalties(uint256[] calldata tokenIds) external nonReentrant {
        require(royaltiesEnabled, "Royalty: not enabled");
        for (uint256 i = 0; i < tokenIds.length; i++) {
            _settleHolderForToken(msg.sender, tokenIds[i]);
        }
        uint256 amount = pendingRoyalties[msg.sender];
        require(amount > 0, "Royalty: nothing to claim");
        pendingRoyalties[msg.sender] = 0;
        emit RoyaltiesClaimed(msg.sender, amount);
        _sendRoyalties(msg.sender, amount);
    }

    /// @notice Returns claimable royalties for a holder across the specified tokenIds.
    function pendingRoyaltiesFor(address holder, uint256[] calldata tokenIds) external view returns (uint256) {
        if (!royaltiesEnabled) return 0;
        uint256 total = pendingRoyalties[holder];
        for (uint256 i = 0; i < tokenIds.length; i++) {
            uint256 id = tokenIds[i];
            uint256 balance = _tokenBalanceOf(holder, id);
            total += (balance * (accumulatedRoyaltiesPerToken[id] - royaltyDebt[holder][id])) / ROYALTY_PRECISION;
        }
        return total;
    }
}
