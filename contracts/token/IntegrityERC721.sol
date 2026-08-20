//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "./IntegrityTokenBase.sol";
import "../hooks/HooksERC721.sol";
import "../interfaces/IHooks.sol";
import "../interfaces/IFlaggedToken.sol";
import "../interfaces/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import "@openzeppelin/contracts/interfaces/IERC2981.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IntegrityERC721
 * @notice The user-facing ERC-721 token contract. Users call transferFrom(),
 *         safeTransferFrom(), etc. directly on this contract. Contains ALL token
 *         storage, the full locked transfer pipeline, the on-chain anti-fraud
 *         "flags" system, AND delegates to an external developer-deployed hooks
 *         contract for custom logic.
 *
 * FLAGS (anti-fraud integrity system):
 *   Each collection maintains an append-only registry mapping bit indices (0-255)
 *   to permanent human-readable labels via defineFlag(). Once minted, a token's
 *   flag bitmap and metadata hash are committed exactly once, atomically with
 *   mint, and are never writable again by anyone — including the issuer admin.
 *   A buyer calls verifyToken()/hasFlag() directly on this contract (independent
 *   of any marketplace) to trustlessly confirm a token really carries the traits
 *   it's advertised with before buying it. See IFlaggedToken for the full
 *   buyer-facing surface.
 *
 * INHERITS:
 *   IntegrityTokenBase — reentrancy guard, IIntegrityToken partial implementation
 *   TokenAdmin (via Base) — issuer admin, pause/unpause
 *
 * SECURITY:
 *   - Deployed exclusively by its own hooks contract, via `new`, from inside that
 *     hooks contract's constructor — there is no separate factory
 *   - transferFrom(), safeTransferFrom(), approve(), setApprovalForAll() are non-virtual
 *   - Transfer pipeline is non-overridable (this contract is not abstract)
 *   - Hooks run via external call — cannot access token storage, so hooks can
 *     gate which flags a mint is allowed to carry but can never write flag storage
 *   - Hooks address is read from msg.sender at construction time (the deploying
 *     contract) and stored in a plain, setter-less slot — never immutable, so this
 *     contract's own runtime bytecode stays byte-identical across every deployment
 *     regardless of which hooks contract created it. See Codehash.sol.
 *   - Standard ERC-721 transfer/approval surface is untouched by the flags system,
 *     so marketplaces (e.g. OpenSea via Seaport) trade this token normally
 */
contract IntegrityERC721 is IERC721, IHookMintERC721, IFlaggedToken, IntegrityTokenBase {
    // =========================================================================
    //                          EVENTS
    // =========================================================================

    // Token-specific events (ERC721 events inherited from IERC721)
    event HolderAdded(address indexed holder, uint256 holderCount);
    event HolderRemoved(address indexed holder, uint256 holderCount);
    event TransferBlocked(address indexed from, address indexed to, uint256 tokenId, string reason);
    event HookCallFailed(string hookName, bytes reason);

    // =========================================================================
    //                     HOOKS CONTRACT (plain storage, setter-less)
    // =========================================================================

    /// @notice The hooks contract that deployed and governs this token. Never
    ///         address(0) — this contract only ever exists because a hooks contract
    ///         called `new` on it. Deliberately not `immutable`: see contract NatSpec.
    HooksERC721 private _hooks;

    // =========================================================================
    //                     TOKEN STORAGE
    // =========================================================================

    string private _name;
    string private _symbol;
    uint256 private _totalSupply;
    uint256 private _holderCount;

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    // =========================================================================
    //                     FLAGS (anti-fraud integrity system)
    // =========================================================================

    /// @dev Permanent label for each flag bit index. Append-only — see defineFlag().
    mapping(uint8 => string) private _flagLabels;
    /// @dev Bitmask of every bit index that has been given a label.
    uint256 private _definedFlagsMask;

    /// @dev Per-token committed flag bitmap. [LOCKED] written once, at mint, never again.
    mapping(uint256 => uint256) private _flags;
    /// @dev Per-token committed metadata hash. [LOCKED] written once, at mint, never again.
    mapping(uint256 => bytes32) private _metadataHash;

    // =========================================================================
    //                     ERC-2981 ROYALTY STORAGE
    // =========================================================================

    address private _royaltyReceiver;
    uint96 private _royaltyFeeNumerator;

    // =========================================================================
    //                     METADATA STORAGE
    // =========================================================================

    string private _baseURI;
    mapping(uint256 => string) private _tokenURIs;

    // =========================================================================
    //                          CONSTRUCTOR
    // =========================================================================

    constructor(
        address admin,
        string memory tokenName,
        string memory tokenSymbol,
        string memory initialContractURI,
        string memory baseURI
    ) IntegrityTokenBase(admin, initialContractURI) {
        _hooks = HooksERC721(msg.sender);
        _name = tokenName;
        _symbol = tokenSymbol;
        _baseURI = baseURI;
    }

    // =========================================================================
    //                     CHAIN-OF-TRUST GETTERS
    // =========================================================================

    function hooksContract() external view returns (address) {
        return address(_hooks);
    }

    // =========================================================================
    //                  ERC-721 ENTRY POINTS (non-virtual, locked)
    // =========================================================================

    function transferFrom(address from, address to, uint256 tokenId) external override whenNotPaused nonReentrant {
        if (!_isApprovedOrOwner(msg.sender, tokenId)) revert NotOwnerOrApproved();
        _transferPipeline721(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) external override whenNotPaused nonReentrant {
        if (!_isApprovedOrOwner(msg.sender, tokenId)) revert NotOwnerOrApproved();
        _transferPipeline721(from, to, tokenId);
        _checkOnERC721Received(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external override {
        if (!_isApprovedOrOwner(msg.sender, tokenId)) revert NotOwnerOrApproved();
        _transferPipeline721(from, to, tokenId);
        _checkOnERC721Received(from, to, tokenId, data);
    }

    function approve(address to, uint256 tokenId) external override {
        address tokenOwner = _ownerOf(tokenId);
        if (msg.sender != tokenOwner && !_operatorApprovals[tokenOwner][msg.sender]) revert NotOwnerOrOperator();
        _tokenApprovals[tokenId] = to;
        emit Approval(tokenOwner, to, tokenId);
    }

    function setApprovalForAll(address operator, bool approved) external override {
        if (msg.sender == operator) revert SelfApproval();
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    // =========================================================================
    //                   TRANSFER PIPELINE (private, locked)
    // =========================================================================

    function _transferPipeline721(address from, address to, uint256 tokenId) private {
        // [LOCKED] Ownership validation
        if (_owners[tokenId] != from) revert TokenNotOwned();
        if (to == address(0)) revert ZeroAddress();

        // [HOOKS - external call] Developer's pre-transfer and validation logic
        _hooks.beforeTransfer(from, to, tokenId);
        (bool valid, string memory reason) = _hooks.validateTransfer(from, to, tokenId);
        require(valid, reason);

        // [LOCKED] Clear approvals
        delete _tokenApprovals[tokenId];

        // [LOCKED] Ownership mutation
        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;
        emit Transfer(from, to, tokenId);

        // [LOCKED] Holder tracking
        if (_balances[to] == 1) {
            _holderCount++;
            emit HolderAdded(to, _holderCount);
        }
        if (_balances[from] == 0) {
            _holderCount--;
            emit HolderRemoved(from, _holderCount);
        }

        // [HOOKS - external call, safe] Developer's post-transfer logic
        try _hooks.afterTransfer(from, to, tokenId) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterTransfer721", failReason);
        }
    }

    // =========================================================================
    //                     ISSUER ADMIN: MINT / BURN
    // =========================================================================

    /// @notice Mint an NFT, committing its flags and metadata hash permanently. Only
    ///         callable by issuer admin.
    /// @param to Recipient address.
    /// @param tokenId The NFT token ID to mint.
    /// @param flags Bitmap of flags to commit to this token. Every set bit must already
    ///              have a label defined via defineFlag(), or the mint reverts.
    /// @param metaHash keccak256 commitment to the token's canonical off-chain metadata,
    ///                 so it can be verified later via verifyMetadata(). Pass bytes32(0)
    ///                 to skip metadata commitment.
    /// @param data Arbitrary data forwarded to hooks.
    function mint(address to, uint256 tokenId, uint256 flags, bytes32 metaHash, bytes calldata data)
        external
        onlyIssuerAdmin
        whenNotPaused
        nonReentrant
    {
        _mintLogic(to, tokenId, flags, metaHash, data);
    }

    /// @notice Burn an NFT with holder tracking. Only callable by issuer admin.
    function burn(uint256 tokenId) external onlyIssuerAdmin whenNotPaused nonReentrant {
        address tokenOwner = _owners[tokenId];
        if (tokenOwner == address(0)) revert NonexistentToken();

        // [HOOKS - external call] Developer's pre-burn logic
        (bool allowed, string memory reason) = _hooks.beforeBurn(tokenId);
        require(allowed, reason);

        delete _tokenApprovals[tokenId];
        _balances[tokenOwner] -= 1;
        delete _owners[tokenId];
        _totalSupply -= 1;
        emit Transfer(tokenOwner, address(0), tokenId);

        if (_balances[tokenOwner] == 0) {
            _holderCount--;
            emit HolderRemoved(tokenOwner, _holderCount);
        }

        // [HOOKS - external call, safe] Developer's post-burn logic
        try _hooks.afterBurn(tokenId) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterBurn721", failReason);
        }
    }

    /// @dev Shared mint logic with hooks (called by mint with data).
    function _mintLogic(address to, uint256 tokenId, uint256 flags, bytes32 metaHash, bytes calldata data) private {
        _mintChecks(to, tokenId);

        // [HOOKS - external call] Developer's pre-mint logic
        (bool allowed, string memory reason) = _hooks.beforeMint(to, tokenId, data);
        require(allowed, reason);

        // [HOOKS - external call] Developer's custom flag policy (allow/deny only —
        // the hook has no storage access here and cannot write flags itself)
        (bool flagsAllowed, string memory flagsReason) = _hooks.validateFlags(to, tokenId, flags);
        require(flagsAllowed, flagsReason);

        // [LOCKED] Commit flags + metadata hash atomically with mint — never writable again
        _commitFlags(tokenId, flags, metaHash);

        _mintBalanceUpdate(to, tokenId);

        // [HOOKS - external call, safe] Developer's post-mint logic
        try _hooks.afterMint(to, tokenId, data) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterMint721", failReason);
        }
    }

    function _mintChecks(address to, uint256 tokenId) private view {
        if (to == address(0)) revert ZeroAddress();
        if (_owners[tokenId] != address(0)) revert TokenAlreadyMinted();
    }

    /// @dev [LOCKED] Commits a token's flag bitmap and metadata hash. Only ever called
    ///      once per tokenId, from mint/hookMint — no other function writes these mappings.
    function _commitFlags(uint256 tokenId, uint256 flags, bytes32 metaHash) private {
        if (flags & ~_definedFlagsMask != 0) revert UndefinedFlagBits();
        _flags[tokenId] = flags;
        _metadataHash[tokenId] = metaHash;
        emit FlagsCommitted(tokenId, flags, metaHash);
    }

    function _mintBalanceUpdate(address to, uint256 tokenId) private {
        bool wasNewHolder = (_balances[to] == 0);

        _balances[to] += 1;
        _owners[tokenId] = to;
        _totalSupply += 1;
        emit Transfer(address(0), to, tokenId);

        if (wasNewHolder) {
            _holderCount++;
            emit HolderAdded(to, _holderCount);
        }
    }

    // =========================================================================
    //                     HOOKS-INITIATED MINT / URI (no before/after callbacks)
    // =========================================================================

    /// @notice Mint an NFT initiated by the hooks contract, committing its flags and
    ///         metadata hash permanently. Skips beforeMint721/afterMint721 callbacks
    ///         to avoid circular calls (the hooks contract IS the caller, so its own
    ///         logic already ran before invoking this).
    /// @dev Only callable by the hooks contract.
    function hookMint(address to, uint256 tokenId, uint256 flags, bytes32 metaHash)
        external
        override
        whenNotPaused
        nonReentrant
    {
        if (msg.sender != address(_hooks)) revert NotHooksContract();
        _mintChecks(to, tokenId);
        _commitFlags(tokenId, flags, metaHash);
        _mintBalanceUpdate(to, tokenId);
    }

    /// @notice Set a per-token URI initiated by the hooks contract.
    /// @dev Only callable by the hooks contract.
    function hookSetTokenURI(uint256 tokenId, string calldata newURI) external override whenNotPaused {
        if (msg.sender != address(_hooks)) revert NotHooksContract();
        if (_owners[tokenId] == address(0)) revert NonexistentToken();
        _tokenURIs[tokenId] = newURI;
    }

    // =========================================================================
    //                     FLAGS: COLLECTION-LEVEL REGISTRY
    // =========================================================================

    /// @notice Permanently defines the human-readable label for a flag bit index.
    ///         Append-only — reverts if that bit already has a label, so the meaning
    ///         of a flag can never change after buyers may have relied on it.
    /// @dev Only callable by issuer admin.
    function defineFlag(uint8 bitIndex, string calldata label) external onlyIssuerAdmin {
        if (bytes(_flagLabels[bitIndex]).length != 0) revert FlagAlreadyDefined();
        if (bytes(label).length == 0) revert EmptyFlagLabel();
        _flagLabels[bitIndex] = label;
        _definedFlagsMask |= (uint256(1) << bitIndex);
        emit FlagDefined(bitIndex, label);
    }

    function flagLabel(uint8 bitIndex) external view override returns (string memory) {
        return _flagLabels[bitIndex];
    }

    function definedFlags() external view override returns (uint256) {
        return _definedFlagsMask;
    }

    // =========================================================================
    //                     FLAGS: BUYER-FACING VERIFICATION
    // =========================================================================

    function hasFlag(uint256 tokenId, uint8 bitIndex) external view override returns (bool) {
        if (_owners[tokenId] == address(0)) revert NonexistentToken();
        return (_flags[tokenId] >> bitIndex) & 1 == 1;
    }

    function flagsOf(uint256 tokenId) external view override returns (uint256) {
        if (_owners[tokenId] == address(0)) revert NonexistentToken();
        return _flags[tokenId];
    }

    function metadataHashOf(uint256 tokenId) external view override returns (bytes32) {
        if (_owners[tokenId] == address(0)) revert NonexistentToken();
        return _metadataHash[tokenId];
    }

    /// @notice One-call anti-scam check: does `tokenId` really carry every flag the
    ///         seller claims, and (optionally) does its metadata match what the buyer
    ///         was shown? Safe to call before purchasing on any marketplace, since it
    ///         reads the token's permanent on-chain commitment, not any off-chain claim.
    function verifyToken(uint256 tokenId, uint256 requiredFlagsMask, bytes32 expectedMetadataHash)
        external
        view
        override
        returns (bool ok, uint256 actualFlags, bytes32 actualMetadataHash)
    {
        if (_owners[tokenId] == address(0)) return (false, 0, bytes32(0));
        actualFlags = _flags[tokenId];
        actualMetadataHash = _metadataHash[tokenId];
        bool flagsOk = (actualFlags & requiredFlagsMask) == requiredFlagsMask;
        bool metaOk = expectedMetadataHash == bytes32(0) || expectedMetadataHash == actualMetadataHash;
        ok = flagsOk && metaOk;
    }

    function verifyMetadata(uint256 tokenId, bytes calldata metadata) external view override returns (bool) {
        if (_owners[tokenId] == address(0)) revert NonexistentToken();
        return keccak256(metadata) == _metadataHash[tokenId];
    }

    // =========================================================================
    //                     ERC-2981 ROYALTIES
    // =========================================================================

    /// @notice Set the default royalty info for all tokens. Only callable by issuer admin.
    /// @param receiver Address to receive royalty payments.
    /// @param feeNumerator Royalty fee in basis points (e.g., 500 = 5%). Max 10000.
    function setDefaultRoyalty(address receiver, uint96 feeNumerator) external onlyIssuerAdmin {
        if (feeNumerator > 10000) revert RoyaltyTooHigh();
        if (receiver == address(0)) revert ZeroAddress();
        _royaltyReceiver = receiver;
        _royaltyFeeNumerator = feeNumerator;
    }

    /// @notice ERC-2981 royalty info query.
    function royaltyInfo(uint256, uint256 salePrice) external view returns (address receiver, uint256 royaltyAmount) {
        receiver = _royaltyReceiver;
        royaltyAmount = (salePrice * _royaltyFeeNumerator) / 10000;
    }

    // =========================================================================
    //                     METADATA: BASE URI
    // =========================================================================

    /// @notice Set the base URI for token metadata. Only callable by issuer admin.
    function setBaseURI(string calldata newBaseURI) external onlyIssuerAdmin {
        (bool allowed, string memory reason) = _hooks.beforeSetBaseURI(newBaseURI);
        require(allowed, reason);

        _baseURI = newBaseURI;

        try _hooks.afterSetBaseURI(newBaseURI) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterSetBaseURI", failReason);
        }
    }

    /// @notice Set a per-token URI override. Empty string clears the override,
    ///         reverting to baseURI + tokenId for that token. Only callable by issuer admin.
    function setTokenURI(uint256 tokenId, string calldata newTokenURI) external onlyIssuerAdmin {
        if (_owners[tokenId] == address(0)) revert NonexistentToken();

        (bool allowed, string memory reason) = _hooks.beforeSetTokenURI(tokenId, newTokenURI);
        require(allowed, reason);

        _tokenURIs[tokenId] = newTokenURI;

        try _hooks.afterSetTokenURI(tokenId, newTokenURI) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterSetTokenURI721", failReason);
        }
    }

    // =========================================================================
    //                     INTERNAL HELPERS
    // =========================================================================

    function _ownerOf(uint256 tokenId) private view returns (address) {
        address tokenOwner = _owners[tokenId];
        if (tokenOwner == address(0)) revert NonexistentToken();
        return tokenOwner;
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) private view returns (bool) {
        address tokenOwner = _owners[tokenId];
        return (spender == tokenOwner || _tokenApprovals[tokenId] == spender || _operatorApprovals[tokenOwner][spender]);
    }

    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory data) private {
        if (to.code.length > 0) {
            try IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, data) returns (bytes4 retval) {
                if (retval != IERC721Receiver.onERC721Received.selector) revert NotERC721Receiver();
            } catch (bytes memory catchReason) {
                if (catchReason.length == 0) {
                    revert NotERC721Receiver();
                } else {
                    assembly {
                        revert(add(32, catchReason), mload(catchReason))
                    }
                }
            }
        }
    }

    // =========================================================================
    //                          VIEW FUNCTIONS
    // =========================================================================

    function name() external view returns (string memory) {
        return _name;
    }

    function symbol() external view returns (string memory) {
        return _symbol;
    }

    function totalSupply() external view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address owner) external view override returns (uint256) {
        if (owner == address(0)) revert ZeroAddress();
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) external view override returns (address) {
        return _ownerOf(tokenId);
    }

    function getApproved(uint256 tokenId) external view override returns (address) {
        if (_owners[tokenId] == address(0)) revert NonexistentToken();
        return _tokenApprovals[tokenId];
    }

    function isApprovedForAll(address owner, address operator) external view override returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function holderCount() external view returns (uint256) {
        return _holderCount;
    }

    /// @notice Returns the metadata URI for a given token ID.
    ///         Returns the per-token override if set; otherwise falls back to baseURI + tokenId.
    function tokenURI(uint256 tokenId) external view returns (string memory) {
        if (_owners[tokenId] == address(0)) revert NonexistentToken();
        string memory override_ = _tokenURIs[tokenId];
        if (bytes(override_).length > 0) return override_;
        string memory base = _baseURI;
        return bytes(base).length > 0 ? string(abi.encodePacked(base, _toString(tokenId))) : "";
    }

    /// @dev Converts a uint256 to its ASCII string decimal representation.
    function _toString(uint256 value) private pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    // =========================================================================
    //                     ERC165 INTERFACE SUPPORT
    // =========================================================================

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC721).interfaceId || interfaceId == type(IERC721Metadata).interfaceId
            || interfaceId == type(IIntegrityToken).interfaceId || interfaceId == type(IFlaggedToken).interfaceId
            || interfaceId == type(IERC2981).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    // =========================================================================
    //                     IIntegrityToken: tokenStandard
    // =========================================================================

    function tokenStandard() external pure override returns (TokenStandard) {
        return TokenStandard.ERC721;
    }

    // =========================================================================
    //                     canTransfer (read-only check)
    // =========================================================================

    function canTransfer(address from, address to, uint256 tokenId)
        external
        view
        returns (bool allowed, string memory reason)
    {
        if (_isPaused()) return (false, "Token is paused");
        (bool valid, string memory validationReason) = _hooks.validateTransfer(from, to, tokenId);
        if (!valid) return (false, validationReason);
        return (true, "");
    }
}
