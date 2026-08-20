//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "./IntegrityTokenBase.sol";
import "../hooks/HooksERC1155.sol";
import "../interfaces/IHooks.sol";
import "../interfaces/IFlaggedToken.sol";
import "../interfaces/IERC1155Receiver.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

/**
 * @title IntegrityERC1155
 * @notice The user-facing ERC-1155 token contract. Users call
 *         safeTransferFrom(), safeBatchTransferFrom(), etc. directly on this
 *         contract. Contains ALL token storage, the full locked transfer
 *         pipeline, the on-chain anti-fraud "flags" system, AND delegates to
 *         an external developer-deployed hooks contract.
 *
 * FLAGS (anti-fraud integrity system):
 *   Same collection-level append-only flag registry as IntegrityERC721 (see
 *   defineFlag()). Because an ERC-1155 id can be minted more than once (supply
 *   grows over time), a tokenId's flags/metadata hash are committed on the
 *   *first* mint of that id and are then permanently locked: every subsequent
 *   mint of the same id must supply the exact same flags/metadataHash or the
 *   call reverts — nobody, including the issuer, can silently change what an
 *   id's flags mean after the fact. Buyers call verifyToken()/hasFlag() with
 *   the id to trustlessly confirm what an item really carries before buying it.
 *
 * INHERITS:
 *   IntegrityTokenBase — reentrancy guard, IIntegrityToken partial implementation
 *   TokenAdmin (via Base) — issuer admin, pause/unpause
 *
 * SECURITY:
 *   - Deployed exclusively by its own hooks contract, via `new`, from inside that
 *     hooks contract's constructor
 *   - safeTransferFrom(), safeBatchTransferFrom(), setApprovalForAll() are non-virtual
 *   - Transfer pipeline is non-overridable (this contract is not abstract)
 *   - Hooks run via external call — cannot access token storage
 *   - Hooks address is read from msg.sender at construction time and stored in a
 *     plain, setter-less slot — never immutable, so this contract's own runtime
 *     bytecode stays byte-identical across every deployment. See Codehash.sol.
 */
contract IntegrityERC1155 is IERC1155, IHookMintERC1155, IFlaggedToken, IntegrityTokenBase {
    // =========================================================================
    //                          EVENTS
    // =========================================================================

    // Token-specific events (ERC1155 events inherited from IERC1155)
    // Note: holder tracking is per-tokenId, so events include tokenId
    event HolderAdded(uint256 indexed tokenId, address indexed holder, uint256 holderCount);
    event HolderRemoved(uint256 indexed tokenId, address indexed holder, uint256 holderCount);
    event TransferBlocked(address indexed from, address indexed to, uint256 amount, string reason);
    event HookCallFailed(string hookName, bytes reason);

    // =========================================================================
    //                     HOOKS CONTRACT (plain storage, setter-less)
    // =========================================================================

    /// @notice The hooks contract that deployed and governs this token. Never
    ///         address(0). Deliberately not `immutable`: see contract NatSpec.
    HooksERC1155 private _hooks;

    // =========================================================================
    //                     TOKEN STORAGE
    // =========================================================================

    string private _uri;
    mapping(uint256 => string) private _tokenURIs;

    mapping(uint256 => mapping(address => uint256)) private _balances;
    mapping(address => uint256) private _aggregateBalances; // total across all token IDs
    mapping(address => mapping(address => bool)) private _operatorApprovals;
    mapping(uint256 => uint256) private _holderCountPerToken;

    uint256 _totalSupply;

    /// @dev Guard flag to prevent circular calls when hookMint invokes afterMint1155.
    bool private _inHookMint;

    // =========================================================================
    //                     FLAGS (anti-fraud integrity system)
    // =========================================================================

    /// @dev Permanent label for each flag bit index. Append-only — see defineFlag().
    mapping(uint8 => string) private _flagLabels;
    /// @dev Bitmask of every bit index that has been given a label.
    uint256 private _definedFlagsMask;

    /// @dev Per-id committed flag bitmap. [LOCKED] written once, on the id's first mint.
    mapping(uint256 => uint256) private _flags;
    /// @dev Per-id committed metadata hash. [LOCKED] written once, on the id's first mint.
    mapping(uint256 => bytes32) private _metadataHash;
    /// @dev Whether an id's flags have been committed yet.
    mapping(uint256 => bool) private _flagsInitialized;

    // =========================================================================
    //                     ERC-2981 ROYALTY STORAGE
    // =========================================================================

    address private _royaltyReceiver;
    uint96 private _royaltyFeeNumerator;

    // =========================================================================
    //                          CONSTRUCTOR
    // =========================================================================

    constructor(address admin, string memory baseTokenURI, string memory initialContractURI)
        IntegrityTokenBase(admin, initialContractURI)
    {
        _hooks = HooksERC1155(msg.sender);
        _uri = baseTokenURI;
    }

    // =========================================================================
    //                     CHAIN-OF-TRUST GETTERS
    // =========================================================================

    function hooksContract() external view returns (address) {
        return address(_hooks);
    }

    // =========================================================================
    //              AGGREGATE BALANCE TRACKING (private helper)
    // =========================================================================

    /// @dev Updates the per-address aggregate balance across all token IDs.
    ///      Called alongside per-ID balance mutations. Use address(0) to skip.
    function _updateAggregateBalances(address from, address to, uint256 amount) private {
        if (from != address(0)) {
            _aggregateBalances[from] -= amount;
        }
        if (to != address(0)) {
            _aggregateBalances[to] += amount;
        }
    }

    // =========================================================================
    //                  ERC-1155 ENTRY POINTS (non-virtual, locked)
    // =========================================================================

    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data)
        external
        override
        nonReentrant
        whenNotPaused
    {
        if (from != msg.sender && !_operatorApprovals[from][msg.sender]) revert NotOwnerOrApproved();
        _transferPipeline1155(from, to, id, amount);
        _checkOnERC1155Received(msg.sender, from, to, id, amount, data);
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external override nonReentrant whenNotPaused {
        if (from != msg.sender && !_operatorApprovals[from][msg.sender]) {
            revert NotOwnerOrApproved();
        }
        if (ids.length != amounts.length) revert LengthMismatch();

        for (uint256 i = 0; i < ids.length; i++) {
            _transferPipeline1155(from, to, ids[i], amounts[i]);
        }

        // EIP-1155 standard: emit TransferBatch as a summary event for ecosystem tooling.
        // Individual TransferSingle events are already emitted per-item inside
        // _transferPipeline1155.
        emit TransferBatch(msg.sender, from, to, ids, amounts);

        _checkOnERC1155BatchReceived(msg.sender, from, to, ids, amounts, data);
    }

    function setApprovalForAll(address operator, bool approved) external override {
        if (msg.sender == operator) revert SelfApproval();
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    // =========================================================================
    //                   TRANSFER PIPELINE (private, locked)
    // =========================================================================

    function _transferPipeline1155(address from, address to, uint256 id, uint256 amount) private {
        // [LOCKED] Sufficient balance check
        if (amount == 0) revert ZeroAmount();
        if (_balances[id][from] < amount) revert InsufficientBalance();
        if (to == address(0)) revert ZeroAddress();

        // [HOOKS - external call] Developer's pre-transfer and validation logic
        _hooks.beforeTransfer(from, to, id, amount);
        (bool valid, string memory reason) = _hooks.validateTransfer(from, to, id, amount);
        require(valid, reason);

        // Snapshot pre-transfer state for holder tracking
        bool toWasNewHolder = (_balances[id][to] == 0);

        // [LOCKED] Balance mutation
        _balances[id][from] -= amount;
        _balances[id][to] += amount;
        _updateAggregateBalances(from, to, amount);
        emit TransferSingle(msg.sender, from, to, id, amount);

        // [LOCKED] Per-token holder tracking
        if (toWasNewHolder && _balances[id][to] > 0) {
            _holderCountPerToken[id]++;
            emit HolderAdded(id, to, _holderCountPerToken[id]);
        }
        if (_balances[id][from] == 0) {
            _holderCountPerToken[id]--;
            emit HolderRemoved(id, from, _holderCountPerToken[id]);
        }

        // [HOOKS - external call, safe] Developer's post-transfer logic
        try _hooks.afterTransfer(from, to, id, amount) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterTransfer1155", failReason);
        }
    }

    // =========================================================================
    //                     ISSUER ADMIN: MINT / BURN
    // =========================================================================

    /// @notice Mint tokens of an id, committing its flags/metadata hash on first mint.
    ///         Only callable by issuer admin.
    /// @param to Recipient address.
    /// @param id The token class ID.
    /// @param amount Token amount to mint.
    /// @param flags Bitmap of flags for this id. On the id's first mint this is committed
    ///              permanently (every bit must already be defined via defineFlag()); on
    ///              later mints of the same id it must exactly match what's already
    ///              committed, or the call reverts.
    /// @param metaHash keccak256 commitment to this id's canonical off-chain metadata.
    /// @param data Arbitrary data forwarded to hooks.
    function mint(address to, uint256 id, uint256 amount, uint256 flags, bytes32 metaHash, bytes calldata data)
        external
        onlyIssuerAdmin
        whenNotPaused
        nonReentrant
    {
        _mintLogic(msg.sender, to, id, amount, flags, metaHash, data);
        _totalSupply += amount;
    }

    /// @notice Batch mint tokens across multiple ids. Only callable by issuer admin.
    /// @param flagsArr Per-id flag bitmap, same commit-once-then-must-match rule as mint().
    /// @param metaHashArr Per-id metadata hash commitment.
    /// @param data Arbitrary data forwarded to hooks.
    function mintBatch(
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        uint256[] calldata flagsArr,
        bytes32[] calldata metaHashArr,
        bytes calldata data
    ) external onlyIssuerAdmin whenNotPaused nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (ids.length != amounts.length || ids.length != flagsArr.length || ids.length != metaHashArr.length) {
            revert LengthMismatch();
        }

        // [HOOKS] Call beforeMint + validateFlags for each token class
        for (uint256 i = 0; i < ids.length; i++) {
            (bool allowed, string memory reason) = _hooks.beforeMint(to, ids[i], amounts[i], data);
            require(allowed, reason);
            (bool flagsAllowed, string memory flagsReason) = _hooks.validateFlags(to, ids[i], flagsArr[i]);
            require(flagsAllowed, flagsReason);
        }

        for (uint256 i = 0; i < ids.length; i++) {
            // [LOCKED] Commit (or verify consistency of) this id's flags
            _commitOrCheckFlags(ids[i], flagsArr[i], metaHashArr[i]);

            bool wasNewHolder = (_balances[ids[i]][to] == 0);
            _balances[ids[i]][to] += amounts[i];
            _updateAggregateBalances(address(0), to, amounts[i]);
            _totalSupply += amounts[i];
            if (wasNewHolder && _balances[ids[i]][to] > 0) {
                _holderCountPerToken[ids[i]]++;
                emit HolderAdded(ids[i], to, _holderCountPerToken[ids[i]]);
            }
        }

        emit TransferBatch(msg.sender, address(0), to, ids, amounts);

        // [HOOKS, safe] Call afterMint for each token class
        for (uint256 i = 0; i < ids.length; i++) {
            try _hooks.afterMint(to, ids[i], amounts[i], data) {}
            catch (bytes memory failReason) {
                emit HookCallFailed("afterMint1155", failReason);
            }
        }
    }

    /// @notice Burn tokens with holder tracking. Only callable by issuer admin.
    /// @dev Flag/metadata commitments are permanent and are not affected by burns.
    function burn(address from, uint256 id, uint256 amount) external onlyIssuerAdmin whenNotPaused nonReentrant {
        if (_balances[id][from] < amount) revert InsufficientBalance();

        // [HOOKS - external call] Developer's pre-burn logic
        (bool allowed, string memory reason) = _hooks.beforeBurn(from, id, amount);
        require(allowed, reason);

        _balances[id][from] -= amount;
        _updateAggregateBalances(from, address(0), amount);
        _totalSupply -= amount;
        emit TransferSingle(msg.sender, from, address(0), id, amount);

        if (_balances[id][from] == 0) {
            _holderCountPerToken[id]--;
            emit HolderRemoved(id, from, _holderCountPerToken[id]);
        }

        // [HOOKS - external call, safe] Developer's post-burn logic
        try _hooks.afterBurn(from, id, amount) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterBurn1155", failReason);
        }
    }

    /// @notice Batch burn tokens with holder tracking. Only callable by issuer admin.
    function burnBatch(address from, uint256[] calldata ids, uint256[] calldata amounts)
        external
        onlyIssuerAdmin
        whenNotPaused
        nonReentrant
    {
        if (ids.length != amounts.length) revert LengthMismatch();

        // [HOOKS] Call beforeBurn for each token class
        for (uint256 i = 0; i < ids.length; i++) {
            (bool allowed, string memory reason) = _hooks.beforeBurn(from, ids[i], amounts[i]);
            require(allowed, reason);
        }

        for (uint256 i = 0; i < ids.length; i++) {
            if (_balances[ids[i]][from] < amounts[i]) revert InsufficientBalance();
            _balances[ids[i]][from] -= amounts[i];
            _updateAggregateBalances(from, address(0), amounts[i]);
            _totalSupply -= amounts[i];
            if (_balances[ids[i]][from] == 0) {
                _holderCountPerToken[ids[i]]--;
                emit HolderRemoved(ids[i], from, _holderCountPerToken[ids[i]]);
            }
        }

        emit TransferBatch(msg.sender, from, address(0), ids, amounts);

        // [HOOKS, safe] Call afterBurn for each token class
        for (uint256 i = 0; i < ids.length; i++) {
            try _hooks.afterBurn(from, ids[i], amounts[i]) {}
            catch (bytes memory failReason) {
                emit HookCallFailed("afterBurn1155", failReason);
            }
        }
    }

    /// @notice Set the base URI. Only callable by issuer admin.
    function setURI(string calldata newuri) external onlyIssuerAdmin {
        // [HOOKS - external call] Developer's pre-URI logic
        (bool allowed, string memory reason) = _hooks.beforeSetURI(newuri);
        require(allowed, reason);

        _uri = newuri;

        // [HOOKS - external call, safe] Developer's post-URI logic
        try _hooks.afterSetURI(newuri) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterSetURI", failReason);
        }
    }

    /// @notice Set a per-token-ID URI override. Empty string clears the override,
    ///         reverting to the base URI template for that ID. Only callable by issuer admin.
    function setTokenURI(uint256 id, string calldata newTokenURI) external onlyIssuerAdmin {
        (bool allowed, string memory reason) = _hooks.beforeSetTokenURI(id, newTokenURI);
        require(allowed, reason);

        _tokenURIs[id] = newTokenURI;

        try _hooks.afterSetTokenURI(id, newTokenURI) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterSetTokenURI1155", failReason);
        }
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

    /// @dev Mint logic with hooks (called by mint with data).
    function _mintLogic(
        address operator,
        address to,
        uint256 id,
        uint256 amount,
        uint256 flags,
        bytes32 metaHash,
        bytes calldata data
    ) private {
        if (to == address(0)) revert ZeroAddress();

        // [HOOKS - external call] Developer's pre-mint logic
        (bool allowed, string memory reason) = _hooks.beforeMint(to, id, amount, data);
        require(allowed, reason);

        // [HOOKS - external call] Developer's custom flag policy (allow/deny only)
        (bool flagsAllowed, string memory flagsReason) = _hooks.validateFlags(to, id, flags);
        require(flagsAllowed, flagsReason);

        // [LOCKED] Commit (or verify consistency of) this id's flags
        _commitOrCheckFlags(id, flags, metaHash);

        bool wasNewHolder = (_balances[id][to] == 0);
        _balances[id][to] += amount;
        _updateAggregateBalances(address(0), to, amount);
        emit TransferSingle(operator, address(0), to, id, amount);

        if (wasNewHolder && _balances[id][to] > 0) {
            _holderCountPerToken[id]++;
            emit HolderAdded(id, to, _holderCountPerToken[id]);
        }

        // [HOOKS - external call, safe] Developer's post-mint logic
        try _hooks.afterMint(to, id, amount, data) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterMint1155", failReason);
        }
    }

    /// @dev [LOCKED] Commits an id's flag bitmap/metadata hash on first mint; on every
    ///      later mint of the same id, requires an exact match instead of allowing a
    ///      rewrite. No other function ever writes these mappings.
    function _commitOrCheckFlags(uint256 id, uint256 flags, bytes32 metaHash) private {
        if (!_flagsInitialized[id]) {
            if (flags & ~_definedFlagsMask != 0) revert UndefinedFlagBits();
            _flags[id] = flags;
            _metadataHash[id] = metaHash;
            _flagsInitialized[id] = true;
            emit FlagsCommitted(id, flags, metaHash);
        } else {
            if (_flags[id] != flags || _metadataHash[id] != metaHash) revert FlagsAlreadyCommitted();
        }
    }

    // =========================================================================
    //                     HOOKS-INITIATED MINT / URI
    // =========================================================================

    /// @notice Mint tokens initiated by the hooks contract, committing/checking the id's
    ///         flags. Skips beforeMint1155 to avoid circular calls but still invokes
    ///         afterMint1155 (guarded by _inHookMint) so per-tokenId supply tracking in
    ///         HooksERC1155 stays accurate.
    /// @dev Only callable by the hooks contract.
    function hookMint(address to, uint256 id, uint256 amount, uint256 flags, bytes32 metaHash)
        external
        override
        whenNotPaused
        nonReentrant
    {
        if (msg.sender != address(_hooks)) revert NotHooksContract();
        if (to == address(0)) revert ZeroAddress();
        if (_inHookMint) revert ReentrantHookMint();

        // [LOCKED] Commit (or verify consistency of) this id's flags
        _commitOrCheckFlags(id, flags, metaHash);

        bool wasNewHolder = (_balances[id][to] == 0);
        _balances[id][to] += amount;
        _updateAggregateBalances(address(0), to, amount);
        _totalSupply += amount;
        emit TransferSingle(msg.sender, address(0), to, id, amount);

        if (wasNewHolder && _balances[id][to] > 0) {
            _holderCountPerToken[id]++;
            emit HolderAdded(id, to, _holderCountPerToken[id]);
        }

        // [HOOKS, safe] afterMint1155 for supply tracking — guarded against re-entry
        _inHookMint = true;
        try _hooks.afterMint(to, id, amount, "") {}
        catch (bytes memory reason) {
            emit HookCallFailed("afterMint1155", reason);
        }
        _inHookMint = false;
    }

    /// @notice Set a per-token-ID URI initiated by the hooks contract.
    /// @dev Only callable by the hooks contract.
    function hookSetTokenURI(uint256 id, string calldata newURI) external override whenNotPaused {
        if (msg.sender != address(_hooks)) revert NotHooksContract();
        _tokenURIs[id] = newURI;
    }

    // =========================================================================
    //                     FLAGS: COLLECTION-LEVEL REGISTRY
    // =========================================================================

    /// @notice Permanently defines the human-readable label for a flag bit index.
    ///         Append-only — reverts if that bit already has a label.
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

    function hasFlag(uint256 id, uint8 bitIndex) external view override returns (bool) {
        return (_flags[id] >> bitIndex) & 1 == 1;
    }

    function flagsOf(uint256 id) external view override returns (uint256) {
        return _flags[id];
    }

    function metadataHashOf(uint256 id) external view override returns (bytes32) {
        return _metadataHash[id];
    }

    /// @notice Whether an id's flags/metadata have been committed yet (i.e. it has been minted at least once).
    function flagsCommitted(uint256 id) external view returns (bool) {
        return _flagsInitialized[id];
    }

    /// @notice One-call anti-scam check: does `id` really carry every flag the seller
    ///         claims, and (optionally) does its metadata match what the buyer was shown?
    function verifyToken(uint256 id, uint256 requiredFlagsMask, bytes32 expectedMetadataHash)
        external
        view
        override
        returns (bool ok, uint256 actualFlags, bytes32 actualMetadataHash)
    {
        if (!_flagsInitialized[id]) return (false, 0, bytes32(0));
        actualFlags = _flags[id];
        actualMetadataHash = _metadataHash[id];
        bool flagsOk = (actualFlags & requiredFlagsMask) == requiredFlagsMask;
        bool metaOk = expectedMetadataHash == bytes32(0) || expectedMetadataHash == actualMetadataHash;
        ok = flagsOk && metaOk;
    }

    function verifyMetadata(uint256 id, bytes calldata metadata) external view override returns (bool) {
        if (!_flagsInitialized[id]) revert NonexistentToken();
        return keccak256(metadata) == _metadataHash[id];
    }

    // =========================================================================
    //                          VIEW FUNCTIONS
    // =========================================================================

    function balanceOf(address account, uint256 id) external view override returns (uint256) {
        if (account == address(0)) revert ZeroAddress();
        return _balances[id][account];
    }

    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids)
        external
        view
        override
        returns (uint256[] memory)
    {
        if (accounts.length != ids.length) revert LengthMismatch();
        uint256[] memory batchBalances = new uint256[](accounts.length);
        for (uint256 i = 0; i < accounts.length; i++) {
            batchBalances[i] = _balances[ids[i]][accounts[i]];
        }
        return batchBalances;
    }

    function isApprovedForAll(address account, address operator) external view override returns (bool) {
        return _operatorApprovals[account][operator];
    }

    /// @notice Returns the metadata URI for a given token ID.
    ///         Returns the per-token override if set; otherwise returns the base URI template.
    function uri(uint256 id) external view returns (string memory) {
        string memory override_ = _tokenURIs[id];
        return bytes(override_).length > 0 ? override_ : _uri;
    }

    function holderCountPerToken(uint256 id) external view returns (uint256) {
        return _holderCountPerToken[id];
    }

    /// @notice Returns the total balance of an account across all token IDs.
    function totalBalanceOf(address account) external view returns (uint256) {
        return _aggregateBalances[account];
    }

    // =========================================================================
    //                     IIntegrityToken: tokenStandard
    // =========================================================================

    function tokenStandard() external pure override returns (TokenStandard) {
        return TokenStandard.ERC1155;
    }

    // =========================================================================
    //                     canTransfer (read-only check)
    // =========================================================================

    function canTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason)
    {
        if (_isPaused()) return (false, "Token is paused");
        if (_balances[id][from] < amount) return (false, "Insufficient balance");
        (bool valid, string memory validationReason) = _hooks.validateTransfer(from, to, id, amount);
        if (!valid) return (false, validationReason);
        return (true, "");
    }

    // =========================================================================
    //                     ERC165 INTERFACE SUPPORT
    // =========================================================================

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC1155).interfaceId || interfaceId == type(IIntegrityToken).interfaceId
            || interfaceId == type(IFlaggedToken).interfaceId || interfaceId == 0x2a55205a // ERC-2981
            || interfaceId == 0x01ffc9a7; // ERC165
    }

    // =========================================================================
    //                   ERC-1155 RECEIVER CHECKS
    // =========================================================================

    function _checkOnERC1155Received(
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) private {
        if (to.code.length > 0) {
            try IERC1155Receiver(to).onERC1155Received(operator, from, id, amount, data) returns (bytes4 retval) {
                if (retval != IERC1155Receiver.onERC1155Received.selector) revert NotERC1155Receiver();
            } catch (bytes memory catchReason) {
                if (catchReason.length == 0) {
                    revert NotERC1155Receiver();
                } else {
                    assembly {
                        revert(add(32, catchReason), mload(catchReason))
                    }
                }
            }
        }
    }

    function _checkOnERC1155BatchReceived(
        address operator,
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes memory data
    ) private {
        if (to.code.length > 0) {
            try IERC1155Receiver(to).onERC1155BatchReceived(operator, from, ids, amounts, data) returns (
                bytes4 retval
            ) {
                if (retval != IERC1155Receiver.onERC1155BatchReceived.selector) {
                    revert NotERC1155Receiver();
                }
            } catch (bytes memory catchReason) {
                if (catchReason.length == 0) {
                    revert NotERC1155Receiver();
                } else {
                    assembly {
                        revert(add(32, catchReason), mload(catchReason))
                    }
                }
            }
        }
    }
}
