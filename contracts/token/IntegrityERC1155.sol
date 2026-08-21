//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "./IntegrityTokenBase.sol";
import "../hooks/HooksWrapperERC1155.sol";
import "../interfaces/IERC1155Receiver.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/IERC1155MetadataURI.sol";
import "@openzeppelin/contracts/interfaces/IERC2981.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IntegrityERC1155
 * @notice The user-facing ERC-1155 token contract. Users call
 *         safeTransferFrom(), safeBatchTransferFrom(), etc. directly on this
 *         contract, which holds all state and the full locked transfer
 *         pipeline, and delegates policy decisions to an external wrapper
 *         contract. Inherits IntegrityTokenBase (reentrancy guard,
 *         IIntegrityToken) and, via it, TokenAdmin (issuer admin,
 *         pause/unpause).
 *
 * SECURITY:
 *   - Deployed exclusively by its own wrapper, via `new`, from inside that
 *     wrapper's constructor
 *   - safeTransferFrom/safeBatchTransferFrom/setApprovalForAll are
 *     non-virtual; the pipeline is non-overridable (this contract is not
 *     abstract)
 *   - The wrapper is called via external CALL and cannot access token
 *     storage; nothing on the hooks side can ever call back into this
 *     contract. Mint and burn are exclusively issuer-admin-gated,
 *     unconditionally.
 *   - Wrapper address is read from msg.sender at construction and stored in a
 *     plain, setter-less slot — never immutable, so this contract's runtime
 *     bytecode stays byte-identical across every deployment. See
 *     IntegrityVerifier.sol.
 *   - Strict ERC-1155 superset: zero-amount transfers succeed and batch
 *     operations emit exactly one TransferBatch (never also per-item
 *     TransferSingle), as required.
 */
contract IntegrityERC1155 is IERC1155, IERC1155MetadataURI, IERC2981, IntegrityTokenBase {
    // =========================================================================
    //                          EVENTS
    // =========================================================================

    event HookCallFailed(string hookName, bytes reason);
    event DefaultRoyaltyUpdated(address indexed receiver, uint96 feeNumerator);

    // =========================================================================
    //                     WRAPPER CONTRACT (plain storage, setter-less)
    // =========================================================================

    /// @notice The wrapper that deployed and governs this token. Never
    ///         address(0). Deliberately not `immutable`: see contract NatSpec.
    HooksWrapperERC1155 private _hooks;

    // =========================================================================
    //                     TOKEN STORAGE
    // =========================================================================

    string private _uri;

    mapping(uint256 => mapping(address => uint256)) private _balances;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    /// @dev Per-id circulating supply.
    mapping(uint256 => uint256) private _totalSupply;

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
        _hooks = HooksWrapperERC1155(msg.sender);
        _uri = baseTokenURI;
    }

    // =========================================================================
    //                     CHAIN-OF-TRUST GETTERS
    // =========================================================================

    function hooksContract() external view returns (address) {
        return address(_hooks);
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

        _transferItem(from, to, id, amount);
        emit TransferSingle(msg.sender, from, to, id, amount);
        _fireAfterTransfer(from, to, id, amount);

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
            _transferItem(from, to, ids[i], amounts[i]);
        }

        // EIP-1155: a batch transfer emits exactly one TransferBatch. Per-item
        // TransferSingle events are deliberately NOT emitted here — emitting both
        // makes indexers double-count balances.
        emit TransferBatch(msg.sender, from, to, ids, amounts);

        for (uint256 i = 0; i < ids.length; i++) {
            _fireAfterTransfer(from, to, ids[i], amounts[i]);
        }

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

    /// @dev Validates, runs the deny gate, and mutates balances for one item.
    ///      Deliberately emits nothing — the caller owns event emission so that a
    ///      batch transfer produces one TransferBatch rather than N TransferSingle.
    ///      Zero-amount transfers are permitted, per ERC-1155.
    function _transferItem(address from, address to, uint256 id, uint256 amount) private {
        // [LOCKED] Sufficient balance check
        if (_balances[id][from] < amount) revert InsufficientBalance();
        if (to == address(0)) revert ZeroAddress();

        // [HOOKS - external call] Settle-only notification, then the authoritative
        // deny gate. A hook can refuse here; it can never write token storage.
        _hooks.beforeTransfer(from, to, id, amount);
        (bool valid, string memory reason) = _hooks.validateTransfer(from, to, id, amount);
        require(valid, reason);

        // [LOCKED] Balance mutation
        _balances[id][from] -= amount;
        _balances[id][to] += amount;
    }

    /// @dev [HOOKS - external call, safe] Post-transfer notification.
    function _fireAfterTransfer(address from, address to, uint256 id, uint256 amount) private {
        try _hooks.afterTransfer(from, to, id, amount) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterTransfer1155", failReason);
        }
    }

    // =========================================================================
    //                     ISSUER ADMIN: MINT / BURN
    // =========================================================================

    /// @notice Mint tokens of an id. Only callable by issuer admin. This is the
    ///         ONLY way supply can ever increase — there is no hook-initiated
    ///         mint path.
    function mint(address to, uint256 id, uint256 amount, bytes calldata data)
        external
        onlyIssuerAdmin
        whenNotPaused
        nonReentrant
    {
        if (to == address(0)) revert ZeroAddress();

        // [HOOKS - external call] Developer's pre-mint logic
        (bool allowed, string memory reason) = _hooks.beforeMint(to, id, amount, data);
        require(allowed, reason);

        _balances[id][to] += amount;
        _totalSupply[id] += amount;
        emit TransferSingle(msg.sender, address(0), to, id, amount);

        // [HOOKS - external call, safe] Developer's post-mint logic
        try _hooks.afterMint(to, id, amount, data) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterMint1155", failReason);
        }
    }

    /// @notice Batch mint tokens across multiple ids. Only callable by issuer admin.
    function mintBatch(address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data)
        external
        onlyIssuerAdmin
        whenNotPaused
        nonReentrant
    {
        if (to == address(0)) revert ZeroAddress();
        if (ids.length != amounts.length) revert LengthMismatch();

        // [HOOKS] Deny gate for each token class, before any mutation
        for (uint256 i = 0; i < ids.length; i++) {
            (bool allowed, string memory reason) = _hooks.beforeMint(to, ids[i], amounts[i], data);
            require(allowed, reason);
        }

        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][to] += amounts[i];
            _totalSupply[ids[i]] += amounts[i];
        }

        emit TransferBatch(msg.sender, address(0), to, ids, amounts);

        // [HOOKS, safe] Post-mint notification for each token class
        for (uint256 i = 0; i < ids.length; i++) {
            try _hooks.afterMint(to, ids[i], amounts[i], data) {}
            catch (bytes memory failReason) {
                emit HookCallFailed("afterMint1155", failReason);
            }
        }
    }

    /// @notice Burn tokens. Only callable by issuer admin.
    function burn(address from, uint256 id, uint256 amount) external onlyIssuerAdmin whenNotPaused nonReentrant {
        if (_balances[id][from] < amount) revert InsufficientBalance();

        // [HOOKS - external call] Developer's pre-burn logic
        (bool allowed, string memory reason) = _hooks.beforeBurn(from, id, amount);
        require(allowed, reason);

        _balances[id][from] -= amount;
        _totalSupply[id] -= amount;
        emit TransferSingle(msg.sender, from, address(0), id, amount);

        // [HOOKS - external call, safe] Developer's post-burn logic
        try _hooks.afterBurn(from, id, amount) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterBurn1155", failReason);
        }
    }

    /// @notice Batch burn tokens. Only callable by issuer admin.
    function burnBatch(address from, uint256[] calldata ids, uint256[] calldata amounts)
        external
        onlyIssuerAdmin
        whenNotPaused
        nonReentrant
    {
        if (ids.length != amounts.length) revert LengthMismatch();

        // [HOOKS] Deny gate for each token class, before any mutation
        for (uint256 i = 0; i < ids.length; i++) {
            (bool allowed, string memory reason) = _hooks.beforeBurn(from, ids[i], amounts[i]);
            require(allowed, reason);
        }

        for (uint256 i = 0; i < ids.length; i++) {
            if (_balances[ids[i]][from] < amounts[i]) revert InsufficientBalance();
            _balances[ids[i]][from] -= amounts[i];
            _totalSupply[ids[i]] -= amounts[i];
        }

        emit TransferBatch(msg.sender, from, address(0), ids, amounts);

        // [HOOKS, safe] Post-burn notification for each token class
        for (uint256 i = 0; i < ids.length; i++) {
            try _hooks.afterBurn(from, ids[i], amounts[i]) {}
            catch (bytes memory failReason) {
                emit HookCallFailed("afterBurn1155", failReason);
            }
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
        emit DefaultRoyaltyUpdated(receiver, feeNumerator);
    }

    /// @notice ERC-2981 royalty info query.
    function royaltyInfo(uint256, uint256 salePrice)
        external
        view
        override
        returns (address receiver, uint256 royaltyAmount)
    {
        receiver = _royaltyReceiver;
        royaltyAmount = (salePrice * _royaltyFeeNumerator) / 10000;
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

    /// @notice Returns the metadata URI template shared by all token IDs.
    function uri(uint256) external view override returns (string memory) {
        return _uri;
    }

    /// @notice Circulating supply of a single token id.
    function totalSupply(uint256 id) external view returns (uint256) {
        return _totalSupply[id];
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
        if (to == address(0)) return (false, "Zero recipient");
        (bool valid, string memory validationReason) = _hooks.validateTransfer(from, to, id, amount);
        if (!valid) return (false, validationReason);
        return (true, "");
    }

    // =========================================================================
    //                     ERC165 INTERFACE SUPPORT
    // =========================================================================

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC1155).interfaceId || interfaceId == type(IERC1155MetadataURI).interfaceId
            || interfaceId == type(IIntegrityToken).interfaceId || interfaceId == type(IERC2981).interfaceId
            || interfaceId == type(IERC165).interfaceId;
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
