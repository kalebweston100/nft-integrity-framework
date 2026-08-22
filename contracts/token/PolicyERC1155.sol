//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "../interfaces/IPolicyGoverned.sol";
import "../interfaces/IERC1155Receiver.sol";
import "../engine/PolicyEngine.sol";
import "../engine/PolicyTypes.sol";
import "./PolicyTokenBase.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/IERC1155MetadataURI.sol";
import "@openzeppelin/contracts/interfaces/IERC2981.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title PolicyERC1155
 * @notice A canonical ERC-1155 whose complete transfer policy is enumerable
 *         data held in a canonical PolicyEngine that this contract deploys
 *         itself.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE CLAIM
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *     Beyond the ERC-1155 standard's own requirements — the caller must be
 *     the holder or an approved operator, the balance must suffice, the
 *     recipient must be non-zero and must accept the transfer — the ONLY
 *     conditions under which this token can block a transfer are the rules
 *     enumerated by policy().rules(). No other condition exists, and none
 *     can be added without swapDelay seconds of public notice.
 *
 * See PolicyERC20 for the full statement of why the claim holds, and why there
 * is no pause().
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * BATCH SEMANTICS — DEFINED, NOT INCIDENTAL
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *     A batch transfer is exactly equivalent to the same transfers performed
 *     one at a time, in array order.
 *
 * Each item is evaluated against live state and then settled before the next is
 * evaluated, so item N sees the balances left by items 0..N-1. This is the only
 * definition that cannot be gamed: evaluating the whole batch against
 * pre-batch state would let an issuer's MaxBalance or HolderCap rule be
 * overshot by splitting a transfer across ids in one call, and the rules would
 * mean something different in a batch than out of one.
 *
 * The cost is that the policy is consulted once per item rather than once per
 * call. That is the honest price of the rules meaning what they say.
 *
 * A batch still emits exactly one TransferBatch, as EIP-1155 requires — never
 * per-item TransferSingle events, which would make indexers double-count.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * PER-ID ACCOUNTING
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * `totalSupply` and `holderCount` in the TransferContext are PER ID, matching
 * the way rules are scoped: a rule with `scoped = true` applies only to its own
 * id, so the quantities it compares against must be that id's. A MaxBalanceBps
 * rule on id 7 is a share of id 7's supply, not of the collection.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * MINT AND BURN
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * `mint`/`mintBatch` are issuer-admin gated and outside the policy.
 * `burn`/`burnBatch` destroy the caller's own balance only — never an admin
 * power, because burning from an arbitrary holder is confiscation, a strictly
 * stronger lever than the freeze this design refuses to implement.
 */
contract PolicyERC1155 is PolicyTokenBase {
    // =========================================================================
    //                                  EVENTS
    // =========================================================================

    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);
    event TransferBatch(
        address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values
    );
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);
    event URI(string value, uint256 indexed id);
    event DefaultRoyaltyUpdated(address indexed receiver, uint96 feeNumerator);

    // =========================================================================
    //                        STATE — ALL PLAIN STORAGE
    // =========================================================================

    string private _uri;

    mapping(uint256 => mapping(address => uint256)) private _balances;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    /// @notice Circulating supply per token id.
    mapping(uint256 => uint256) private _totalSupply;

    /// @notice Addresses holding a non-zero balance, per token id, for
    ///         HolderCap. Per-id because rules are scoped per-id.
    mapping(uint256 => uint256) private _holderCount;

    address private _royaltyReceiver;
    uint96 private _royaltyFeeNumerator;

    // =========================================================================
    //                               CONSTRUCTOR
    // =========================================================================

    /// @param admin        Issuer admin: may mint, set royalties, change rules.
    /// @param initialURI   Metadata URI template shared by all ids.
    /// @param swapDelay    Seconds of notice before a rule change commits.
    /// @param initialRules The policy at launch. Empty means unconditional.
    constructor(address admin, string memory initialURI, uint256 swapDelay, Rule[] memory initialRules)
        PolicyTokenBase(admin, swapDelay, initialRules)
    {
        _uri = initialURI;
    }

    // =========================================================================
    //                   ERC-1155 VIEWS (non-virtual, locked)
    // =========================================================================

    function uri(uint256) external view returns (string memory) {
        return _uri;
    }

    function balanceOf(address account, uint256 id) external view returns (uint256) {
        if (account == address(0)) revert ZeroAddress();
        return _balances[id][account];
    }

    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids)
        external
        view
        returns (uint256[] memory)
    {
        if (accounts.length != ids.length) revert LengthMismatch();
        uint256[] memory batchBalances = new uint256[](accounts.length);
        for (uint256 i; i < accounts.length; ++i) {
            batchBalances[i] = _balances[ids[i]][accounts[i]];
        }
        return batchBalances;
    }

    function isApprovedForAll(address account, address operator) external view returns (bool) {
        return _operatorApprovals[account][operator];
    }

    /// @notice Circulating supply of one token id.
    function totalSupply(uint256 id) external view returns (uint256) {
        return _totalSupply[id];
    }

    /// @notice Addresses holding a non-zero balance of one token id.
    function holderCount(uint256 id) external view returns (uint256) {
        return _holderCount[id];
    }

    /// @inheritdoc IPolicyGoverned
    function tokenStandard() external pure returns (TokenStandard) {
        return TokenStandard.ERC1155;
    }

    /// @notice Whether the policy would currently allow this transfer, and why
    ///         not if it would not. Free to call; changes nothing.
    /// @dev Single-item only. For a batch, a caller wanting a preflight should
    ///      check each item: the batch is defined as sequential singles, so a
    ///      per-item check is the faithful preview — though it cannot account
    ///      for earlier items in the same batch shifting balances.
    function canTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason)
    {
        if (to == address(0)) return (false, "zero recipient");
        if (_balances[id][from] < amount) return (false, "insufficient balance");
        return _policy.evaluate(_context(from, to, id, amount));
    }

    /// @notice ERC-165. Advertises IPolicyGoverned so an integrator can discover
    ///         the policy without knowing anything else about this token.
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC1155).interfaceId || interfaceId == type(IERC1155MetadataURI).interfaceId
            || interfaceId == type(IPolicyGoverned).interfaceId || interfaceId == type(IERC2981).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    // =========================================================================
    //                ERC-1155 ENTRY POINTS (non-virtual, locked)
    // =========================================================================

    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external {
        if (from != msg.sender && !_operatorApprovals[from][msg.sender]) revert NotOwnerOrApproved();

        _transferItem(from, to, id, amount);
        emit TransferSingle(msg.sender, from, to, id, amount);

        _checkOnERC1155Received(msg.sender, from, to, id, amount, data);
    }

    /// @dev See the contract NatSpec: this is N sequential single transfers,
    ///      each evaluated against the state the previous ones left.
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external {
        if (from != msg.sender && !_operatorApprovals[from][msg.sender]) {
            revert NotOwnerOrApproved();
        }
        if (ids.length != amounts.length) revert LengthMismatch();

        for (uint256 i; i < ids.length; ++i) {
            _transferItem(from, to, ids[i], amounts[i]);
        }

        // EIP-1155: a batch emits exactly one TransferBatch. Per-item
        // TransferSingle events are deliberately NOT emitted — emitting both
        // makes indexers double-count balances.
        emit TransferBatch(msg.sender, from, to, ids, amounts);

        _checkOnERC1155BatchReceived(msg.sender, from, to, ids, amounts, data);
    }

    function setApprovalForAll(address operator, bool approved) external {
        if (msg.sender == operator) revert SelfApproval();
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    // =========================================================================
    //                          THE TRANSFER PATH
    // =========================================================================

    /**
     * @dev THE LOAD-BEARING FUNCTION. Every `revert` reachable from here is
     *      either an ERC-1155 correctness requirement or the policy verdict,
     *      and that exhaustiveness IS the product. Do not add a discretionary
     *      revert to this function — not a pause, not a role check, not an
     *      operator filter. Any such addition silently falsifies the claim in
     *      this contract's NatSpec while leaving every test green.
     *
     *      Emits nothing: the caller owns event emission so that a batch
     *      produces one TransferBatch rather than N TransferSingle. Zero-amount
     *      transfers are permitted, per ERC-1155, and are still policy-gated.
     */
    function _transferItem(address from, address to, uint256 id, uint256 amount) private {
        // [ERC-1155 correctness] Not discretionary — required by the standard.
        if (to == address(0)) revert ZeroAddress();
        if (_balances[id][from] < amount) revert InsufficientBalance();

        // [THE ONLY DISCRETIONARY GATE] `evaluate` is `view`, so this is a
        // STATICCALL: the engine cannot write storage, emit, or reenter this
        // contract in any state-changing way, to arbitrary subcall depth.
        (bool ok, string memory reason) = _policy.evaluate(_context(from, to, id, amount));
        if (!ok) revert PolicyDenied(reason);

        // [LOCKED] Balance mutation.
        _moveBalance(from, to, id, amount);

        // [POST-TRANSFER] Lets stateful rules (MinHoldTime) record what settled.
        _policy.recordTransfer(_context(from, to, id, amount));
    }

    /// @dev The self-transfer guard is load-bearing, not an optimisation.
    ///      Without it both balances are cached from the same slot, the credit
    ///      overwrites the debit, and a self-transfer inflates the balance out
    ///      of nothing. A self-transfer moves no value and creates no holder,
    ///      so returning early is also the correct accounting.
    function _moveBalance(address from, address to, uint256 id, uint256 amount) private {
        if (from == to) return;

        uint256 fromBalance = _balances[id][from];
        uint256 toBalance = _balances[id][to];

        unchecked {
            _balances[id][from] = fromBalance - amount;
            _balances[id][to] = toBalance + amount;
        }

        if (amount > 0) {
            if (toBalance == 0) ++_holderCount[id];
            if (fromBalance == amount) --_holderCount[id];
        }
    }

    /// @dev The context the policy evaluates. `totalSupply` and `holderCount`
    ///      are PER ID — see the contract NatSpec.
    function _context(address from, address to, uint256 id, uint256 amount)
        private
        view
        returns (TransferContext memory)
    {
        return TransferContext({
            standard: TokenStandard.ERC1155,
            from: from,
            to: to,
            id: id,
            amount: amount,
            fromBalance: _balances[id][from],
            toBalance: _balances[id][to],
            totalSupply: _totalSupply[id],
            holderCount: _holderCount[id]
        });
    }

    // =========================================================================
    //                                 SUPPLY
    // =========================================================================

    /// @notice Mint tokens of an id. Issuer-admin gated and outside the policy.
    function mint(address to, uint256 id, uint256 amount) external onlyIssuerAdmin {
        if (to == address(0)) revert ZeroAddress();
        _mintItem(to, id, amount);
        emit TransferSingle(msg.sender, address(0), to, id, amount);
    }

    /// @notice Mint across several ids. Issuer-admin gated.
    function mintBatch(address to, uint256[] calldata ids, uint256[] calldata amounts) external onlyIssuerAdmin {
        if (to == address(0)) revert ZeroAddress();
        if (ids.length != amounts.length) revert LengthMismatch();

        for (uint256 i; i < ids.length; ++i) {
            _mintItem(to, ids[i], amounts[i]);
        }
        emit TransferBatch(msg.sender, address(0), to, ids, amounts);
    }

    /// @notice Destroy some of the caller's own balance.
    /// @dev No admin path to burn someone else's balance — see the contract
    ///      NatSpec.
    function burn(uint256 id, uint256 amount) external {
        _burnItem(msg.sender, id, amount);
        emit TransferSingle(msg.sender, msg.sender, address(0), id, amount);
    }

    /// @notice Destroy some of the caller's own balance across several ids.
    function burnBatch(uint256[] calldata ids, uint256[] calldata amounts) external {
        if (ids.length != amounts.length) revert LengthMismatch();

        for (uint256 i; i < ids.length; ++i) {
            _burnItem(msg.sender, ids[i], amounts[i]);
        }
        emit TransferBatch(msg.sender, msg.sender, address(0), ids, amounts);
    }

    function _mintItem(address to, uint256 id, uint256 amount) private {
        uint256 toBalance = _balances[id][to];
        _totalSupply[id] += amount;
        unchecked {
            _balances[id][to] = toBalance + amount;
        }
        if (amount > 0 && toBalance == 0) ++_holderCount[id];
    }

    function _burnItem(address from, uint256 id, uint256 amount) private {
        uint256 fromBalance = _balances[id][from];
        if (fromBalance < amount) revert InsufficientBalance();

        unchecked {
            _balances[id][from] = fromBalance - amount;
            _totalSupply[id] -= amount;
        }
        if (amount > 0 && fromBalance == amount) --_holderCount[id];
    }

    // =========================================================================
    //                            ERC-2981 ROYALTIES
    // =========================================================================

    /// @notice Set the default royalty for all ids.
    /// @dev An issuer power that is NOT a blocking condition — royalties cannot
    ///      make a transfer revert, so this sits outside the policy without
    ///      weakening the claim.
    function setDefaultRoyalty(address receiver, uint96 feeNumerator) external onlyIssuerAdmin {
        if (feeNumerator > 10_000) revert RoyaltyTooHigh();
        if (receiver == address(0)) revert ZeroAddress();
        _royaltyReceiver = receiver;
        _royaltyFeeNumerator = feeNumerator;
        emit DefaultRoyaltyUpdated(receiver, feeNumerator);
    }

    /// @notice ERC-2981 royalty query.
    function royaltyInfo(uint256, uint256 salePrice) external view returns (address receiver, uint256 royaltyAmount) {
        receiver = _royaltyReceiver;
        royaltyAmount = (salePrice * _royaltyFeeNumerator) / 10_000;
    }

    // =========================================================================
    //                          RECEIVER CHECKS
    // =========================================================================

    /// @dev [ERC-1155 correctness] The standard requires a transfer to a
    ///      contract to revert unless the recipient accepts it.
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
