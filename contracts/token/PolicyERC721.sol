//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "../interfaces/IPolicyGoverned.sol";
import "../interfaces/IERC721Receiver.sol";
import "../engine/PolicyEngine.sol";
import "../engine/PolicyTypes.sol";
import "./PolicyTokenBase.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import "@openzeppelin/contracts/interfaces/IERC2981.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title PolicyERC721
 * @notice A canonical ERC-721 whose complete transfer policy is enumerable data
 *         held in a canonical PolicyEngine that this contract deploys itself.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE CLAIM
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *     Beyond the ERC-721 standard's own requirements — the caller must be
 *     owner or approved, the token must be owned by `from`, the recipient
 *     must be non-zero and, for safeTransferFrom, must accept the token —
 *     the ONLY conditions under which this token can block a transfer are
 *     the rules enumerated by policy().rules(). No other condition exists,
 *     and none can be added without swapDelay seconds of public notice.
 *
 * The receiver check is part of that standard-conformance set, not a
 * discretionary gate: ERC-721 REQUIRES safeTransferFrom to revert when the
 * recipient is a contract that does not implement onERC721Received. It is
 * listed explicitly because a reader auditing "only the policy can block this"
 * will otherwise find a revert that looks unaccounted for.
 *
 * See PolicyERC20 for the full statement of why the claim holds — canonical
 * entry point, canonical policy, one discretionary gate — and why there is no
 * pause().
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE UNCONDITIONAL CASE — WHY THIS MATTERS MOST FOR NFTs
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * An empty rule array means: this collection cannot block your transfer, and
 * cannot acquire the power to without public notice. Today there is no way to
 * state that about an NFT as a checkable fact. `Pausable` is one line, an
 * operator filter is a modifier, and behind a proxy the implementation can
 * gain either tomorrow — so establishing their ABSENCE means reading every path
 * of the current source and re-reading it after every upgrade.
 *
 * Here it is one array read against a published codehash, and it costs the
 * collection nothing: with no rules this contract behaves exactly like an
 * ordinary ERC-721 and is fully marketplace-compatible.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * MINT AND BURN
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * `mint` is issuer-admin gated and outside the policy — the issuer controls
 * issuance regardless, and a lockup rule would make the initial drop
 * impossible.
 *
 * `burn` is restricted to the OWNER of the token. Not the admin, and — unlike
 * ERC721Burnable — not an approved operator either: approving a marketplace to
 * sell your NFT should never be approval to destroy it. An admin able to burn
 * an arbitrary holder's token holds a confiscation lever strictly stronger than
 * the freeze this design refuses to implement.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * NO REENTRANCY GUARD, DELIBERATELY
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The receiver callback is the last step of the transfer, after every state
 * write, so reentering is indistinguishable from an ordinary subsequent
 * transfer and is safe — the same reasoning every conforming ERC-721 relies on.
 * A guard would also add a revert to the transfer path that is neither a
 * standard requirement nor a policy verdict, weakening the claim above to buy
 * nothing.
 */
contract PolicyERC721 is PolicyTokenBase {
    // =========================================================================
    //                                  EVENTS
    // =========================================================================

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    event DefaultRoyaltyUpdated(address indexed receiver, uint96 feeNumerator);

    // =========================================================================
    //                        STATE — ALL PLAIN STORAGE
    // =========================================================================

    string private _name;
    string private _symbol;
    string private _baseURI;

    uint256 private _totalSupply;

    /// @notice Count of addresses owning at least one token, for HolderCap.
    uint256 private _holderCount;

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    address private _royaltyReceiver;
    uint96 private _royaltyFeeNumerator;

    // =========================================================================
    //                               CONSTRUCTOR
    // =========================================================================

    /// @param admin        Issuer admin: may mint, set royalties, change rules.
    /// @param tokenName    ERC-721 name.
    /// @param tokenSymbol  ERC-721 symbol.
    /// @param initialBaseURI Prefix for tokenURI; the token id is appended.
    /// @param swapDelay    Seconds of notice before a rule change commits.
    /// @param initialRules The policy at launch. Empty means unconditional.
    constructor(
        address admin,
        string memory tokenName,
        string memory tokenSymbol,
        string memory initialBaseURI,
        uint256 swapDelay,
        Rule[] memory initialRules
    ) PolicyTokenBase(admin, swapDelay, initialRules) {
        _name = tokenName;
        _symbol = tokenSymbol;
        _baseURI = initialBaseURI;
    }

    // =========================================================================
    //                    ERC-721 VIEWS (non-virtual, locked)
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

    function balanceOf(address owner) external view returns (uint256) {
        if (owner == address(0)) revert ZeroAddress();
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) external view returns (address) {
        return _ownerOf(tokenId);
    }

    function getApproved(uint256 tokenId) external view returns (address) {
        if (_owners[tokenId] == address(0)) revert NonexistentToken();
        return _tokenApprovals[tokenId];
    }

    function isApprovedForAll(address owner, address operator) external view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function baseURI() external view returns (string memory) {
        return _baseURI;
    }

    /// @notice Metadata URI for a token: baseURI with the id appended.
    function tokenURI(uint256 tokenId) external view returns (string memory) {
        if (_owners[tokenId] == address(0)) revert NonexistentToken();
        string memory base = _baseURI;
        return bytes(base).length > 0 ? string(abi.encodePacked(base, _toString(tokenId))) : "";
    }

    /// @inheritdoc IPolicyGoverned
    function tokenStandard() external pure returns (TokenStandard) {
        return TokenStandard.ERC721;
    }

    /// @notice Number of addresses owning at least one token.
    function holderCount() external view returns (uint256) {
        return _holderCount;
    }

    /// @notice Whether the policy would currently allow this transfer, and why
    ///         not if it would not. Free to call; changes nothing.
    /// @dev A marketplace should call this before submitting a fill, and render
    ///      the reason instead of burning the buyer's gas on a revert.
    function canTransfer(address from, address to, uint256 tokenId)
        external
        view
        returns (bool allowed, string memory reason)
    {
        if (to == address(0)) return (false, "zero recipient");
        if (_owners[tokenId] != from) return (false, "not owned by from");
        return _policy.evaluate(_context(from, to, tokenId));
    }

    /// @notice ERC-165. Advertises IPolicyGoverned so an integrator can discover
    ///         the policy without knowing anything else about this token.
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC721).interfaceId || interfaceId == type(IERC721Metadata).interfaceId
            || interfaceId == type(IPolicyGoverned).interfaceId || interfaceId == type(IERC2981).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    // =========================================================================
    //                 ERC-721 ENTRY POINTS (non-virtual, locked)
    // =========================================================================

    function transferFrom(address from, address to, uint256 tokenId) external {
        if (!_isApprovedOrOwner(msg.sender, tokenId)) revert NotOwnerOrApproved();
        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) external {
        if (!_isApprovedOrOwner(msg.sender, tokenId)) revert NotOwnerOrApproved();
        _transfer(from, to, tokenId);
        _checkOnERC721Received(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external {
        if (!_isApprovedOrOwner(msg.sender, tokenId)) revert NotOwnerOrApproved();
        _transfer(from, to, tokenId);
        _checkOnERC721Received(from, to, tokenId, data);
    }

    function approve(address to, uint256 tokenId) external {
        address tokenOwner = _ownerOf(tokenId);
        if (msg.sender != tokenOwner && !_operatorApprovals[tokenOwner][msg.sender]) revert NotOwnerOrOperator();
        _tokenApprovals[tokenId] = to;
        emit Approval(tokenOwner, to, tokenId);
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
     *      either an ERC-721 correctness requirement or the policy verdict, and
     *      that exhaustiveness IS the product. Do not add a discretionary
     *      revert to this function — not a pause, not a role check, not an
     *      operator filter. Any such addition silently falsifies the claim in
     *      this contract's NatSpec while leaving every test green.
     */
    function _transfer(address from, address to, uint256 tokenId) private {
        // [ERC-721 correctness] Not discretionary — required by the standard.
        if (_owners[tokenId] != from) revert TokenNotOwned();
        if (to == address(0)) revert ZeroAddress();

        // [THE ONLY DISCRETIONARY GATE] `evaluate` is `view`, so this is a
        // STATICCALL: the engine cannot write storage, emit, or reenter this
        // contract in any state-changing way, to arbitrary subcall depth.
        (bool ok, string memory reason) = _policy.evaluate(_context(from, to, tokenId));
        if (!ok) revert PolicyDenied(reason);

        // [LOCKED] Ownership mutation. Nothing above this line has written
        // state, so the balances the policy saw are the pre-transfer values.
        delete _tokenApprovals[tokenId];
        _moveToken(from, to, tokenId);

        emit Transfer(from, to, tokenId);

        // [POST-TRANSFER] Lets stateful rules (MinHoldTime) record what settled.
        _policy.recordTransfer(_context(from, to, tokenId));
    }

    /// @dev A self-transfer must not touch balances: decrementing and then
    ///      incrementing the same slot is correct only by accident, and the
    ///      holder accounting below would double-count. Returning early is the
    ///      correct accounting — the caller still emits Transfer, as the
    ///      standard requires.
    function _moveToken(address from, address to, uint256 tokenId) private {
        if (from == to) return;

        uint256 fromBalance = _balances[from];
        uint256 toBalance = _balances[to];

        unchecked {
            _balances[from] = fromBalance - 1;
            _balances[to] = toBalance + 1;
        }
        _owners[tokenId] = to;

        if (toBalance == 0) ++_holderCount;
        if (fromBalance == 1) --_holderCount;
    }

    /// @dev The context the policy evaluates. ERC-721 fixes `amount` at 1 and
    ///      puts the token id in `id`; balances are token COUNTS.
    function _context(address from, address to, uint256 tokenId) private view returns (TransferContext memory) {
        return TransferContext({
            standard: TokenStandard.ERC721,
            from: from,
            to: to,
            id: tokenId,
            amount: 1,
            fromBalance: _balances[from],
            toBalance: _balances[to],
            totalSupply: _totalSupply,
            holderCount: _holderCount
        });
    }

    // =========================================================================
    //                                 SUPPLY
    // =========================================================================

    /// @notice Mint a token. Issuer-admin gated and outside the policy; see the
    ///         contract NatSpec.
    function mint(address to, uint256 tokenId) external onlyIssuerAdmin {
        if (to == address(0)) revert ZeroAddress();
        if (_owners[tokenId] != address(0)) revert TokenAlreadyMinted();

        uint256 toBalance = _balances[to];
        unchecked {
            _balances[to] = toBalance + 1;
            ++_totalSupply;
        }
        _owners[tokenId] = to;
        if (toBalance == 0) ++_holderCount;

        emit Transfer(address(0), to, tokenId);
    }

    /// @notice Destroy a token you own.
    /// @dev Owner only — deliberately not the admin, and deliberately not an
    ///      approved operator either. See the contract NatSpec.
    function burn(uint256 tokenId) external {
        address tokenOwner = _owners[tokenId];
        if (tokenOwner == address(0)) revert NonexistentToken();
        if (msg.sender != tokenOwner) revert NotOwnerOrApproved();

        delete _tokenApprovals[tokenId];
        delete _owners[tokenId];

        uint256 fromBalance = _balances[tokenOwner];
        unchecked {
            _balances[tokenOwner] = fromBalance - 1;
            --_totalSupply;
        }
        if (fromBalance == 1) --_holderCount;

        emit Transfer(tokenOwner, address(0), tokenId);
    }

    // =========================================================================
    //                            ERC-2981 ROYALTIES
    // =========================================================================

    /// @notice Set the default royalty for all tokens.
    /// @dev An issuer power that is NOT a blocking condition: royalties are
    ///      honoured by marketplaces off-chain and cannot make a transfer
    ///      revert, so this sits outside the policy without weakening the
    ///      claim. Contrast pause(), which could not.
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
    //                             INTERNAL HELPERS
    // =========================================================================

    function _ownerOf(uint256 tokenId) private view returns (address) {
        address tokenOwner = _owners[tokenId];
        if (tokenOwner == address(0)) revert NonexistentToken();
        return tokenOwner;
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) private view returns (bool) {
        address tokenOwner = _owners[tokenId];
        return spender == tokenOwner || _tokenApprovals[tokenId] == spender || _operatorApprovals[tokenOwner][spender];
    }

    /// @dev [ERC-721 correctness] The standard requires safeTransferFrom to
    ///      revert when the recipient is a contract that does not accept the
    ///      token. Bubbles the receiver's own revert data when it provides any,
    ///      so a rejecting recipient can explain itself.
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

    /// @dev uint256 to its ASCII decimal representation.
    function _toString(uint256 value) private pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            ++digits;
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
}
