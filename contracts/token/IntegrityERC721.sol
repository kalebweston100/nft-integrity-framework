//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "./IntegrityTokenBase.sol";
import "../hooks/HooksWrapperERC721.sol";
import "../interfaces/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import "@openzeppelin/contracts/interfaces/IERC2981.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IntegrityERC721
 * @notice The user-facing ERC-721 token contract. Users call transferFrom(),
 *         safeTransferFrom(), etc. directly on this contract. Contains ALL token
 *         storage and the full locked transfer pipeline, and delegates policy
 *         decisions to an external wrapper contract.
 *
 * INHERITS:
 *   IntegrityTokenBase — reentrancy guard, IIntegrityToken partial implementation
 *   TokenAdmin (via Base) — issuer admin, pause/unpause
 *
 * SECURITY:
 *   - Deployed exclusively by its own wrapper, via `new`, from inside that
 *     wrapper's constructor — there is no factory
 *   - transferFrom(), safeTransferFrom(), approve(), setApprovalForAll() are non-virtual
 *   - Transfer pipeline is non-overridable (this contract is not abstract)
 *   - The wrapper is called via external CALL — it cannot access token storage.
 *     There is no path in the other direction: nothing on the hooks side can
 *     ever call back into this contract. Mint and burn are exclusively
 *     issuer-admin-gated, unconditionally.
 *   - Wrapper address is read from msg.sender at construction time (the deploying
 *     contract) and stored in a plain, setter-less slot — never immutable, so this
 *     contract's own runtime bytecode stays byte-identical across every deployment
 *     regardless of which wrapper created it. See IntegrityVerifier.sol.
 *   - Standard ERC-721 transfer/approval surface is untouched, so marketplaces
 *     (e.g. OpenSea via Seaport) trade this token normally
 */
contract IntegrityERC721 is IERC721, IERC721Metadata, IERC2981, IntegrityTokenBase {
    // =========================================================================
    //                          EVENTS
    // =========================================================================

    event HookCallFailed(string hookName, bytes reason);
    event DefaultRoyaltyUpdated(address indexed receiver, uint96 feeNumerator);
    event BaseURIUpdated(string newBaseURI);
    event TokenURIUpdated(uint256 indexed tokenId, string newTokenURI);

    // =========================================================================
    //                     WRAPPER CONTRACT (plain storage, setter-less)
    // =========================================================================

    /// @notice The wrapper that deployed and governs this token. Never
    ///         address(0) — this contract only ever exists because a wrapper
    ///         called `new` on it. Deliberately not `immutable`: see contract NatSpec.
    HooksWrapperERC721 private _hooks;

    // =========================================================================
    //                     TOKEN STORAGE
    // =========================================================================

    string private _name;
    string private _symbol;
    uint256 private _totalSupply;

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => address) private _tokenApprovals;
    mapping(address => mapping(address => bool)) private _operatorApprovals;

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
        string memory initialBaseURI
    ) IntegrityTokenBase(admin, initialContractURI) {
        _hooks = HooksWrapperERC721(msg.sender);
        _name = tokenName;
        _symbol = tokenSymbol;
        _baseURI = initialBaseURI;
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

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data)
        external
        override
        whenNotPaused
        nonReentrant
    {
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

        // [HOOKS - external call] Settle-only notification, then the authoritative
        // deny gate. A hook can refuse here; it can never write token storage.
        _hooks.beforeTransfer(from, to, tokenId);
        (bool valid, string memory reason) = _hooks.validateTransfer(from, to, tokenId);
        require(valid, reason);

        // [LOCKED] Clear approvals
        delete _tokenApprovals[tokenId];

        // [LOCKED] Ownership mutation. Self-transfers are a no-op on balances, which
        // is why they are applied as a net delta rather than a decrement/increment
        // pair — the latter miscounts when from == to.
        if (from != to) {
            _balances[from] -= 1;
            _balances[to] += 1;
            _owners[tokenId] = to;
        }
        emit Transfer(from, to, tokenId);

        // [HOOKS - external call, safe] Developer's post-transfer logic
        try _hooks.afterTransfer(from, to, tokenId) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterTransfer721", failReason);
        }
    }

    // =========================================================================
    //                     ISSUER ADMIN: MINT / BURN
    // =========================================================================

    /// @notice Mint an NFT. Only callable by issuer admin. This is the ONLY way
    ///         new tokens can ever be minted — there is no hook-initiated mint path.
    /// @param to Recipient address.
    /// @param tokenId The NFT token ID to mint.
    /// @param data Arbitrary data forwarded to hooks.
    function mint(address to, uint256 tokenId, bytes calldata data)
        external
        onlyIssuerAdmin
        whenNotPaused
        nonReentrant
    {
        _mintChecks(to, tokenId);

        // [HOOKS - external call] Developer's pre-mint logic
        (bool allowed, string memory reason) = _hooks.beforeMint(to, tokenId, data);
        require(allowed, reason);

        _mintBalanceUpdate(to, tokenId);

        // [HOOKS - external call, safe] Developer's post-mint logic
        try _hooks.afterMint(to, tokenId, data) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterMint721", failReason);
        }
    }

    /// @notice Burn an NFT. Only callable by issuer admin.
    function burn(uint256 tokenId) external onlyIssuerAdmin whenNotPaused nonReentrant {
        address tokenOwner = _owners[tokenId];
        if (tokenOwner == address(0)) revert NonexistentToken();

        // [HOOKS - external call] Developer's pre-burn logic
        (bool allowed, string memory reason) = _hooks.beforeBurn(tokenId);
        require(allowed, reason);

        delete _tokenApprovals[tokenId];
        delete _tokenURIs[tokenId];
        _balances[tokenOwner] -= 1;
        delete _owners[tokenId];
        _totalSupply -= 1;
        emit Transfer(tokenOwner, address(0), tokenId);

        // [HOOKS - external call, safe] Developer's post-burn logic
        try _hooks.afterBurn(tokenId) {}
        catch (bytes memory failReason) {
            emit HookCallFailed("afterBurn721", failReason);
        }
    }

    function _mintChecks(address to, uint256 tokenId) private view {
        if (to == address(0)) revert ZeroAddress();
        if (_owners[tokenId] != address(0)) revert TokenAlreadyMinted();
    }

    function _mintBalanceUpdate(address to, uint256 tokenId) private {
        _balances[to] += 1;
        _owners[tokenId] = to;
        _totalSupply += 1;
        emit Transfer(address(0), to, tokenId);
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
    //                     METADATA: BASE URI
    // =========================================================================

    /// @notice Set the base URI for token metadata. Only callable by issuer admin.
    function setBaseURI(string calldata newBaseURI) external onlyIssuerAdmin {
        (bool allowed, string memory reason) = _hooks.beforeSetBaseURI(newBaseURI);
        require(allowed, reason);

        _baseURI = newBaseURI;
        emit BaseURIUpdated(newBaseURI);

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
        emit TokenURIUpdated(tokenId, newTokenURI);

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

    function name() external view override returns (string memory) {
        return _name;
    }

    function symbol() external view override returns (string memory) {
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

    /// @notice Returns the metadata URI for a given token ID.
    ///         Returns the per-token override if set; otherwise falls back to baseURI + tokenId.
    function tokenURI(uint256 tokenId) external view override returns (string memory) {
        if (_owners[tokenId] == address(0)) revert NonexistentToken();
        string memory override_ = _tokenURIs[tokenId];
        if (bytes(override_).length > 0) return override_;
        string memory base = _baseURI;
        return bytes(base).length > 0 ? string(abi.encodePacked(base, _toString(tokenId))) : "";
    }

    function baseURI() external view returns (string memory) {
        return _baseURI;
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
            || interfaceId == type(IIntegrityToken).interfaceId || interfaceId == type(IERC2981).interfaceId
            || interfaceId == type(IERC165).interfaceId;
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
        if (_owners[tokenId] != from) return (false, "Not owned by from");
        if (to == address(0)) return (false, "Zero recipient");
        (bool valid, string memory validationReason) = _hooks.validateTransfer(from, to, tokenId);
        if (!valid) return (false, validationReason);
        return (true, "");
    }
}
