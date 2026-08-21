//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC721.sol";
import "../interfaces/IHooksERC721.sol";

/**
 * @title HooksWrapperERC721
 * @notice Canonical, un-inherited relay between an IntegrityERC721 token and a
 *         developer's HooksLogicERC721 contract — every deployment produces
 *         byte-identical bytecode (see IntegrityVerifier.sol).
 *
 * Calls flow one-way, Token → Wrapper → Logic, via plain CALL (never
 * DELEGATECALL); this contract never calls the token. `token` and `logic` are
 * plain storage, set once in the constructor with no setter — zero immutable
 * state is what makes `type(HooksWrapperERC721).runtimeCode` compile at all
 * (see HooksWrapperERC20).
 */
contract HooksWrapperERC721 is IHooksERC721, ERC165 {
    /// @notice The IntegrityERC721 this wrapper deployed. Plain storage, no setter.
    IntegrityERC721 public token;

    /// @notice The developer's logic contract, captured from msg.sender at
    ///         construction (unspoofable). Plain storage, no setter.
    address public logic;

    modifier onlyToken() {
        require(msg.sender == address(token), "Wrapper: Not token contract");
        _;
    }

    constructor(
        address issuerAdmin_,
        string memory tokenName,
        string memory tokenSymbol,
        string memory contractURI_,
        string memory baseURI_
    ) {
        logic = msg.sender;
        token = new IntegrityERC721(issuerAdmin_, tokenName, tokenSymbol, contractURI_, baseURI_);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IHooksERC721).interfaceId || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 tokenId) external override onlyToken {
        IHooksERC721(logic).beforeTransfer(from, to, tokenId);
    }

    function validateTransfer(address from, address to, uint256 tokenId)
        external
        view
        override
        onlyToken
        returns (bool valid, string memory reason)
    {
        return IHooksERC721(logic).validateTransfer(from, to, tokenId);
    }

    function afterTransfer(address from, address to, uint256 tokenId) external override onlyToken {
        IHooksERC721(logic).afterTransfer(from, to, tokenId);
    }

    // =========================================================================
    //                            MINT
    // =========================================================================

    function beforeMint(address to, uint256 tokenId, bytes calldata data)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return IHooksERC721(logic).beforeMint(to, tokenId, data);
    }

    function afterMint(address to, uint256 tokenId, bytes calldata data) external override onlyToken {
        IHooksERC721(logic).afterMint(to, tokenId, data);
    }

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(uint256 tokenId) external override onlyToken returns (bool allowed, string memory reason) {
        return IHooksERC721(logic).beforeBurn(tokenId);
    }

    function afterBurn(uint256 tokenId) external override onlyToken {
        IHooksERC721(logic).afterBurn(tokenId);
    }
}
