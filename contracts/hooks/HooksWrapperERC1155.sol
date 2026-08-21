//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC1155.sol";
import "../interfaces/IHooksERC1155.sol";

/**
 * @title HooksWrapperERC1155
 * @notice Canonical, un-inherited relay between an IntegrityERC1155 token and a
 *         developer's HooksLogicERC1155 contract — every deployment produces
 *         byte-identical bytecode (see IntegrityVerifier.sol).
 *
 * Calls flow one-way, Token → Wrapper → Logic, via plain CALL (never
 * DELEGATECALL); this contract never calls the token. `token` and `logic` are
 * plain storage, set once in the constructor with no setter — zero immutable
 * state is what makes `type(HooksWrapperERC1155).runtimeCode` compile at all
 * (see HooksWrapperERC20).
 */
contract HooksWrapperERC1155 is IHooksERC1155, ERC165 {
    /// @notice The IntegrityERC1155 this wrapper deployed. Plain storage, no setter.
    IntegrityERC1155 public token;

    /// @notice The developer's logic contract, captured from msg.sender at
    ///         construction (unspoofable). Plain storage, no setter.
    address public logic;

    modifier onlyToken() {
        require(msg.sender == address(token), "Wrapper: Not token contract");
        _;
    }

    constructor(address issuerAdmin_, string memory baseTokenURI, string memory contractURI_) {
        logic = msg.sender;
        token = new IntegrityERC1155(issuerAdmin_, baseTokenURI, contractURI_);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IHooksERC1155).interfaceId || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 id, uint256 amount) external override onlyToken {
        IHooksERC1155(logic).beforeTransfer(from, to, id, amount);
    }

    function validateTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        override
        onlyToken
        returns (bool valid, string memory reason)
    {
        return IHooksERC1155(logic).validateTransfer(from, to, id, amount);
    }

    function afterTransfer(address from, address to, uint256 id, uint256 amount) external override onlyToken {
        IHooksERC1155(logic).afterTransfer(from, to, id, amount);
    }

    // =========================================================================
    //                            MINT
    // =========================================================================

    function beforeMint(address to, uint256 id, uint256 amount, bytes calldata data)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return IHooksERC1155(logic).beforeMint(to, id, amount, data);
    }

    function afterMint(address to, uint256 id, uint256 amount, bytes calldata data) external override onlyToken {
        IHooksERC1155(logic).afterMint(to, id, amount, data);
    }

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(address from, uint256 id, uint256 amount)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return IHooksERC1155(logic).beforeBurn(from, id, amount);
    }

    function afterBurn(address from, uint256 id, uint256 amount) external override onlyToken {
        IHooksERC1155(logic).afterBurn(from, id, amount);
    }
}
