//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC20.sol";
import "../interfaces/IHooksERC20.sol";

/**
 * @title HooksWrapperERC20
 * @notice Canonical, un-inherited relay between an IntegrityERC20 token and a
 *         developer's HooksLogicERC20 contract — every deployment produces
 *         byte-identical bytecode (see IntegrityVerifier.sol).
 *
 * Calls flow one-way, Token → Wrapper → Logic, via plain CALL (never
 * DELEGATECALL), so neither side can read or write the other's storage; this
 * contract never calls the token, and nothing in this framework does (see
 * IntegrityERC20.sol). `token` and `logic` are plain storage, set once in the
 * constructor with no setter — Solidity refuses to compile
 * `type(C).runtimeCode` for any contract holding an `immutable`, so this
 * zero-immutable-state discipline is what makes
 * `type(HooksWrapperERC20).runtimeCode` compile at all, the same constraint
 * applied one layer out from the token.
 */
contract HooksWrapperERC20 is IHooksERC20, ERC165 {
    /// @notice The IntegrityERC20 this wrapper deployed. Plain storage, no setter.
    IntegrityERC20 public token;

    /// @notice The developer's logic contract, captured from msg.sender at
    ///         construction (unspoofable). Plain storage, no setter.
    address public logic;

    /// @notice Salt for the CREATE2 deployment of `token`, making the token's
    ///         address a commitment to its init code — constructor included.
    /// @dev    A `constant` is inlined into bytecode and, unlike `immutable`,
    ///         does NOT break `type(C).runtimeCode`, so the zero-immutable
    ///         property that makes this wrapper hash-verifiable is unaffected.
    bytes32 internal constant TOKEN_SALT = keccak256("IntegrityToken.v1");

    modifier onlyToken() {
        require(msg.sender == address(token), "Wrapper: Not token contract");
        _;
    }

    constructor(address issuerAdmin_, string memory tokenName, string memory tokenSymbol, string memory contractURI_) {
        logic = msg.sender;
        token = new IntegrityERC20{salt: TOKEN_SALT}(issuerAdmin_, tokenName, tokenSymbol, contractURI_);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IHooksERC20).interfaceId || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 amount) external override onlyToken {
        IHooksERC20(logic).beforeTransfer(from, to, amount);
    }

    function validateTransfer(address from, address to, uint256 amount)
        external
        view
        override
        onlyToken
        returns (bool valid, string memory reason)
    {
        return IHooksERC20(logic).validateTransfer(from, to, amount);
    }

    function afterTransfer(address from, address to, uint256 amount) external override onlyToken {
        IHooksERC20(logic).afterTransfer(from, to, amount);
    }

    // =========================================================================
    //                            MINT
    // =========================================================================

    function beforeMint(address to, uint256 amount, bytes calldata data)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return IHooksERC20(logic).beforeMint(to, amount, data);
    }

    function afterMint(address to, uint256 amount, bytes calldata data) external override onlyToken {
        IHooksERC20(logic).afterMint(to, amount, data);
    }

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(address from, uint256 amount)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return IHooksERC20(logic).beforeBurn(from, amount);
    }

    function afterBurn(address from, uint256 amount) external override onlyToken {
        IHooksERC20(logic).afterBurn(from, amount);
    }
}
