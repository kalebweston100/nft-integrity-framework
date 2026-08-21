//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC20.sol";
import "../interfaces/IHooksERC20.sol";

/**
 * @title HooksWrapperERC20
 * @notice The canonical, un-inherited contract that sits between an
 *         IntegrityERC20 token and a developer's custom HooksLogicERC20 contract.
 *         Concrete, never subclassed — every deployment of this exact contract
 *         produces byte-identical runtime bytecode (see IntegrityVerifier.sol),
 *         the same way IntegrityERC20 itself does.
 *
 * CALL DIRECTION IS STRICTLY ONE-WAY: Token → Wrapper → Logic. This contract's
 * entire job is to relay: the token calls it (gated `onlyToken`), and every call
 * is forwarded, unmodified, to `logic` via plain external CALL — never
 * DELEGATECALL, so `logic` cannot read or write this wrapper's storage, and
 * this wrapper cannot read or write the token's. There is no path in the other
 * direction: this contract never calls anything on the token. Nothing in this
 * framework does — see IntegrityERC20.sol for why that's true unconditionally,
 * not just by convention here.
 *
 * ZERO IMMUTABLE STATE, DELIBERATELY: `token` and `logic` are plain storage,
 * each written exactly once in this constructor with no setter. That is what
 * makes `type(HooksWrapperERC20).runtimeCode` compile at all (Solidity refuses
 * the expression for any contract holding an `immutable`) — the same
 * constraint, applied one layer out from the token, verified the same way.
 *
 * DEPLOYMENT: a developer's custom logic contract (inheriting HooksLogicERC20)
 * deploys this wrapper in its own constructor; this wrapper's constructor then
 * deploys the IntegrityERC20 token. Three `new` calls, chained, one transaction:
 * Logic → Wrapper → Token.
 */
contract HooksWrapperERC20 is IHooksERC20, ERC165 {
    /// @notice The IntegrityERC20 this wrapper deployed. Plain storage, set once
    ///         from inside this constructor, no setter — see contract NatSpec.
    IntegrityERC20 public token;

    /// @notice The developer's custom logic contract. Captured from `msg.sender`
    ///         at construction — this wrapper only ever exists because a logic
    ///         contract called `new` on it, so this is unspoofable, exactly like
    ///         the token's own hooks reference. Plain storage, no setter.
    address public logic;

    modifier onlyToken() {
        require(msg.sender == address(token), "Wrapper: Not token contract");
        _;
    }

    constructor(address issuerAdmin_, string memory tokenName, string memory tokenSymbol, string memory contractURI_) {
        logic = msg.sender;
        token = new IntegrityERC20(issuerAdmin_, tokenName, tokenSymbol, contractURI_);
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
