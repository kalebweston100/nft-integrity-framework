//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC1155.sol";
import "../interfaces/IHooksERC1155.sol";

/**
 * @dev The full surface a HooksLogicERC1155 must expose, used only so this file
 *      can cast `logic` to a typed interface when forwarding. Deliberately NOT
 *      `IERC165` — see HooksWrapperERC20's ILogicERC20 for why. Includes the URI
 *      metadata hooks alongside the core IHooksERC1155 shape, since the wrapper
 *      must forward those too and they aren't part of the public interface.
 */
interface ILogicERC1155 {
    function beforeTransfer(address from, address to, uint256 id, uint256 amount) external;
    function validateTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason);
    function afterTransfer(address from, address to, uint256 id, uint256 amount) external;
    function beforeMint(address to, uint256 id, uint256 amount, bytes calldata data)
        external
        returns (bool allowed, string memory reason);
    function afterMint(address to, uint256 id, uint256 amount, bytes calldata data) external;
    function beforeBurn(address from, uint256 id, uint256 amount) external returns (bool allowed, string memory reason);
    function afterBurn(address from, uint256 id, uint256 amount) external;
    function beforeSetURI(string calldata newUri) external view returns (bool allowed, string memory reason);
    function afterSetURI(string calldata newUri) external;
    function beforeSetTokenURI(uint256 id, string calldata newURI)
        external
        view
        returns (bool allowed, string memory reason);
    function afterSetTokenURI(uint256 id, string calldata newURI) external;
}

/**
 * @title HooksWrapperERC1155
 * @notice The canonical, un-inherited contract that sits between an
 *         IntegrityERC1155 token and a developer's custom HooksLogicERC1155
 *         contract. Concrete, never subclassed — every deployment of this exact
 *         contract produces byte-identical runtime bytecode (see
 *         IntegrityVerifier.sol), the same way IntegrityERC1155 itself does.
 *
 * CALL DIRECTION IS STRICTLY ONE-WAY: Token → Wrapper → Logic. This contract's
 * entire job is to relay: the token calls it (gated `onlyToken`), and every call
 * is forwarded, unmodified, to `logic` via plain external CALL — never
 * DELEGATECALL. There is no path in the other direction: this contract never
 * calls anything on the token.
 *
 * ZERO IMMUTABLE STATE, DELIBERATELY: `token` and `logic` are plain storage,
 * each written exactly once in this constructor with no setter — see
 * HooksWrapperERC20's NatSpec for why that's what makes
 * `type(HooksWrapperERC1155).runtimeCode` compile at all.
 *
 * DEPLOYMENT: a developer's custom logic contract (inheriting HooksLogicERC1155)
 * deploys this wrapper in its own constructor; this wrapper's constructor then
 * deploys the IntegrityERC1155 token. Three `new` calls, chained, one
 * transaction: Logic → Wrapper → Token.
 */
contract HooksWrapperERC1155 is IHooksERC1155, ERC165 {
    /// @notice The IntegrityERC1155 this wrapper deployed. Plain storage, set once
    ///         from inside this constructor, no setter.
    IntegrityERC1155 public token;

    /// @notice The developer's custom logic contract. Captured from `msg.sender`
    ///         at construction — unspoofable, exactly like the token's own hooks
    ///         reference. Plain storage, no setter.
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
        ILogicERC1155(logic).beforeTransfer(from, to, id, amount);
    }

    function validateTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        override
        onlyToken
        returns (bool valid, string memory reason)
    {
        return ILogicERC1155(logic).validateTransfer(from, to, id, amount);
    }

    function afterTransfer(address from, address to, uint256 id, uint256 amount) external override onlyToken {
        ILogicERC1155(logic).afterTransfer(from, to, id, amount);
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
        return ILogicERC1155(logic).beforeMint(to, id, amount, data);
    }

    function afterMint(address to, uint256 id, uint256 amount, bytes calldata data) external override onlyToken {
        ILogicERC1155(logic).afterMint(to, id, amount, data);
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
        return ILogicERC1155(logic).beforeBurn(from, id, amount);
    }

    function afterBurn(address from, uint256 id, uint256 amount) external override onlyToken {
        ILogicERC1155(logic).afterBurn(from, id, amount);
    }

    // =========================================================================
    //                          METADATA
    // =========================================================================

    function beforeSetURI(string calldata newUri) external view onlyToken returns (bool allowed, string memory reason) {
        return ILogicERC1155(logic).beforeSetURI(newUri);
    }

    function afterSetURI(string calldata newUri) external onlyToken {
        ILogicERC1155(logic).afterSetURI(newUri);
    }

    function beforeSetTokenURI(uint256 id, string calldata newURI)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return ILogicERC1155(logic).beforeSetTokenURI(id, newURI);
    }

    function afterSetTokenURI(uint256 id, string calldata newURI) external onlyToken {
        ILogicERC1155(logic).afterSetTokenURI(id, newURI);
    }
}
