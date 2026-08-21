//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC721.sol";
import "../interfaces/IHooksERC721.sol";

/**
 * @title HooksWrapperERC721
 * @notice The canonical, un-inherited contract that sits between an
 *         IntegrityERC721 token and a developer's custom HooksLogicERC721
 *         contract. Concrete, never subclassed — every deployment of this exact
 *         contract produces byte-identical runtime bytecode (see
 *         IntegrityVerifier.sol), the same way IntegrityERC721 itself does.
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
 * `type(HooksWrapperERC721).runtimeCode` compile at all.
 *
 * DEPLOYMENT: a developer's custom logic contract (inheriting HooksLogicERC721)
 * deploys this wrapper in its own constructor; this wrapper's constructor then
 * deploys the IntegrityERC721 token. Three `new` calls, chained, one
 * transaction: Logic → Wrapper → Token.
 */
contract HooksWrapperERC721 is IHooksERC721, ERC165 {
    /// @notice The IntegrityERC721 this wrapper deployed. Plain storage, set once
    ///         from inside this constructor, no setter.
    IntegrityERC721 public token;

    /// @notice The developer's custom logic contract. Captured from `msg.sender`
    ///         at construction — unspoofable, exactly like the token's own hooks
    ///         reference. Plain storage, no setter.
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
