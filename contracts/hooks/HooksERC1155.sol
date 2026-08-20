//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "../token/IntegrityERC1155.sol";
import "../interfaces/IHooksERC1155.sol";

/**
 * @title HooksERC1155
 * @notice Abstract base for ERC-1155 hooks contracts. Provides the full hook
 *         framework, access control, and deploys its own token. Implements
 *         IHooksERC1155 — see that interface for the normative rules this
 *         contract's calling convention follows.
 *
 * DEPLOYMENT FLOW:
 *   1. Deploy MyHooks(issuerAdmin, baseTokenURI, contractURI) inheriting
 *      HooksERC1155 — its constructor deploys the IntegrityERC1155 token directly
 *      (`new IntegrityERC1155(...)`) and wires itself as governor. There is no
 *      factory and no separate initialization step: `token` is set once,
 *      synchronously, as the return value of `new`.
 *
 * EXTENSION:
 *   Override _onBeforeTransfer / _onBeforeMint / _onBeforeBurn for custom logic.
 *   Override _onAfterMint / _onAfterBurn for post-mutation logic.
 *   After-hooks are wrapped in try/catch by the token — bugs won't brick the token.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer → validateTransfer → balance → afterTransfer
 *   MINT:     beforeMint → validateFlags → flags commit/check → balance → afterMint
 *   BURN:     balance check → beforeBurn → balance → afterBurn
 */
abstract contract HooksERC1155 is IHooksERC1155, ERC165 {
    /// @notice The IntegrityERC1155 this hooks contract deployed and governs.
    IntegrityERC1155 public immutable token;
    address public issuerAdmin;

    modifier onlyToken() {
        require(msg.sender == address(token), "Hooks: Not token contract");
        _;
    }

    modifier onlyIssuerAdmin() {
        require(msg.sender == issuerAdmin, "Hooks: Not issuer admin");
        _;
    }

    constructor(address _issuerAdmin, string memory baseTokenURI, string memory contractURI_) {
        require(_issuerAdmin != address(0), "Hooks: Zero admin address");
        issuerAdmin = _issuerAdmin;
        token = new IntegrityERC1155(_issuerAdmin, baseTokenURI, contractURI_);
    }

    function transferAdmin(address newAdmin) external onlyIssuerAdmin {
        require(newAdmin != address(0), "Hooks: Zero address");
        issuerAdmin = newAdmin;
    }

    function _mintFromHooks(address to, uint256 id, uint256 amount, uint256 flags, bytes32 metadataHash) internal {
        token.hookMint(to, id, amount, flags, metadataHash);
    }

    function _setTokenURIFromHooks(uint256 id, string memory newURI) internal {
        token.hookSetTokenURI(id, newURI);
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IHooksERC1155).interfaceId || super.supportsInterface(interfaceId);
    }

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 id, uint256 amount) external override onlyToken {
        _onBeforeTransfer(from, to, id, amount);
    }

    function _onBeforeTransfer(address from, address to, uint256 id, uint256 amount) internal virtual {}

    function validateTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        override
        onlyToken
        returns (bool valid, string memory reason)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 id, uint256 amount) external virtual override onlyToken {}

    function onTransferBlocked(address from, address to, uint256 id, uint256 amount, string calldata reason)
        external
        onlyToken
    {}

    // =========================================================================
    //                            MINT HOOKS
    // =========================================================================

    function beforeMint(address to, uint256 id, uint256 amount, bytes calldata data)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeMint(to, id, amount, data);
    }

    function _onBeforeMint(address to, uint256 id, uint256 amount, bytes calldata data)
        internal
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterMint(address to, uint256 id, uint256 amount, bytes calldata data) external override onlyToken {
        _onAfterMint(to, id, amount, data);
    }

    function _onAfterMint(address to, uint256 id, uint256 amount, bytes calldata data) internal virtual {}

    /// @notice Called before the token commits/checks a mint's flag bitmap for an id.
    ///         Override to enforce custom flag policy. This hook can only allow/deny —
    ///         it has no access to token storage and cannot write flags itself; only the
    ///         token contract ever writes flag storage.
    function validateFlags(address to, uint256 id, uint256 flags)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateFlags(to, id, flags);
    }

    function _onValidateFlags(address to, uint256 id, uint256 flags)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    // =========================================================================
    //                            BURN HOOKS
    // =========================================================================

    function beforeBurn(address from, uint256 id, uint256 amount)
        external
        override
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeBurn(from, id, amount);
    }

    function _onBeforeBurn(address from, uint256 id, uint256 amount) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(address from, uint256 id, uint256 amount) external override onlyToken {
        _onAfterBurn(from, id, amount);
    }

    function _onAfterBurn(address from, uint256 id, uint256 amount) internal virtual {}

    // =========================================================================
    //                          METADATA HOOKS
    // =========================================================================

    function beforeSetURI(string calldata newUri) external onlyToken returns (bool allowed, string memory reason) {
        return (true, "");
    }

    function afterSetURI(string calldata newUri) external onlyToken {}

    function beforeSetTokenURI(uint256, string calldata)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return (true, "");
    }

    function afterSetTokenURI(uint256, string calldata) external onlyToken {}
}
