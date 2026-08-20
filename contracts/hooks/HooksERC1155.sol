//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../token/IntegrityERC1155.sol";

/**
 * @title HooksERC1155
 * @notice Abstract base for ERC-1155 hooks contracts. Provides the full hook
 *         framework, access control, and deploys its own token.
 *
 * DEPLOYMENT FLOW:
 *   1. Deploy MyHooks(issuerAdmin, baseTokenURI, contractURI) inheriting
 *      HooksERC1155 — its constructor deploys the IntegrityERC1155 token directly
 *      (`new IntegrityERC1155(...)`) and wires itself as governor. There is no
 *      factory and no separate initialization step: `token` is set once,
 *      synchronously, as the return value of `new`.
 *
 * EXTENSION:
 *   Override _onBeforeTransfer1155 / _onBeforeMint1155 / _onBeforeBurn1155 for custom logic.
 *   Override _onAfterMint1155 / _onAfterBurn1155 for post-mutation logic.
 *   After-hooks are wrapped in try/catch by the token — bugs won't brick the token.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer1155 → validateTransfer1155 → balance → afterTransfer1155
 *   MINT:     beforeMint1155 → validateFlags1155 → flags commit/check → balance → afterMint1155
 *   BURN:     balance check → beforeBurn1155 → balance → afterBurn1155
 */
abstract contract HooksERC1155 {
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

    // =========================================================================
    //                          TRANSFER HOOKS
    // =========================================================================

    function beforeTransfer1155(address from, address to, uint256 id, uint256 amount) external onlyToken {
        _onBeforeTransfer1155(from, to, id, amount);
    }

    function _onBeforeTransfer1155(address from, address to, uint256 id, uint256 amount) internal virtual {}

    function validateTransfer1155(address from, address to, uint256 id, uint256 amount)
        external
        view
        onlyToken
        returns (bool valid, string memory reason)
    {
        return (true, "");
    }

    function afterTransfer1155(address from, address to, uint256 id, uint256 amount) external virtual onlyToken {}

    function onTransferBlocked1155(address from, address to, uint256 id, uint256 amount, string calldata reason)
        external
        onlyToken
    {}

    // =========================================================================
    //                            MINT HOOKS
    // =========================================================================

    function beforeMint1155(address to, uint256 id, uint256 amount, bytes calldata data)
        external
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeMint1155(to, id, amount, data);
    }

    function _onBeforeMint1155(address to, uint256 id, uint256 amount, bytes calldata data)
        internal
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterMint1155(address to, uint256 id, uint256 amount, bytes calldata data) external onlyToken {
        _onAfterMint1155(to, id, amount, data);
    }

    function _onAfterMint1155(address to, uint256 id, uint256 amount, bytes calldata data) internal virtual {}

    /// @notice Called before the token commits/checks a mint's flag bitmap for an id.
    ///         Override to enforce custom flag policy. This hook can only allow/deny —
    ///         it has no access to token storage and cannot write flags itself; only the
    ///         token contract ever writes flag storage.
    function validateFlags1155(address to, uint256 id, uint256 flags)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onValidateFlags1155(to, id, flags);
    }

    function _onValidateFlags1155(address to, uint256 id, uint256 flags)
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

    function beforeBurn1155(address from, uint256 id, uint256 amount)
        external
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return _onBeforeBurn1155(from, id, amount);
    }

    function _onBeforeBurn1155(address from, uint256 id, uint256 amount)
        internal
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterBurn1155(address from, uint256 id, uint256 amount) external onlyToken {
        _onAfterBurn1155(from, id, amount);
    }

    function _onAfterBurn1155(address from, uint256 id, uint256 amount) internal virtual {}

    // =========================================================================
    //                          METADATA HOOKS
    // =========================================================================

    function beforeSetURI(string calldata newUri) external onlyToken returns (bool allowed, string memory reason) {
        return (true, "");
    }

    function afterSetURI(string calldata newUri) external onlyToken {}

    function beforeSetTokenURI1155(uint256, string calldata)
        external
        view
        onlyToken
        returns (bool allowed, string memory reason)
    {
        return (true, "");
    }

    function afterSetTokenURI1155(uint256, string calldata) external onlyToken {}
}
