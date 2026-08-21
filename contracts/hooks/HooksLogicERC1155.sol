//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./HooksAdmin.sol";
import "./HooksWrapperERC1155.sol";

/**
 * @title HooksLogicERC1155
 * @notice Abstract base a developer inherits to write custom ERC-1155 hook
 *         policy. Its constructor deploys a HooksWrapperERC1155, which in turn
 *         deploys the IntegrityERC1155 token — so deploying your logic contract
 *         is the single transaction that brings the whole chain (Logic →
 *         Wrapper → Token) into existence.
 *
 * CALL DIRECTION: the wrapper calls this contract (gated `onlyWrapper`); this
 * contract never calls back into the wrapper or the token. There is no
 * hook-initiated write path anywhere in this framework — mint/burn are
 * exclusively issuer-admin-gated on the token. See IntegrityERC1155.sol.
 *
 * EXTENSION:
 *   Every hook has an internal `virtual` counterpart. Override the `_on*`
 *   function, never the external one — the external functions carry
 *   `onlyWrapper` and are deliberately non-virtual so an override cannot remove
 *   that check.
 *
 *     Deny gates (fail-closed):
 *       _onValidateTransfer  → return (false, reason) to block a transfer
 *       _onBeforeMint        → return (false, reason) to block a mint
 *       _onBeforeBurn        → return (false, reason) to block a burn
 *
 *     Notifications (fail-open, try/catch-wrapped by the token around the
 *     entire Token → Wrapper → Logic call chain):
 *       _onBeforeTransfer, _onAfterTransfer, _onAfterMint, _onAfterBurn
 *
 *   Use _onValidateTransfer — not a revert in _onBeforeTransfer — to deny a
 *   transfer. beforeTransfer is a settle-only notification per IHooksERC20 rule 2.
 *
 * HOOK EXECUTION ORDER:
 *   TRANSFER: pause → beforeTransfer → validateTransfer → balance → afterTransfer
 *   MINT:     beforeMint → balance → afterMint
 *   BURN:     balance check → beforeBurn → balance → afterBurn
 */
abstract contract HooksLogicERC1155 is HooksAdmin {
    /// @notice The wrapper this logic contract deployed. Immutable is fine here —
    ///         unlike the wrapper and the token, this contract carries real,
    ///         per-developer custom logic and was never going to have one
    ///         universal codehash across the ecosystem.
    HooksWrapperERC1155 public immutable wrapper;

    modifier onlyWrapper() {
        require(msg.sender == address(wrapper), "Hooks: Not wrapper contract");
        _;
    }

    constructor(address _issuerAdmin, string memory baseTokenURI, string memory contractURI_) HooksAdmin(_issuerAdmin) {
        wrapper = new HooksWrapperERC1155(_issuerAdmin, baseTokenURI, contractURI_);
    }

    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 id, uint256 amount) external onlyWrapper {
        _onBeforeTransfer(from, to, id, amount);
    }

    /// @dev Settle-only notification. Do not use a revert here to signal policy —
    ///      override _onValidateTransfer instead.
    function _onBeforeTransfer(address from, address to, uint256 id, uint256 amount) internal virtual {}

    function validateTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        onlyWrapper
        returns (bool valid, string memory reason)
    {
        return _onValidateTransfer(from, to, id, amount);
    }

    /// @dev The authoritative deny gate for transfers. Return (false, reason) to block.
    function _onValidateTransfer(address from, address to, uint256 id, uint256 amount)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 id, uint256 amount) external onlyWrapper {
        _onAfterTransfer(from, to, id, amount);
    }

    function _onAfterTransfer(address from, address to, uint256 id, uint256 amount) internal virtual {}

    // =========================================================================
    //                            MINT
    // =========================================================================

    function beforeMint(address to, uint256 id, uint256 amount, bytes calldata data)
        external
        onlyWrapper
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

    function afterMint(address to, uint256 id, uint256 amount, bytes calldata data) external onlyWrapper {
        _onAfterMint(to, id, amount, data);
    }

    function _onAfterMint(address to, uint256 id, uint256 amount, bytes calldata data) internal virtual {}

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(address from, uint256 id, uint256 amount)
        external
        onlyWrapper
        returns (bool allowed, string memory reason)
    {
        return _onBeforeBurn(from, id, amount);
    }

    function _onBeforeBurn(address from, uint256 id, uint256 amount) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(address from, uint256 id, uint256 amount) external onlyWrapper {
        _onAfterBurn(from, id, amount);
    }

    function _onAfterBurn(address from, uint256 id, uint256 amount) internal virtual {}
}
