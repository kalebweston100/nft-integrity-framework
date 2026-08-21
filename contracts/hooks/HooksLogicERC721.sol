//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./HooksAdmin.sol";
import "./HooksWrapperERC721.sol";

/**
 * @title HooksLogicERC721
 * @notice Abstract base a developer inherits to write custom ERC-721 hook policy.
 *         Its constructor deploys a HooksWrapperERC721, which in turn deploys the
 *         IntegrityERC721 token — so deploying your logic contract is the single
 *         transaction that brings the whole chain (Logic → Wrapper → Token) into
 *         existence.
 *
 * CALL DIRECTION: the wrapper calls this contract (gated `onlyWrapper`); this
 * contract never calls back into the wrapper or the token. There is no
 * hook-initiated write path anywhere in this framework — mint/burn are
 * exclusively issuer-admin-gated on the token. See IntegrityERC721.sol.
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
 *   TRANSFER: pause → beforeTransfer → validateTransfer → ownership → afterTransfer
 *   MINT:     beforeMint → ownership → afterMint
 *   BURN:     ownership check → beforeBurn → ownership → afterBurn
 */
abstract contract HooksLogicERC721 is HooksAdmin {
    /// @notice The wrapper this logic contract deployed. Immutable is fine here —
    ///         unlike the wrapper and the token, this contract carries real,
    ///         per-developer custom logic and was never going to have one
    ///         universal codehash across the ecosystem.
    HooksWrapperERC721 public immutable wrapper;

    modifier onlyWrapper() {
        require(msg.sender == address(wrapper), "Hooks: Not wrapper contract");
        _;
    }

    constructor(
        address _issuerAdmin,
        string memory tokenName,
        string memory tokenSymbol,
        string memory contractURI_,
        string memory baseURI_
    ) HooksAdmin(_issuerAdmin) {
        wrapper = new HooksWrapperERC721(_issuerAdmin, tokenName, tokenSymbol, contractURI_, baseURI_);
    }

    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 tokenId) external onlyWrapper {
        _onBeforeTransfer(from, to, tokenId);
    }

    /// @dev Settle-only notification. Do not use a revert here to signal policy —
    ///      override _onValidateTransfer instead.
    function _onBeforeTransfer(address from, address to, uint256 tokenId) internal virtual {}

    function validateTransfer(address from, address to, uint256 tokenId)
        external
        view
        onlyWrapper
        returns (bool valid, string memory reason)
    {
        return _onValidateTransfer(from, to, tokenId);
    }

    /// @dev The authoritative deny gate for transfers. Return (false, reason) to block.
    function _onValidateTransfer(address from, address to, uint256 tokenId)
        internal
        view
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterTransfer(address from, address to, uint256 tokenId) external onlyWrapper {
        _onAfterTransfer(from, to, tokenId);
    }

    function _onAfterTransfer(address from, address to, uint256 tokenId) internal virtual {}

    // =========================================================================
    //                            MINT
    // =========================================================================

    function beforeMint(address to, uint256 tokenId, bytes calldata data)
        external
        onlyWrapper
        returns (bool allowed, string memory reason)
    {
        return _onBeforeMint(to, tokenId, data);
    }

    function _onBeforeMint(address to, uint256 tokenId, bytes calldata data)
        internal
        virtual
        returns (bool, string memory)
    {
        return (true, "");
    }

    function afterMint(address to, uint256 tokenId, bytes calldata data) external onlyWrapper {
        _onAfterMint(to, tokenId, data);
    }

    function _onAfterMint(address to, uint256 tokenId, bytes calldata data) internal virtual {}

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(uint256 tokenId) external onlyWrapper returns (bool allowed, string memory reason) {
        return _onBeforeBurn(tokenId);
    }

    function _onBeforeBurn(uint256 tokenId) internal virtual returns (bool, string memory) {
        return (true, "");
    }

    function afterBurn(uint256 tokenId) external onlyWrapper {
        _onAfterBurn(tokenId);
    }

    function _onAfterBurn(uint256 tokenId) internal virtual {}
}
