//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC721
 * @notice The interface HooksERC721 implements: a "restrictive external hooks"
 *         contract that deploys and governs its own new ERC-721 token, using a
 *         locked (non-virtual) transfer/mint/burn pipeline. See IHooksERC20 for
 *         the full set of normative rules a conforming host token must follow
 *         (CALL-only invocation, fail-closed before/validate, fail-open
 *         try/catch-wrapped after, ERC-165 discovery, new-deployment-only —
 *         never a retrofit onto a pre-existing token).
 *
 * Burn takes only `tokenId`, not `from` — ownership is resolved via `ownerOf`
 * internally rather than trusted from the caller. `validateFlags`, the
 * base-URI/token-URI metadata hooks, and `onTransferBlocked` are additional,
 * framework-specific surface a conforming contract may expose beyond this
 * interface's minimum; they aren't part of it.
 */
interface IHooksERC721 is IERC165 {
    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 tokenId) external;

    function validateTransfer(address from, address to, uint256 tokenId)
        external
        view
        returns (bool allowed, string memory reason);

    /// @notice Informational only — the host MUST wrap this in try/catch.
    function afterTransfer(address from, address to, uint256 tokenId) external;

    // =========================================================================
    //                            MINT
    // =========================================================================

    /// @notice Combined settle-and-decide call. Returning `(false, reason)` MUST
    ///         block the mint.
    function beforeMint(address to, uint256 tokenId, bytes calldata data)
        external
        returns (bool allowed, string memory reason);

    function afterMint(address to, uint256 tokenId, bytes calldata data) external;

    // =========================================================================
    //                            BURN
    // =========================================================================

    /// @notice Combined settle-and-decide call. Returning `(false, reason)` MUST
    ///         block the burn.
    function beforeBurn(uint256 tokenId) external returns (bool allowed, string memory reason);

    function afterBurn(uint256 tokenId) external;
}
