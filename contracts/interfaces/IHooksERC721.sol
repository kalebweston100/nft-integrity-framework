//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC721
 * @notice The deny/notify calling convention governing an ERC-721 token's
 *         transfer/mint/burn pipeline. Implemented by HooksWrapperERC721
 *         (canonical, called by the token) and HooksLogicERC721 (author-inherited,
 *         called by the wrapper) — see IHooksERC20 for the full architecture and
 *         the normative rules a conforming host token must follow (CALL-only
 *         invocation, fail-closed validate, fail-open try/catch-wrapped after,
 *         locked entry points, setter-less wrapper reference, strict-superset
 *         conformance to the underlying token standard, and ERC-165 discovery
 *         together with the limits of what discovery proves). Calls flow in one
 *         direction only: Token → Wrapper → Logic, never back.
 *
 * Burn takes only `tokenId`, not `from` — ownership is resolved via `ownerOf`
 * internally rather than trusted from the caller. The base-URI / token-URI metadata
 * hooks are additional framework-specific surface a conforming contract may expose
 * beyond this interface's minimum; they are not part of it.
 */
interface IHooksERC721 is IERC165 {
    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    /// @notice Settle-only notification. SHOULD NOT be used to signal a policy
    ///         denial — use validateTransfer.
    function beforeTransfer(address from, address to, uint256 tokenId) external;

    /// @notice Authoritative deny gate. Returning `(false, reason)` MUST block.
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
