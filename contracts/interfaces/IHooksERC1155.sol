//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC1155
 * @notice The interface HooksERC1155 implements: a "restrictive external hooks"
 *         contract that deploys and governs its own new ERC-1155 token, using a
 *         locked (non-virtual) transfer/mint/burn pipeline. See IHooksERC20 for
 *         the full set of normative rules a conforming host token must follow
 *         (CALL-only invocation, fail-closed before/validate, fail-open
 *         try/catch-wrapped after, ERC-165 discovery, new-deployment-only —
 *         never a retrofit onto a pre-existing token).
 *
 * No separate batch hooks: the token's batch mint/burn/transfer entry points
 * (mintBatch, burnBatch, safeBatchTransferFrom) each loop and fire these same
 * single-item hooks once per item — there is no distinct batch code path to
 * standardize. `validateFlags`, the URI metadata hooks, and `onTransferBlocked`
 * are additional, framework-specific surface a conforming contract may expose
 * beyond this interface's minimum; they aren't part of it.
 */
interface IHooksERC1155 is IERC165 {
    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 id, uint256 amount) external;

    function validateTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason);

    /// @notice Informational only — the host MUST wrap this in try/catch.
    function afterTransfer(address from, address to, uint256 id, uint256 amount) external;

    // =========================================================================
    //                            MINT
    // =========================================================================

    /// @notice Combined settle-and-decide call. Returning `(false, reason)` MUST
    ///         block the mint.
    function beforeMint(address to, uint256 id, uint256 amount, bytes calldata data)
        external
        returns (bool allowed, string memory reason);

    function afterMint(address to, uint256 id, uint256 amount, bytes calldata data) external;

    // =========================================================================
    //                            BURN
    // =========================================================================

    /// @notice Combined settle-and-decide call. Returning `(false, reason)` MUST
    ///         block the burn.
    function beforeBurn(address from, uint256 id, uint256 amount) external returns (bool allowed, string memory reason);

    function afterBurn(address from, uint256 id, uint256 amount) external;
}
