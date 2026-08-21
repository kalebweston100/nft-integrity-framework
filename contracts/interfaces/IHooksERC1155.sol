//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC1155
 * @notice The deny/notify calling convention governing an ERC-1155 token's
 *         transfer/mint/burn pipeline. Implemented by HooksWrapperERC1155
 *         (canonical, called by the token) and HooksLogicERC1155
 *         (author-inherited, called by the wrapper) — see IHooksERC20 for the
 *         full architecture and normative rules (CALL-only invocation,
 *         fail-closed validate, fail-open try/catch-wrapped after, locked
 *         entry points, setter-less wrapper reference, strict-superset
 *         conformance, and ERC-165 discovery and its limits). Calls flow one
 *         direction only: Token → Wrapper → Logic, never back.
 *
 * No separate batch hooks: the token's batch mint/burn/transfer entry points
 * (mintBatch, burnBatch, safeBatchTransferFrom) each loop and fire these same
 * single-item hooks once per item — there is no distinct batch code path to
 * standardize.
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
