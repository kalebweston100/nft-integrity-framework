//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC1155
 * @notice DRAFT — proposed standalone interface for a "restrictive external hooks"
 *         contract attached to an ERC-1155 token. See IHooksERC20 for the full set
 *         of normative rules a conforming host token must follow (CALL-only
 *         invocation, fail-closed before/validate, fail-open try/catch-wrapped
 *         after, ERC-165 discovery via `type(IHooksERC1155).interfaceId`).
 *
 * ERC-1155 mints/burns/transfers both single and batch, so unlike IHooksERC20/721
 * this interface carries batch variants. A host MAY support only the single-item
 * path (e.g. mint-on-deposit apps that never batch) — batch support is signalled
 * separately, see the `supportsBatch()` note below.
 */
interface IHooksERC1155 is IERC165 {
    // =========================================================================
    //                          TRANSFER (single)
    // =========================================================================

    function beforeTransfer(address from, address to, uint256 id, uint256 amount) external;

    function validateTransfer(address from, address to, uint256 id, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason);

    function afterTransfer(address from, address to, uint256 id, uint256 amount) external;

    // =========================================================================
    //                          TRANSFER (batch)
    // =========================================================================

    function beforeBatchTransfer(address from, address to, uint256[] calldata ids, uint256[] calldata amounts) external;

    function validateBatchTransfer(address from, address to, uint256[] calldata ids, uint256[] calldata amounts)
        external
        view
        returns (bool allowed, string memory reason);

    function afterBatchTransfer(address from, address to, uint256[] calldata ids, uint256[] calldata amounts) external;

    // =========================================================================
    //                            MINT
    // =========================================================================

    function beforeMint(address to, uint256 id, uint256 amount) external;

    function validateMint(address to, uint256 id, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason);

    function afterMint(address to, uint256 id, uint256 amount) external;

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(address from, uint256 id, uint256 amount) external;

    function validateBurn(address from, uint256 id, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason);

    function afterBurn(address from, uint256 id, uint256 amount) external;

    // =========================================================================
    //                          CAPABILITY FLAG
    // =========================================================================

    /// @notice Whether this hooks contract implements the batch variants above.
    ///         A host that batch-mutates MUST check this (or catch the revert) before
    ///         calling the batch functions on a hooks contract that only implements
    ///         the single-item path — the batch functions are still part of this
    ///         interface's required ABI, but a minimal implementation MAY revert from
    ///         them and report `false` here rather than implement real batch logic.
    function supportsBatch() external view returns (bool);
}
