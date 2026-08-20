//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC721
 * @notice DRAFT — proposed standalone interface for a "restrictive external hooks"
 *         contract attached to an ERC-721 token. See IHooksERC20 for the full set of
 *         normative rules a conforming host token must follow (CALL-only invocation,
 *         fail-closed before/validate, fail-open try/catch-wrapped after, ERC-165
 *         discovery). Repeated in brief below; full rationale lives in the root
 *         README's "A minimal, standalone hook standard (draft)" section.
 *
 *   - Host MUST invoke via CALL, never DELEGATECALL — the hooks contract's storage
 *     is never reachable by the host, and vice versa.
 *   - `before*`/`validate*` are unprotected (fail-closed: a revert or a `false`
 *     return blocks the action). `after*` MUST be try/catch-wrapped by the host
 *     (fail-open: cannot deny or brick the host).
 *   - Host MUST expose `supportsInterface(type(IHooksERC721).interfaceId) == true`
 *     as the discovery mechanism for this hooks contract's conformance.
 *
 * OUT OF SCOPE for this base interface: on-chain trait/certification registries
 * (this framework's own `IFlaggedToken`), royalty distribution, and any
 * factory/deployment machinery. Those are additive, framework-specific choices,
 * not part of the minimal hook contract shape.
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

    function beforeMint(address to, uint256 tokenId) external;

    function validateMint(address to, uint256 tokenId) external view returns (bool allowed, string memory reason);

    function afterMint(address to, uint256 tokenId) external;

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(address from, uint256 tokenId) external;

    function validateBurn(address from, uint256 tokenId) external view returns (bool allowed, string memory reason);

    function afterBurn(address from, uint256 tokenId) external;
}
