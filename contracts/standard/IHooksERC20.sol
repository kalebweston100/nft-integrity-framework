//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC20
 * @notice DRAFT — proposed standalone interface for a "restrictive external hooks"
 *         contract attached to an ERC-20 token. Not yet an EIP; see
 *         contracts/standard/README.md and the root README's "A minimal, standalone
 *         hook standard (draft)" section for the full rationale.
 *
 * NORMATIVE RULES FOR A CONFORMING HOST TOKEN (not enforceable by this interface
 * alone — they are requirements on the caller, i.e. the token contract):
 *
 *   1. The host MUST invoke the hooks contract via a plain external CALL, never
 *      DELEGATECALL. The hooks contract has its own storage; it MUST NOT be able
 *      to read or write the host's storage by construction, not by convention.
 *   2. `before*` and `validate*` MUST be called unprotected — a revert here MUST
 *      revert the host's transaction (fail-closed; hooks can authoritatively deny).
 *   3. `after*` MUST be called inside a try/catch by the host — a bug or revert in
 *      an after-hook MUST NOT be able to brick the host (fail-open; after-hooks are
 *      informational only, and cannot deny after the fact).
 *   4. `validate*` MUST be a `view` call — it can read state but cannot mutate the
 *      hooks contract's own storage, keeping the authoritative deny path side-effect-free.
 *
 * DISCOVERY: a conforming hooks contract MUST return true from
 * `supportsInterface(type(IHooksERC20).interfaceId)` per ERC-165, so a host, indexer,
 * or marketplace can confirm conformance from the hooks address alone before wiring
 * it up or trusting it.
 */
interface IHooksERC20 is IERC165 {
    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    /// @notice Called before a transfer settles. May update the hooks contract's own
    ///         state (e.g. settling a royalty accumulator). MUST NOT revert to signal
    ///         a policy denial — use validateTransfer for that.
    function beforeTransfer(address from, address to, uint256 amount) external;

    /// @notice Authoritative deny gate for a transfer. Returning `(false, reason)`
    ///         MUST block the transfer.
    function validateTransfer(address from, address to, uint256 amount)
        external
        view
        returns (bool allowed, string memory reason);

    /// @notice Informational post-transfer callback. The host MUST wrap this in
    ///         try/catch — it cannot deny or undo the transfer.
    function afterTransfer(address from, address to, uint256 amount) external;

    // =========================================================================
    //                            MINT
    // =========================================================================

    function beforeMint(address to, uint256 amount) external;

    function validateMint(address to, uint256 amount) external view returns (bool allowed, string memory reason);

    function afterMint(address to, uint256 amount) external;

    // =========================================================================
    //                            BURN
    // =========================================================================

    function beforeBurn(address from, uint256 amount) external;

    function validateBurn(address from, uint256 amount) external view returns (bool allowed, string memory reason);

    function afterBurn(address from, uint256 amount) external;
}
