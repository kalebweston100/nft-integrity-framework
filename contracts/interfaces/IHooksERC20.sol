//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC20
 * @notice The interface HooksERC20 implements: a "restrictive external hooks"
 *         contract that deploys and governs its own new ERC-20 token, using a
 *         locked (non-virtual) transfer/mint/burn pipeline.
 *
 * THIS IS NOT A RETROFIT MECHANISM. A conforming hooks contract governs a token
 * deployed fresh, specifically for it, in the same deployment flow — never an
 * existing token that predates the hooks contract or that other code already
 * controls. See HooksERC20's constructor for how the fresh deployment is wired.
 *
 * NORMATIVE RULES FOR A CONFORMING HOST TOKEN (not enforceable by this interface
 * alone — they are requirements on the caller, i.e. the token contract):
 *
 *   1. The host MUST invoke the hooks contract via a plain external CALL, never
 *      DELEGATECALL. The hooks contract has its own storage; it MUST NOT be able
 *      to read or write the host's storage by construction, not by convention.
 *   2. `before*` calls MUST be called unprotected by the host — a revert, or a
 *      `(false, reason)` return from a function that returns one, MUST block the
 *      action (fail-closed; hooks can authoritatively deny). Transfer additionally
 *      exposes a separate `validate*` call for the same purpose; mint/burn fold
 *      the decision into `before*` itself — both are equally valid fail-closed
 *      shapes, this interface doesn't mandate one over the other.
 *   3. `after*` MUST be called inside a try/catch by the host — a bug or revert in
 *      an after-hook MUST NOT be able to brick the host (fail-open; after-hooks are
 *      informational only, and cannot deny after the fact).
 *   4. Where a separate `validate*` function exists (transfer, below) it MUST be
 *      a `view` call — it can read state but cannot mutate the hooks contract's
 *      own storage, keeping that side-effect-free.
 *   5. The host MUST be a new token deployed for this hooks contract, with its
 *      transfer/mint/burn entry points non-virtual (locked) so neither the issuer
 *      nor the hooks contract has an inheritance path to change what "transfer"
 *      means. Binding to a pre-existing, independently-deployed token is out of scope.
 *
 * DISCOVERY: a conforming hooks contract MUST return true from
 * `supportsInterface(type(IHooksERC20).interfaceId)` per ERC-165, so a host, indexer,
 * or marketplace can confirm conformance from the hooks address alone before wiring
 * it up or trusting it. Note that `onlyToken` access control means nothing but the
 * governed token can actually call these functions — the value of the interface is
 * this discovery/conformance check, not enabling arbitrary third-party calls.
 */
interface IHooksERC20 is IERC165 {
    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    /// @notice Called before a transfer settles. MUST NOT revert to signal a
    ///         policy denial — use validateTransfer for that.
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

    /// @notice Combined settle-and-decide call. Returning `(false, reason)` MUST
    ///         block the mint.
    function beforeMint(address to, uint256 amount, bytes calldata data)
        external
        returns (bool allowed, string memory reason);

    function afterMint(address to, uint256 amount, bytes calldata data) external;

    // =========================================================================
    //                            BURN
    // =========================================================================

    /// @notice Combined settle-and-decide call. Returning `(false, reason)` MUST
    ///         block the burn.
    function beforeBurn(address from, uint256 amount) external returns (bool allowed, string memory reason);

    function afterBurn(address from, uint256 amount) external;
}
