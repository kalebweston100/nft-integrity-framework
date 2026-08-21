//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC20
 * @notice The deny/notify calling convention governing an ERC-20 token's
 *         transfer/mint/burn pipeline. Two contracts implement this shape in
 *         two roles: HooksWrapperERC20 (canonical, un-inherited) toward the
 *         TOKEN, called via plain CALL and gated `onlyToken`; HooksLogicERC20
 *         (abstract, author-inherited) toward the WRAPPER, gated
 *         `onlyWrapper`. Calls flow one way — Token → Wrapper → Logic — with
 *         no hook-initiated write path of any kind; every function below can
 *         block or observe, none can mutate the token's storage.
 *
 * NORMATIVE RULES FOR A CONFORMING HOST TOKEN (on the caller, not enforceable
 * by this interface alone):
 *
 *   1. Invoke the wrapper via plain CALL, never DELEGATECALL — the wrapper
 *      (and its logic contract) has its own storage and must not read or
 *      write the host's, by construction.
 *   2. `before*` MUST be able to block. Transfer's authoritative deny gate is
 *      the separate `validateTransfer` view call — `beforeTransfer` is
 *      settle-only and SHOULD NOT signal denial. Mint/burn fold the decision
 *      into `before*` itself via `(bool allowed, string reason)`. Both shapes
 *      are fail-closed.
 *   3. `after*` MUST run inside a host try/catch — fail-open; a bug or revert
 *      there cannot brick the host or deny after the fact.
 *   4. `validateTransfer` MUST be `view`, keeping the deny gate
 *      side-effect-free. Since the wrapper's `validateTransfer` is `view` and
 *      calls the logic contract's (also `view`), the compiler emits a
 *      STATICCALL for that hop — enforced transitively, not just documented.
 *   5. Transfer/mint/burn entry points MUST be non-virtual (locked) and the
 *      wrapper reference MUST have no setter — a mutable reference makes
 *      every other guarantee revocable. The reference implementation
 *      satisfies both by having the wrapper deploy the token in its own
 *      constructor into a plain, setter-less slot; that's one way to do it,
 *      not the only one.
 *   6. The host MUST remain a fully conforming ERC-20 (strict superset):
 *      zero-value transfers succeed, events aren't duplicated, and no hook
 *      may cause deviation except by reverting the whole call.
 *
 * DISCOVERY, AND ITS LIMITS: a conforming wrapper MUST return true from
 * `supportsInterface(type(IHooksERC20).interfaceId)`. That's a good-faith
 * declaration, not proof — any contract can claim conformance it doesn't
 * honor. Confirming actual behavior requires verifying bytecode (see
 * IntegrityVerifier.sol); because HooksWrapperERC20 is canonical, that
 * verification is possible for the wrapper the same way it is for the token —
 * the logic contract behind it remains verifiable only by reading its source.
 */
interface IHooksERC20 is IERC165 {
    // =========================================================================
    //                          TRANSFER
    // =========================================================================

    /// @notice Settle-only notification, called before a transfer mutates state.
    ///         SHOULD NOT be used to signal a policy denial — use validateTransfer.
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
