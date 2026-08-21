//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC20
 * @notice The deny/notify calling convention that governs an ERC-20 token's
 *         transfer/mint/burn pipeline. Implemented by TWO different contracts,
 *         in two different roles, in this framework's architecture:
 *
 *           HooksWrapperERC20 (canonical, un-inherited) implements this toward
 *           the TOKEN — the token calls it via plain external CALL, gated
 *           `onlyToken` on the wrapper's side.
 *
 *           HooksLogicERC20 (abstract, author-inherited) implements the same
 *           shape toward the WRAPPER — the wrapper forwards every call to it,
 *           gated `onlyWrapper` on the logic contract's side.
 *
 *         Calls flow in exactly one direction: Token → Wrapper → Logic. Nothing
 *         in this framework ever calls back from Logic or Wrapper into the
 *         token — there is no hook-initiated write path of any kind. Every
 *         function below can block or observe; none can cause a mutation on the
 *         token's own storage.
 *
 * NORMATIVE RULES FOR A CONFORMING HOST TOKEN (requirements on the caller, i.e. the
 * token contract — not enforceable by this interface alone):
 *
 *   1. The host MUST invoke the wrapper via a plain external CALL, never
 *      DELEGATECALL. The wrapper (and the logic contract behind it) has its own
 *      storage; it MUST NOT be able to read or write the host's storage by
 *      construction, not by convention.
 *   2. `before*` calls MUST be able to block. For transfer, the authoritative deny
 *      gate is the separate `validateTransfer` view call; `beforeTransfer` is a
 *      settle-only notification and SHOULD NOT be used to signal policy denial.
 *      Mint and burn fold the decision into `before*` itself, which returns
 *      `(bool allowed, string reason)`. Both shapes are fail-closed.
 *   3. `after*` MUST be called inside a try/catch by the host — a bug or revert in
 *      an after-hook MUST NOT be able to brick the host (fail-open; after-hooks are
 *      informational only, and cannot deny after the fact).
 *   4. `validateTransfer` MUST be a `view` call — it can read state but cannot
 *      mutate storage anywhere in the call chain, keeping the deny gate
 *      side-effect-free. Because the wrapper's own `validateTransfer` is `view`
 *      and calls the logic contract's `validateTransfer` (also `view`), the
 *      compiler emits a STATICCALL for that hop too — the no-mutation rule is
 *      enforced transitively, not just documented.
 *   5. The host's transfer/mint/burn entry points MUST be non-virtual (locked), so
 *      neither the issuer nor anything downstream has an inheritance path to
 *      change what "transfer" means, and the host's reference to its wrapper MUST
 *      have no setter. A mutable reference makes every other guarantee here
 *      revocable. This framework's reference implementation satisfies both by
 *      having the wrapper deploy the token in its own constructor and store the
 *      result in a plain, setter-less slot; that is one way to satisfy the rule,
 *      not the only conceivable one.
 *   6. The host MUST remain a fully conforming ERC-20. This is a strict superset:
 *      zero-value transfers MUST succeed, event emission MUST NOT be duplicated,
 *      and no hook may cause the host to deviate from ERC-20 semantics except by
 *      reverting the whole call.
 *
 * DISCOVERY, AND ITS LIMITS: a conforming wrapper MUST return true from
 * `supportsInterface(type(IHooksERC20).interfaceId)` per ERC-165. This is a
 * good-faith declaration that makes honest integrations legible — it is NOT proof.
 * Declaring an interface is a claim any contract can make; a hostile deployment
 * can claim conformance it does not honour. Confirming that a deployment actually
 * behaves as specified requires verifying its bytecode — see
 * contracts/libraries/IntegrityVerifier.sol. Because HooksWrapperERC20 is
 * canonical (no immutables, one hash for every deployment), that verification is
 * possible for the wrapper the same way it is for the token — the logic
 * contract behind it remains the one part that can only be verified by reading
 * its source.
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
