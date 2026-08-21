//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/**
 * @title IHooksERC20
 * @notice A "restrictive external hooks" contract governing an ERC-20 token whose
 *         transfer/mint/burn pipeline is locked (non-virtual) and which routes
 *         policy decisions out to this contract by plain external CALL.
 *
 * This interface is DENY-ONLY. Every function below can block an action; none can
 * cause one. Hook-initiated minting (IHooks.sol) is a separate, narrow capability
 * outside this interface — see that file for why it isn't declared via ERC-165.
 *
 * NORMATIVE RULES FOR A CONFORMING HOST TOKEN (requirements on the caller, i.e. the
 * token contract — not enforceable by this interface alone):
 *
 *   1. The host MUST invoke the hooks contract via a plain external CALL, never
 *      DELEGATECALL. The hooks contract has its own storage; it MUST NOT be able
 *      to read or write the host's storage by construction, not by convention.
 *   2. `before*` calls MUST be able to block. For transfer, the authoritative deny
 *      gate is the separate `validateTransfer` view call; `beforeTransfer` is a
 *      settle-only notification and SHOULD NOT be used to signal policy denial.
 *      Mint and burn fold the decision into `before*` itself, which returns
 *      `(bool allowed, string reason)`. Both shapes are fail-closed.
 *   3. `after*` MUST be called inside a try/catch by the host — a bug or revert in
 *      an after-hook MUST NOT be able to brick the host (fail-open; after-hooks are
 *      informational only, and cannot deny after the fact).
 *   4. `validateTransfer` MUST be a `view` call — it can read state but cannot
 *      mutate the hooks contract's own storage, keeping the deny gate
 *      side-effect-free.
 *   5. The host's transfer/mint/burn entry points MUST be non-virtual (locked), so
 *      neither the issuer nor the hooks contract has an inheritance path to change
 *      what "transfer" means, and the host's reference to its hooks contract MUST
 *      have no setter. A mutable hooks address makes every other guarantee here
 *      revocable. This framework's reference implementation satisfies both by
 *      having the hooks contract deploy its token in its own constructor and store
 *      the result; that is one way to satisfy the rule, not the only conceivable one.
 *   6. The host MUST remain a fully conforming ERC-20. This is a strict superset:
 *      zero-value transfers MUST succeed, event emission MUST NOT be duplicated,
 *      and no hook may cause the host to deviate from ERC-20 semantics except by
 *      reverting the whole call.
 *
 * DISCOVERY, AND ITS LIMITS: a conforming hooks contract MUST return true from
 * `supportsInterface(type(IHooksERC20).interfaceId)` per ERC-165. This is a
 * good-faith declaration that makes honest integrations legible — it is NOT proof.
 * Declaring an interface is a claim any contract can make; a hostile hooks contract
 * can claim conformance it does not honour. Confirming that a deployment actually
 * behaves as specified requires verifying its bytecode — see
 * contracts/libraries/IntegrityVerifier.sol.
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
