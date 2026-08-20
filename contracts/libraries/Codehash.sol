//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title Codehash
 * @notice Minimal EXTCODEHASH-based bytecode verification.
 *
 * SAFETY: this is safe to use against an UNTRUSTED `target` because it never calls
 * into `target` — EXTCODEHASH is read directly by the EVM from the target's actual
 * deployed bytecode, so a malicious contract cannot misreport it the way it could if
 * you called an `isCanonical()`-style function defined on the contract you're trying
 * to verify (that contract could simply hardcode such a function to return true).
 *
 * WHERE TO USE THIS: as an `internal` library function, it has no deployed address of
 * its own — it compiles directly into whatever contract calls it, so there is nothing
 * to trust beyond reading these few lines once. Import it directly into a marketplace
 * contract, an indexer, or any verifier; there is no reason to route the check through
 * an intermediary deployed contract (doing so would only add an address to trust,
 * never add safety — the check is exactly as strong inlined as it is anywhere else).
 *
 * WHAT MAKES A HASH WORTH COMPARING AGAINST: this framework's token contracts
 * (IntegrityERC20/721/1155) hold zero `immutable` state — the address of the hooks
 * contract that governs each token is stored in a plain (non-immutable) slot, set
 * once in the constructor with no setter. EXTCODEHASH never includes storage, only
 * code, so every canonical deployment of a given token contract produces
 * byte-identical runtime bytecode forever, regardless of which hooks contract
 * deployed it. One published hash per token contract version is enough to verify any
 * deployment of it, anywhere, by anyone — see the README's "Verifying a deployment"
 * section for the full reasoning and required compiler settings.
 *
 * Hooks contracts are the opposite by design: they carry per-developer custom logic
 * (and typically their own immutables, e.g. `issuerAdmin`), so there is no single
 * universal hash for "a hooks contract" the way there is for a token. Verifying a
 * specific hooks contract with this same function is still meaningful — it just
 * answers a narrower question ("does this address run exactly the code its author
 * published for THIS hooks implementation") rather than an ecosystem-wide one.
 */
library Codehash {
    /// @notice Checks an arbitrary address's runtime bytecode hash against an expected
    ///         value, e.g. a published canonical hash for a given token contract
    ///         version, or an author-published hash for a specific hooks implementation.
    function isCanonical(address target, bytes32 expectedCodeHash) internal view returns (bool) {
        return target.codehash == expectedCodeHash;
    }
}
