//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../token/IntegrityERC20.sol";
import "../token/IntegrityERC721.sol";
import "../token/IntegrityERC1155.sol";

/**
 * @title IntegrityVerifier
 * @notice Registry-less verification that a token address runs the real, unmodified
 *         IntegrityERC20/721/1155 implementation — with no published hash, no
 *         factory, no registry, and no admin key to trust.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * HOW THIS WORKS, AND WHY THE TOKENS HOLD NO `immutable` STATE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Solidity exposes a contract's runtime bytecode at COMPILE TIME as
 * `type(C).runtimeCode` — but only for contracts with no immutable variables.
 * A contract with immutables has no single runtime bytecode: the values are
 * patched into the code at construction, so each deployment differs. The
 * compiler rejects the expression outright:
 *
 *     Error (9274): "runtimeCode" is not available for contracts containing
 *                   immutable variables.
 *
 * IntegrityERC20/721/1155 therefore hold ZERO immutable state. Each stores its
 * governing hooks address in a plain storage slot, written once in the
 * constructor from `msg.sender` (the deploying hooks contract — unspoofable) with
 * no setter anywhere. EXTCODEHASH never covers storage, only code, so every
 * canonical deployment of a given token version is byte-identical forever,
 * regardless of which hooks contract deployed it.
 *
 * That combination is what makes verification anchor-free. A verifier that
 * imports this source derives the expected hash itself, at compile time:
 *
 *     keccak256(type(IntegrityERC721).runtimeCode) == token.codehash
 *
 * Nothing is published, looked up, or taken on trust from a third party.
 *
 * And the constraint enforces itself: if anyone ever adds an `immutable` to a
 * token contract, this file stops compiling. The invariant cannot silently rot
 * into a convention nobody checks.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT THIS DOES AND DOES NOT PROVE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * PROVES: the token at `target` runs exactly the pipeline in this repository —
 * locked entry points, CALL-only hooks, setter-less hooks reference.
 *
 * DOES NOT PROVE: that the token is safe to buy. The hooks contract governing it
 * holds the arbitrary logic and is deliberately NOT covered by any universal
 * hash — hooks contracts carry per-developer state and immutables by design. A
 * canonical token governed by hostile hooks can still deny every transfer, or
 * mint without limit if its hooks contract calls the token's hookMint entry
 * point (there is no ERC-165 marker for this — see IHooks.sol — so knowing
 * whether a given hooks contract mints means reading its source).
 * Verifying a specific hooks implementation with `isCanonical` below is still
 * meaningful; it just answers a narrower question — "does this address run
 * exactly the code its author published for THIS hooks contract" — rather than
 * an ecosystem-wide one.
 *
 * Verification also still bottoms out in reading source. What is eliminated is
 * every ADDITIONAL anchor: no registry, no factory, no admin key, no published
 * hash artifact.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * REPRODUCIBILITY
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Bytecode is only comparable across independent compilations if the build is
 * reproducible. A verifier MUST compile with the same settings as the deployment
 * it is checking; this repository's canonical settings live in `foundry.toml`:
 * solc 0.8.34, optimizer on with 200 runs, evmVersion "cancun", viaIR true, and
 * `bytecode_hash = "none"` (which drops the CBOR metadata trailer that would
 * otherwise differ between machines compiling identical source).
 *
 * A settings mismatch fails CLOSED — a legitimate token is rejected rather than
 * a malicious one accepted — but it is a real operational hazard, so pin the
 * profile rather than relying on defaults.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * GAS / SIZE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * `type(C).runtimeCode` embeds the entire runtime blob (tens of KB) at the call
 * site. Call the canonical*Hash() helpers ONCE, in your verifier's constructor,
 * and store the result in an `immutable` — never per-call:
 *
 *     contract MyMarketplace {
 *         bytes32 private immutable _canonical721;
 *         constructor() { _canonical721 = IntegrityVerifier.canonicalERC721Hash(); }
 *         function check(address t) external view returns (bool) {
 *             return IntegrityVerifier.isCanonical(t, _canonical721);
 *         }
 *     }
 *
 * A verifier holding immutables is fine — only the VERIFIED contract must be
 * immutable-free. Off-chain callers can simply `eth_call` a view function that
 * uses the helpers directly, where size and gas do not matter.
 */
library IntegrityVerifier {
    // =========================================================================
    //                     PRIMITIVE
    // =========================================================================

    /// @notice Compares an arbitrary address's runtime bytecode hash against an
    ///         expected value.
    /// @dev SAFE AGAINST UNTRUSTED TARGETS: this never calls into `target`.
    ///      EXTCODEHASH is read directly by the EVM from the target's deployed
    ///      bytecode, so a malicious contract cannot misreport it the way it could
    ///      if you called an `isCanonical()`-style function defined ON the contract
    ///      you are trying to verify (that contract could just return true).
    ///
    ///      This is why verification can never be expressed as an interface the
    ///      target implements: an interface is a thing you call, and the whole
    ///      point is to not take the target's word for anything.
    ///
    ///      As an `internal` library function it has no deployed address of its
    ///      own — it compiles into whatever contract uses it, so there is nothing
    ///      to trust beyond reading these few lines. Routing the check through an
    ///      intermediary deployed contract would only add an address to trust.
    ///
    ///      Note: `codehash` is 0 for accounts that do not exist and for EOAs, and
    ///      keccak256("") for an existing account with no code. Comparing against a
    ///      zero or mistyped `expectedCodeHash` therefore fails in the permissive
    ///      direction — always derive the expected value from the helpers below
    ///      rather than pasting a literal.
    function isCanonical(address target, bytes32 expectedCodeHash) internal view returns (bool) {
        return target.codehash == expectedCodeHash;
    }

    // =========================================================================
    //           COMPILE-TIME DERIVED CANONICAL HASHES (no publication)
    // =========================================================================

    /// @notice The canonical runtime codehash of IntegrityERC20, derived at compile
    ///         time. Compiles only because IntegrityERC20 holds no immutables.
    function canonicalERC20Hash() internal pure returns (bytes32) {
        return keccak256(type(IntegrityERC20).runtimeCode);
    }

    /// @notice The canonical runtime codehash of IntegrityERC721, derived at compile
    ///         time. Compiles only because IntegrityERC721 holds no immutables.
    function canonicalERC721Hash() internal pure returns (bytes32) {
        return keccak256(type(IntegrityERC721).runtimeCode);
    }

    /// @notice The canonical runtime codehash of IntegrityERC1155, derived at compile
    ///         time. Compiles only because IntegrityERC1155 holds no immutables.
    function canonicalERC1155Hash() internal pure returns (bytes32) {
        return keccak256(type(IntegrityERC1155).runtimeCode);
    }

    // =========================================================================
    //                     ONE-CALL CHECKS
    // =========================================================================

    function isCanonicalERC20(address target) internal view returns (bool) {
        return isCanonical(target, canonicalERC20Hash());
    }

    function isCanonicalERC721(address target) internal view returns (bool) {
        return isCanonical(target, canonicalERC721Hash());
    }

    function isCanonicalERC1155(address target) internal view returns (bool) {
        return isCanonical(target, canonicalERC1155Hash());
    }

    // =========================================================================
    //                     MUTUAL-REFERENCE (PAIRING) CHECK
    // =========================================================================

    /// @notice Confirms a token and a hooks contract genuinely reference each other.
    ///
    /// @dev The two directions are NOT equally trustworthy, which is the point:
    ///
    ///        token → hooks : unspoofable. The token writes it once, in its own
    ///                        constructor, from `msg.sender`, and exposes no setter.
    ///        hooks → token : author-controlled. Any contract can declare a `token`
    ///                        address pointing at someone else's legitimate token.
    ///
    ///      Checking the round trip closes the spoofable direction using the
    ///      unspoofable one: a fake hooks contract can claim to govern a real token,
    ///      but that token will not name it back. Requires no hash, no registry,
    ///      and no compiler-settings agreement — so it is worth running even where
    ///      bytecode comparison is impractical.
    ///
    ///      Both calls are made against contracts you may not trust, so a hostile
    ///      target can return anything it likes; a `true` result here means only
    ///      "these two agree", never "these two are canonical". Pair it with
    ///      isCanonicalERC*() for the stronger claim.
    function isConsistentPair(address token, address hooks) internal view returns (bool) {
        if (token == address(0) || hooks == address(0)) return false;

        (bool okToken, bytes memory tokenRet) = token.staticcall(abi.encodeWithSignature("hooksContract()"));
        if (!okToken || tokenRet.length != 32) return false;

        (bool okHooks, bytes memory hooksRet) = hooks.staticcall(abi.encodeWithSignature("token()"));
        if (!okHooks || hooksRet.length != 32) return false;

        return abi.decode(tokenRet, (address)) == hooks && abi.decode(hooksRet, (address)) == token;
    }
}
