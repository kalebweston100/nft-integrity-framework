//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../token/IntegrityERC20.sol";
import "../token/IntegrityERC721.sol";
import "../token/IntegrityERC1155.sol";
import "../hooks/HooksWrapperERC20.sol";
import "../hooks/HooksWrapperERC721.sol";
import "../hooks/HooksWrapperERC1155.sol";

/**
 * @title IntegrityVerifier
 * @notice Registry-less verification that a token — AND the wrapper governing
 *         it — run the real, unmodified framework implementation, with no
 *         published hash, no factory, no registry, and no admin key to trust.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * HOW THIS WORKS, AND WHY TOKENS/WRAPPERS HOLD NO `immutable` STATE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Solidity exposes a contract's runtime bytecode at compile time via
 * `type(C).runtimeCode` — but only for contracts with no immutable variables;
 * with immutables, each deployment's bytecode differs, and the compiler
 * rejects the expression outright (`"runtimeCode" is not available for
 * contracts containing immutable variables`).
 *
 * IntegrityERC20/721/1155 hold zero immutable state: each stores its
 * governing wrapper address in a plain slot, written once in the constructor
 * from `msg.sender` (unspoofable), no setter. EXTCODEHASH covers only code,
 * never storage, so every canonical deployment of a given token is
 * byte-identical forever, regardless of which wrapper deployed it.
 *
 * HooksWrapperERC20/721/1155 apply the identical trick one layer out — `token`
 * and `logic` are also plain storage, written once, no setter — so the
 * wrapper is just as anchor-free to verify as the token:
 *
 *     keccak256(type(IntegrityERC721).runtimeCode)      == token.codehash
 *     keccak256(type(HooksWrapperERC721).runtimeCode)   == wrapper.codehash
 *
 * A verifier derives both hashes itself at compile time — nothing is
 * published, looked up, or trusted from a third party. And the constraint
 * enforces itself: add an `immutable` to either contract and this file stops
 * compiling. The invariant can't silently rot into an unchecked convention.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT VERIFYING THE TOKEN ALONE PROVES
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * That the token runs exactly this repository's pipeline — locked entry
 * points, CALL-only invocation of its wrapper, setter-less wrapper reference —
 * and that mint/burn can only be triggered by the issuer admin. No hook can
 * ever call back into the token, so a canonical token's supply is provably
 * confined to `onlyIssuerAdmin`, regardless of what governs it.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT VERIFYING THE WRAPPER ADDS
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Verifying the token alone says nothing about whether the address governing
 * it honors the deny-only calling convention — that address could run
 * arbitrary code exposing the right selectors. Verifying that
 * `token.hooksContract()` also runs canonical HooksWrapperERC721 bytecode
 * closes that gap: it proves the governing contract forwards every call to
 * `logic` via plain CALL (never DELEGATECALL), that the deny gates match
 * IHooksERC721 exactly, and that `validateTransfer`'s `view` guarantee is
 * compiler-enforced at both hops (Wrapper → Logic is a STATICCALL because
 * both sides declare the function `view`).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT NEITHER VERIFICATION PROVES
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * That the token is safe to buy. `logic` — the developer's actual custom
 * policy contract — is deliberately not covered by any universal hash; it
 * carries per-developer state and immutables by design, so there was never
 * going to be one hash for "a logic contract" the way there is for the token
 * and wrapper. A canonical token behind a canonical wrapper can still have
 * every transfer denied by hostile logic. Verifying a SPECIFIC logic
 * implementation with `isCanonical` below still answers a narrower question —
 * "does this address run exactly what its author published for THIS logic
 * contract" — not an ecosystem-wide one.
 *
 * Verification still bottoms out in reading source; what's eliminated is
 * every additional anchor — no registry, no factory, no admin key, no
 * published hash artifact — for either the token or the wrapper.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * REPRODUCIBILITY
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Bytecode is only comparable across independent compilations if the build is
 * reproducible. A verifier MUST compile with the same settings as the
 * deployment it checks; this repo's canonical settings live in `foundry.toml`:
 * solc 0.8.34, optimizer on (200 runs), evmVersion "cancun", viaIR true, and
 * `bytecode_hash = "none"` (drops the CBOR metadata trailer that would
 * otherwise differ between machines compiling identical source).
 *
 * A settings mismatch fails CLOSED — rejecting a legitimate deployment rather
 * than accepting a malicious one — but it's a real operational hazard, so pin
 * the profile rather than relying on defaults.
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
 *         bytes32 private immutable _canonicalWrapper721;
 *         constructor() {
 *             _canonical721 = IntegrityVerifier.canonicalERC721Hash();
 *             _canonicalWrapper721 = IntegrityVerifier.canonicalWrapperERC721Hash();
 *         }
 *         function isFullyCanonical(address token, address wrapper) external view returns (bool) {
 *             return IntegrityVerifier.isCanonical(token, _canonical721)
 *                 && IntegrityVerifier.isCanonical(wrapper, _canonicalWrapper721);
 *         }
 *     }
 *
 * A verifier holding immutables is fine — only the VERIFIED contracts must be
 * immutable-free. Off-chain callers can simply `eth_call` a view function that
 * uses the helpers directly, where size and gas do not matter.
 */
library IntegrityVerifier {
    // =========================================================================
    //                     PRIMITIVE
    // =========================================================================

    /// @notice Compares an arbitrary address's runtime bytecode hash against an
    ///         expected value.
    /// @dev SAFE AGAINST UNTRUSTED TARGETS: EXTCODEHASH is read directly by the
    ///      EVM from `target`'s deployed bytecode — this never calls into
    ///      `target`, so a malicious contract can't misreport it the way it
    ///      could if you called an `isCanonical()` function defined ON the
    ///      contract you're verifying (it could just return true). That's why
    ///      verification can never be an interface the target implements — an
    ///      interface is a thing you call, and the point is to not take the
    ///      target's word for anything. As an `internal` library function this
    ///      has no deployed address of its own; it compiles into the caller,
    ///      so there's nothing extra to trust.
    ///
    ///      Note: `codehash` is 0 for nonexistent accounts/EOAs and
    ///      keccak256("") for an empty account — a zero or mistyped
    ///      `expectedCodeHash` fails permissively, so always derive it from the
    ///      helpers below rather than pasting a literal.
    function isCanonical(address target, bytes32 expectedCodeHash) internal view returns (bool) {
        return target.codehash == expectedCodeHash;
    }

    // =========================================================================
    //           COMPILE-TIME DERIVED CANONICAL HASHES — TOKENS
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
    //           COMPILE-TIME DERIVED CANONICAL HASHES — WRAPPERS
    // =========================================================================

    /// @notice The canonical runtime codehash of HooksWrapperERC20, derived at
    ///         compile time. Compiles only because it holds no immutables.
    function canonicalWrapperERC20Hash() internal pure returns (bytes32) {
        return keccak256(type(HooksWrapperERC20).runtimeCode);
    }

    /// @notice The canonical runtime codehash of HooksWrapperERC721, derived at
    ///         compile time. Compiles only because it holds no immutables.
    function canonicalWrapperERC721Hash() internal pure returns (bytes32) {
        return keccak256(type(HooksWrapperERC721).runtimeCode);
    }

    /// @notice The canonical runtime codehash of HooksWrapperERC1155, derived at
    ///         compile time. Compiles only because it holds no immutables.
    function canonicalWrapperERC1155Hash() internal pure returns (bytes32) {
        return keccak256(type(HooksWrapperERC1155).runtimeCode);
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

    function isCanonicalWrapperERC20(address target) internal view returns (bool) {
        return isCanonical(target, canonicalWrapperERC20Hash());
    }

    function isCanonicalWrapperERC721(address target) internal view returns (bool) {
        return isCanonical(target, canonicalWrapperERC721Hash());
    }

    function isCanonicalWrapperERC1155(address target) internal view returns (bool) {
        return isCanonical(target, canonicalWrapperERC1155Hash());
    }

    // =========================================================================
    //                     MUTUAL-REFERENCE (PAIRING) CHECKS
    // =========================================================================

    /// @notice Confirms a token and its wrapper genuinely reference each other.
    ///
    /// @dev The two directions are NOT equally trustworthy:
    ///        token   → wrapper : unspoofable — written once in the token's
    ///                            own constructor, from `msg.sender`, no setter.
    ///        wrapper → token   : author-controlled — any contract can declare
    ///                            a `token` address pointing at someone else's
    ///                            legitimate token.
    ///
    ///      Checking the round trip closes the spoofable direction using the
    ///      unspoofable one: a fake wrapper can claim to govern a real token,
    ///      but that token won't name it back. Needs no hash, registry, or
    ///      compiler-settings agreement, so it's worth running even where
    ///      bytecode comparison is impractical.
    ///
    ///      Both calls target contracts you may not trust, so a hostile target
    ///      can return anything it likes; `true` here means only "these two
    ///      agree", never "these two are canonical" — pair it with
    ///      isCanonicalERC*()/isCanonicalWrapperERC*() for the stronger claim.
    function isConsistentPair(address token, address wrapper) internal view returns (bool) {
        if (token == address(0) || wrapper == address(0)) return false;

        (bool okToken, bytes memory tokenRet) = token.staticcall(abi.encodeWithSignature("hooksContract()"));
        if (!okToken || tokenRet.length != 32) return false;

        (bool okWrapper, bytes memory wrapperRet) = wrapper.staticcall(abi.encodeWithSignature("token()"));
        if (!okWrapper || wrapperRet.length != 32) return false;

        return abi.decode(tokenRet, (address)) == wrapper && abi.decode(wrapperRet, (address)) == token;
    }

    /// @notice Confirms a wrapper and the logic contract behind it genuinely
    ///         reference each other — the same pattern as isConsistentPair,
    ///         one layer further out.
    ///
    /// @dev    wrapper → logic  : unspoofable, captured from `msg.sender` in
    ///                            the wrapper's own constructor, no setter.
    ///         logic   → wrapper: author-controlled — any contract can declare
    ///                            a `wrapper` address pointing at someone
    ///                            else's legitimate wrapper.
    ///
    ///         Same asymmetry, same fix: the round trip catches a logic
    ///         contract that claims a wrapper it did not actually deploy.
    function isConsistentLogicPair(address wrapper, address logic) internal view returns (bool) {
        if (wrapper == address(0) || logic == address(0)) return false;

        (bool okWrapper, bytes memory wrapperRet) = wrapper.staticcall(abi.encodeWithSignature("logic()"));
        if (!okWrapper || wrapperRet.length != 32) return false;

        (bool okLogic, bytes memory logicRet) = logic.staticcall(abi.encodeWithSignature("wrapper()"));
        if (!okLogic || logicRet.length != 32) return false;

        return abi.decode(wrapperRet, (address)) == logic && abi.decode(logicRet, (address)) == wrapper;
    }
}
