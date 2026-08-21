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
 * HOW THIS WORKS, AND WHY THE TOKENS AND WRAPPERS HOLD NO `immutable` STATE
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
 * governing wrapper address in a plain storage slot, written once in the
 * constructor from `msg.sender` (the deploying wrapper — unspoofable) with no
 * setter anywhere. EXTCODEHASH never covers storage, only code, so every
 * canonical deployment of a given token version is byte-identical forever,
 * regardless of which wrapper deployed it.
 *
 * HooksWrapperERC20/721/1155 apply the identical trick one layer out: `token`
 * and `logic` are ALSO plain storage, written once from the constructor
 * (`token` via `new`, `logic` via `msg.sender`), with no setter. So the wrapper
 * is just as anchor-free to verify as the token — `type(HooksWrapperERC721)
 * .runtimeCode` compiles for the same reason, and gives a single hash valid
 * for every deployment of that wrapper, regardless of which logic contract or
 * token it wraps.
 *
 * A verifier that imports this source derives both expected hashes itself, at
 * compile time:
 *
 *     keccak256(type(IntegrityERC721).runtimeCode)      == token.codehash
 *     keccak256(type(HooksWrapperERC721).runtimeCode)   == wrapper.codehash
 *
 * Nothing is published, looked up, or taken on trust from a third party. And
 * the constraint enforces itself: if anyone ever adds an `immutable` to either
 * contract, this file stops compiling. The invariant cannot silently rot into
 * a convention nobody checks.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT VERIFYING THE TOKEN ALONE PROVES
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * That the token runs exactly the pipeline in this repository — locked entry
 * points, CALL-only invocation of its wrapper, setter-less wrapper reference —
 * and that mint/burn can ONLY be triggered by the issuer admin. There is no
 * hook-initiated write path anywhere in this framework: nothing on the hooks
 * side can ever call back into the token, so a canonical token's supply is
 * provably confined to `onlyIssuerAdmin`, full stop, regardless of what
 * governs it.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT VERIFYING THE WRAPPER ADDS
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Verifying the token alone says nothing about whether the address governing
 * it actually honours the deny-only calling convention it's supposed to —
 * that address could, in principle, be running arbitrary code that happens to
 * expose the right selectors. Verifying that `token.hooksContract()` is ALSO
 * running canonical HooksWrapperERC721 bytecode closes that gap: it proves the
 * governing contract forwards every call to `logic` via plain external CALL
 * (never DELEGATECALL), that the deny gates are exactly the ones documented in
 * IHooksERC721, and that `validateTransfer`'s `view` guarantee is enforced by
 * the compiler at both hops (Wrapper → Logic is a STATICCALL because both
 * sides declare the function `view`).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT NEITHER VERIFICATION PROVES
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * That the token is safe to buy. `logic` — the actual custom policy contract a
 * developer wrote — is deliberately NOT covered by any universal hash; it
 * carries per-developer state and immutables by design, so there was never
 * going to be one hash for "a logic contract" the way there is for the token
 * and the wrapper. A canonical token behind a canonical wrapper can still have
 * every transfer denied by hostile logic. Verifying a SPECIFIC logic
 * implementation with `isCanonical` below is still meaningful; it just answers
 * a narrower question — "does this address run exactly the code its author
 * published for THIS logic contract" — rather than an ecosystem-wide one.
 *
 * Verification also still bottoms out in reading source. What is eliminated is
 * every ADDITIONAL anchor: no registry, no factory, no admin key, no published
 * hash artifact — for either the token or the wrapper.
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
 * A settings mismatch fails CLOSED — a legitimate deployment is rejected rather
 * than a malicious one accepted — but it is a real operational hazard, so pin
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
    /// @dev The two directions are NOT equally trustworthy, which is the point:
    ///
    ///        token   → wrapper : unspoofable. The token writes it once, in its
    ///                            own constructor, from `msg.sender`, no setter.
    ///        wrapper → token   : author-controlled by whatever deployed the
    ///                            wrapper. Any contract can declare a `token`
    ///                            address pointing at someone else's legitimate
    ///                            token.
    ///
    ///      Checking the round trip closes the spoofable direction using the
    ///      unspoofable one: a fake wrapper can claim to govern a real token,
    ///      but that token will not name it back. Requires no hash, no registry,
    ///      and no compiler-settings agreement — so it is worth running even
    ///      where bytecode comparison is impractical.
    ///
    ///      Both calls are made against contracts you may not trust, so a hostile
    ///      target can return anything it likes; a `true` result here means only
    ///      "these two agree", never "these two are canonical". Pair it with
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
    ///         reference each other — the identical pattern as isConsistentPair,
    ///         one layer further out.
    ///
    /// @dev    wrapper → logic : unspoofable. The wrapper captures this from
    ///                           `msg.sender` in its own constructor, no setter.
    ///         logic   → wrapper : author-controlled. Any contract can declare a
    ///                           `wrapper` address pointing at someone else's
    ///                           legitimate wrapper.
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
