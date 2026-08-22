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
 * WHAT A CODEHASH PROVES — FUTURE BEHAVIOUR, NEVER HISTORY
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * A canonical codehash proves the token runs exactly this repository's
 * pipeline — locked entry points, CALL-only invocation of its wrapper — and
 * therefore that EVERY STATE TRANSITION FROM NOW ON obeys those rules. No hook
 * can call back into the token, and mint/burn are unconditionally
 * `onlyIssuerAdmin`.
 *
 * It proves NOTHING about the state you are looking at when you check. The
 * constructor that wrote the initial storage lives in the CREATION code, which
 * EXTCODEHASH never covers — so a canonical codehash is compatible with a
 * fabricated starting balance, a fabricated supply, and a `hooksContract()`
 * that never deployed the token. See test/CodehashLimits.t.sol, which
 * demonstrates precisely this, and the PROVENANCE section below, which closes
 * it.
 *
 * The rule this yields, and the one to design against:
 *
 *     Guarantees about FUTURE behaviour can ride on a codehash.
 *     Guarantees about HISTORY need CREATE2 provenance as well.
 *
 * "Supply is confined to onlyIssuerAdmin" is a claim about history. It holds
 * only when isProvenanceVerified*() holds too — use isFullyVerified*().
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
    //                     PROVENANCE (CREATE2) CHECKS
    // =========================================================================
    //
    // WHY THESE EXIST — THE LIMIT OF EXTCODEHASH
    //
    // A runtime codehash constrains FUTURE behaviour and nothing else. It
    // cannot speak to how a contract's current state arose, because the code
    // that wrote the initial state — the constructor — lives in the CREATION
    // code and is never covered by EXTCODEHASH.
    //
    // Init code and runtime code are independent byte strings: CREATE stores
    // whatever the init code RETURNs. So an attacker can write an arbitrary
    // constructor that fabricates storage and then returns canonical runtime
    // bytes copied off any real deployment (they are public, by design). The
    // result passes isCanonicalERC721() honestly — it really does run
    // canonical code — while reporting a totalSupply no mint ever created and
    // a `hooksContract()` that never deployed it. test/CodehashLimits.t.sol
    // demonstrates exactly this.
    //
    // CREATE2 closes the gap, because its address is a commitment to the INIT
    // code:
    //
    //     address = keccak256(0xff ++ deployer ++ salt ++ keccak256(initCode))[12:]
    //
    // Recomputing that address proves the canonical constructor actually ran:
    // storage started empty and `_hooks` genuinely came from `msg.sender`.
    // Combined with a canonical runtime codehash — which proves every
    // subsequent transition is canonical — the full statement is recovered:
    //
    //     supply started at zero and can only have grown via onlyIssuerAdmin.
    //
    // The constructor arguments are read back off the token, which cannot lie
    // about them: any different value yields a different initCode hash, hence
    // a different address, hence a mismatch. They are self-certifying.
    //
    // No new trust anchor is introduced. The CREATE2 deployer is the wrapper,
    // which is already an input to the check — there is no factory, registry,
    // or singleton involved.
    //
    // NOTE: `type(C).creationCode` is available even for contracts holding
    // immutables — only `runtimeCode` is restricted — so this check is
    // strictly more powerful than the codehash comparison, and would extend to
    // tokens the zero-immutable discipline currently rules out.

    /// @dev Salt used by HooksWrapperERC20/721/1155 when deploying their token.
    ///      Must stay in sync with TOKEN_SALT on those contracts.
    bytes32 internal constant TOKEN_SALT = keccak256("IntegrityToken.v1");

    function _create2Address(address deployer, bytes32 salt, bytes32 initCodeHash) private pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, salt, initCodeHash)))));
    }

    /// @notice Proves `token` was deployed by `wrapper` running the canonical
    ///         IntegrityERC20 constructor — so its initial state is canonical.
    /// @dev    CALLS INTO `token`. Only sound once the codehash is known
    ///         canonical; prefer isFullyVerifiedERC20, which orders the two
    ///         checks correctly and short-circuits.
    function isProvenanceVerifiedERC20(address token, address wrapper) internal view returns (bool) {
        if (token == address(0) || wrapper == address(0)) return false;
        IntegrityERC20 t = IntegrityERC20(token);
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(IntegrityERC20).creationCode, abi.encode(t.deployAdmin(), t.name(), t.symbol(), t.contractURI())
            )
        );
        return token == _create2Address(wrapper, TOKEN_SALT, initCodeHash);
    }

    /// @notice Proves `token` was deployed by `wrapper` running the canonical
    ///         IntegrityERC721 constructor — so its initial state is canonical.
    /// @dev    See isProvenanceVerifiedERC20 for the calling caveat.
    function isProvenanceVerifiedERC721(address token, address wrapper) internal view returns (bool) {
        if (token == address(0) || wrapper == address(0)) return false;
        IntegrityERC721 t = IntegrityERC721(token);
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(IntegrityERC721).creationCode,
                abi.encode(t.deployAdmin(), t.name(), t.symbol(), t.contractURI(), t.baseURI())
            )
        );
        return token == _create2Address(wrapper, TOKEN_SALT, initCodeHash);
    }

    /// @notice Proves `token` was deployed by `wrapper` running the canonical
    ///         IntegrityERC1155 constructor — so its initial state is canonical.
    /// @dev    See isProvenanceVerifiedERC20 for the calling caveat.
    function isProvenanceVerifiedERC1155(address token, address wrapper) internal view returns (bool) {
        if (token == address(0) || wrapper == address(0)) return false;
        IntegrityERC1155 t = IntegrityERC1155(token);
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(IntegrityERC1155).creationCode, abi.encode(t.deployAdmin(), t.uri(0), t.contractURI())
            )
        );
        return token == _create2Address(wrapper, TOKEN_SALT, initCodeHash);
    }

    // =========================================================================
    //                     FULL VERIFICATION (code + provenance)
    // =========================================================================
    //
    // The complete claim, and the one integrators should use. Ordering
    // matters: isCanonical* reads EXTCODEHASH without calling the target, so a
    // hostile address is rejected before any of its code is invoked. Only once
    // the codehash is confirmed canonical are the provenance getters called —
    // at which point they are guaranteed to exist and behave.

    function isFullyVerifiedERC20(address token, address wrapper) internal view returns (bool) {
        return isCanonicalERC20(token) && isCanonicalWrapperERC20(wrapper) && isProvenanceVerifiedERC20(token, wrapper);
    }

    function isFullyVerifiedERC721(address token, address wrapper) internal view returns (bool) {
        return
            isCanonicalERC721(token) && isCanonicalWrapperERC721(wrapper) && isProvenanceVerifiedERC721(token, wrapper);
    }

    function isFullyVerifiedERC1155(address token, address wrapper) internal view returns (bool) {
        return
            isCanonicalERC1155(token) && isCanonicalWrapperERC1155(wrapper)
                && isProvenanceVerifiedERC1155(token, wrapper);
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
