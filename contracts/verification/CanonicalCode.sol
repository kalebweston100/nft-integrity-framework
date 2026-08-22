//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title CanonicalCode
 * @notice Registry-less verification that an arbitrary address runs known code,
 *         and was deployed by a known constructor — with no published hash, no
 *         factory, no registry, and no admin key to trust.
 *
 * @dev STANDALONE AND DEPENDENCY-FREE. This file imports nothing. Copy it into
 *      any project; it has no relationship to the token framework it was
 *      extracted from. As an `internal` library it compiles into its caller and
 *      has no deployed address of its own, so there is nothing extra to trust.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * THE CENTRAL DISTINCTION
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *     A codehash proves FUTURE BEHAVIOUR.
 *     It cannot prove HISTORY. For that you need CREATE2 provenance.
 *
 * This is not a limitation to work around; it is the shape of the problem, and
 * getting it wrong silently over-claims.
 *
 * EXTCODEHASH hashes a contract's RUNTIME code. The code that wrote the
 * contract's initial storage — the constructor — lives in its CREATION code,
 * which EXTCODEHASH never covers. Init code and runtime code are independent
 * byte strings: CREATE stores whatever the init code RETURNs, and nothing
 * links the two.
 *
 * So an attacker can write an arbitrary constructor that fabricates storage,
 * then return canonical runtime bytes copied off any real deployment (public
 * by design — EXTCODECOPY works on any address). The result passes a codehash
 * check HONESTLY: it really does run canonical code, and every state
 * transition from that moment forward really does obey canonical rules. What
 * is false is everything about how it got there.
 *
 * Concretely, using a token as the example:
 *
 *   "transfers route through the configured hook"      FUTURE  → codehash ✓
 *   "entry points cannot be overridden"                FUTURE  → codehash ✓
 *   "this contract never DELEGATECALLs"                FUTURE  → codehash ✓
 *   "supply was only ever minted by the admin"         HISTORY → needs CREATE2
 *   "this address was recorded from msg.sender"        HISTORY → needs CREATE2
 *
 * A CREATE2 address is a commitment to the init code:
 *
 *     address = keccak256(0xff ++ deployer ++ salt ++ keccak256(initCode))[12:]
 *
 * Recomputing it proves the canonical constructor actually ran — so storage
 * started where that constructor put it. Note that `type(C).creationCode` is
 * available at compile time EVEN FOR CONTRACTS HOLDING IMMUTABLES; only
 * `type(C).runtimeCode` is restricted. Provenance verification is therefore
 * strictly more powerful than codehash comparison, at the cost of needing the
 * constructor arguments.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SELF-CERTIFYING CONSTRUCTOR ARGUMENTS
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Provenance needs the arguments the constructor was called with, and the
 * natural source is the contract being verified — which looks circular, since
 * a hostile contract could lie about them.
 *
 * It isn't. Any lie changes the init-code hash, hence the expected address,
 * hence the result. A contract can only report arguments that reproduce its own
 * address. Read them off the target freely; they certify themselves.
 *
 * (Store any constructor argument that a setter can later change — an admin
 * address, say — in a second, setter-less slot as well, or an ordinary
 * administrative handover will make the deployment unverifiable.)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY THIS CANNOT BE AN INTERFACE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Verification can never be a function you call ON the contract being verified
 * — it would just return true. EXTCODEHASH is read by the EVM directly from
 * deployed bytecode, so isCanonical() below never invokes the target and a
 * malicious contract cannot misreport it. Order your checks accordingly:
 * establish the codehash BEFORE calling anything on an address, and a hostile
 * target is rejected before its code ever runs.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * DERIVING EXPECTED VALUES
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Never paste hash literals. Derive them at compile time from imported source:
 *
 *     bytes32 expected = keccak256(type(MyContract).runtimeCode);
 *
 * The hash then cannot drift from the source it describes — the failure mode
 * that makes hardcoded init-code constants a well-known footgun. `runtimeCode`
 * compiles only for contracts holding NO immutable variables, which is a
 * feature: keep verified contracts immutable-free and the constraint enforces
 * itself, because adding one breaks the build with
 *
 *     Error (9274): "runtimeCode" is not available for contracts containing
 *                   immutable variables.
 *
 * Store constructor-time state in plain, setter-less storage instead —
 * EXTCODEHASH covers only code, never storage, so every deployment stays
 * byte-identical regardless of how it was configured.
 *
 * REPRODUCIBILITY: bytecode is comparable across independent compilations only
 * if the build is. Pin the compiler version, optimizer settings, and EVM
 * version, and drop the CBOR metadata trailer (`bytecode_hash = "none"`,
 * `cbor_metadata = false` under Foundry) — otherwise two people compiling
 * identical source get different hashes from a trailer derived from absolute
 * file paths. A mismatch fails CLOSED, rejecting a legitimate deployment rather
 * than accepting a malicious one, but it is a real operational hazard.
 *
 * GAS: `type(C).runtimeCode` and `.creationCode` embed the entire blob at the
 * call site. Derive hashes ONCE in your verifier's constructor and store them
 * in an `immutable` — never per call. A verifier holding immutables is fine;
 * only the VERIFIED contracts must be immutable-free.
 */
library CanonicalCode {
    // =========================================================================
    //                  FUTURE BEHAVIOUR — WHAT THE CODE WILL DO
    // =========================================================================

    /// @notice Whether `target` runs exactly the code hashing to
    ///         `expectedCodeHash`.
    /// @dev SAFE AGAINST UNTRUSTED TARGETS — never calls into `target`.
    ///
    ///      Proves every state transition from now on obeys that code's rules.
    ///      Proves NOTHING about the state you are looking at; pair with
    ///      isProvenanceVerified for that.
    ///
    ///      `codehash` is 0 for EOAs and nonexistent accounts and
    ///      keccak256("") for an existing account with no code, so a zero or
    ///      mistyped `expectedCodeHash` fails permissively. Always derive it
    ///      from `keccak256(type(C).runtimeCode)`.
    function isCanonical(address target, bytes32 expectedCodeHash) internal view returns (bool) {
        return target.codehash == expectedCodeHash;
    }

    // =========================================================================
    //                     HISTORY — HOW THE CODE GOT THERE
    // =========================================================================

    /// @notice The init-code hash for a CREATE2 deployment.
    /// @param creationCode Typically `type(C).creationCode` — available even
    ///        for contracts holding immutables.
    /// @param encodedArgs `abi.encode(...)` of the constructor arguments, or
    ///        empty for a constructor taking none.
    function initCodeHash(bytes memory creationCode, bytes memory encodedArgs) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(creationCode, encodedArgs));
    }

    /// @notice The address a CREATE2 deployment lands at.
    function addressOf(address deployer, bytes32 salt, bytes32 initCodeHash_) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), deployer, salt, initCodeHash_)))));
    }

    /// @notice Whether `target` was deployed by `deployer` via CREATE2, running
    ///         exactly the constructor that `initCodeHash_` describes.
    /// @dev The gap a codehash cannot close. A match proves the canonical
    ///      constructor ran, so the contract's initial storage is whatever that
    ///      constructor wrote — no fabricated balances, no planted addresses.
    ///
    ///      `deployer` need not be a factory or singleton. Any contract already
    ///      part of the structure being verified will do, which is what keeps
    ///      this anchor-free: nothing global is introduced.
    function isProvenanceVerified(address target, address deployer, bytes32 salt, bytes32 initCodeHash_)
        internal
        pure
        returns (bool)
    {
        return target != address(0) && target == addressOf(deployer, salt, initCodeHash_);
    }

    // =========================================================================
    //                     BOTH — THE COMPLETE STATEMENT
    // =========================================================================

    /// @notice Canonical code AND a canonical constructor: the contract behaves
    ///         as its source says, and started from where its source says.
    /// @dev Short-circuits on the codehash first, so a hostile address is
    ///      rejected before any call is made to it.
    function isFullyVerified(
        address target,
        bytes32 expectedCodeHash,
        address deployer,
        bytes32 salt,
        bytes32 initCodeHash_
    ) internal view returns (bool) {
        return isCanonical(target, expectedCodeHash) && isProvenanceVerified(target, deployer, salt, initCodeHash_);
    }
}
