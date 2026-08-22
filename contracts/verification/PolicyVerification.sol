//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./CanonicalCode.sol";
import "../engine/PolicyEngine.sol";
import "../engine/PolicyTypes.sol";
import "../token/PolicyERC20.sol";

/**
 * @title PolicyVerification
 * @notice One call that answers the only question a holder actually has:
 *         under what conditions can this token block my transfer?
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY THIS IS ANSWERABLE AT ALL
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * For an ordinary token it is not. Ask it of an Etherscan-verified ERC-3643
 * compliance module and you must read arbitrary Solidity and reason about every
 * path through it — a program-analysis problem, undecidable in general, in
 * practice a human auditor per token per version. Source verification tells you
 * WHAT THE CODE IS. It cannot tell you what the code MEANS for you.
 *
 * Here the answer is an array read, because the policy is data rather than
 * code. That, not the hashing below, is the contribution. The hashes exist for
 * one narrow purpose: to establish that `rules()` is EXHAUSTIVE.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT MAKES THE ANSWER COMPLETE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Two codehashes, and the claim needs both:
 *
 *   tokenCanonical   The entry point runs known code, so the transfer path is
 *                    the one in PolicyERC20 — whose only discretionary revert
 *                    is the policy verdict. WITHOUT THIS THE REPORT IS
 *                    MEANINGLESS: an unverified token can `require` anything,
 *                    anywhere, and the rules below would describe one condition
 *                    among unknown others.
 *
 *   policyCanonical  The engine runs known code, so `rules()` is really what
 *                    `evaluate()` consults and no condition outside the array
 *                    can exist.
 *
 * Both are claims about FUTURE BEHAVIOUR, which is exactly what a codehash can
 * carry — so this report needs no CREATE2 provenance. Provenance would be
 * required for claims about HISTORY ("these were the launch rules", "supply was
 * only ever minted by the admin"); it is deliberately not attempted here,
 * because the headline claim does not rest on it. See CanonicalCode.sol for the
 * distinction.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ORDERING IS LOAD-BEARING
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * EXTCODEHASH never invokes the target, so a codehash is safe to take against a
 * hostile address. Every function below establishes a codehash BEFORE making
 * any call to that address, and returns early when it fails. Reordering these
 * checks would let a hostile contract run before it has been rejected.
 *
 * GAS: `type(C).runtimeCode` embeds the whole blob at the call site. An
 * on-chain consumer should derive the two hashes ONCE in its constructor and
 * store them in `immutable`s — a verifier holding immutables is fine, only the
 * VERIFIED contracts must be immutable-free.
 */
library PolicyVerification {
    /**
     * @notice The complete verified picture of a token's transfer policy.
     *
     * @param tokenCanonical  The token runs canonical PolicyERC20 code. If
     *                        false, every other field is untrustworthy and the
     *                        report stops here.
     * @param policyCanonical The engine runs canonical PolicyEngine code.
     * @param hasExternalGate At least one rule defers to arbitrary code, so
     *                        "no other condition exists" is reduced to whatever
     *                        that contract does.
     * @param swapDelay       Seconds of public notice before a rule change
     *                        commits. Covers which conditions exist, NOT who
     *                        they apply to — registry membership changes are
     *                        instant. See PolicyEngine's NatSpec.
     * @param pendingAt       When a proposed rule change becomes committable,
     *                        0 if none is pending. Non-zero means the policy is
     *                        about to change: read pendingRules() off the
     *                        engine to see how.
     * @param externalRefs    Every address this policy consults, of any rule
     *                        kind. Each is unverified code whose codehash a
     *                        thorough integrator should check too.
     * @param rules           The complete, exhaustive policy.
     */
    struct Report {
        bool tokenCanonical;
        bool policyCanonical;
        bool hasExternalGate;
        uint256 swapDelay;
        uint256 pendingAt;
        address[] externalRefs;
        Rule[] rules;
    }

    /// @notice Expected runtime codehash of a canonical PolicyERC20.
    /// @dev Derived at compile time from imported source, so it cannot drift
    ///      from the code it describes. Compiles only while PolicyERC20 holds
    ///      zero immutables — add one and this stops building, by design.
    function canonicalTokenHashERC20() internal pure returns (bytes32) {
        return keccak256(type(PolicyERC20).runtimeCode);
    }

    /// @notice Expected runtime codehash of a canonical PolicyEngine.
    /// @dev One value for every issuer on every chain, forever, per version —
    ///      which is what makes an off-chain consumer (a wallet, an explorer)
    ///      practical. Policy varies in storage; this never does.
    function canonicalPolicyHash() internal pure returns (bytes32) {
        return keccak256(type(PolicyEngine).runtimeCode);
    }

    /**
     * @notice Verify a token and enumerate its complete transfer policy.
     * @dev SAFE AGAINST UNTRUSTED INPUT — no call is made to `token` until its
     *      codehash has been established, and none to the engine until its own
     *      has been.
     *
     *      A false `tokenCanonical` is not necessarily an attack; it is far
     *      more often an ordinary ERC-20 that simply is not part of this
     *      framework. Render it as "unknown", not "malicious".
     */
    function verifyERC20(address token) internal view returns (Report memory report) {
        report.tokenCanonical = CanonicalCode.isCanonical(token, canonicalTokenHashERC20());
        if (!report.tokenCanonical) return report;

        // Safe: `token` has been established as canonical PolicyERC20, whose
        // policy() is a plain getter over a setter-less slot — the same slot
        // its transfer path reads.
        address engine = PolicyERC20(token).policy();

        report.policyCanonical = CanonicalCode.isCanonical(engine, canonicalPolicyHash());
        if (!report.policyCanonical) return report;

        PolicyEngine policy = PolicyEngine(engine);
        report.rules = policy.rules();
        report.hasExternalGate = policy.hasExternalGate();
        report.externalRefs = policy.externalRefs();
        report.swapDelay = policy.swapDelay();
        (, report.pendingAt) = policy.pendingRules();
    }

    /**
     * @notice The headline claim, as a single boolean.
     * @dev True means: beyond the ERC-20 standard's own requirements, the ONLY
     *      conditions that can block a transfer of this token are the rules in
     *      `report.rules`, and no new KIND of condition can appear without
     *      `report.swapDelay` seconds of public notice.
     *
     *      Requires the absence of an external gate, because one reduces the
     *      guarantee to whatever arbitrary contract it names. Note this stays
     *      true when `externalRefs` is non-empty without a gate: an Allowlist's
     *      CONDITION is fixed and enumerable even though its MEMBERSHIP is not.
     *      Surface `externalRefs` alongside this either way.
     */
    function isFullyEnumerable(Report memory report) internal pure returns (bool) {
        return report.tokenCanonical && report.policyCanonical && !report.hasExternalGate;
    }
}
