//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./CanonicalCode.sol";
import "../interfaces/Types.sol";
import "../interfaces/IPolicyGoverned.sol";
import "../engine/PolicyEngine.sol";
import "../engine/PolicyTypes.sol";
import "../token/PolicyERC20.sol";
import "../token/PolicyERC721.sol";
import "../token/PolicyERC1155.sol";

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
 * THE CANONICAL SET
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Verification matches a token against a FIXED, FINITE set of hashes — one per
 * member of contracts/token/. A wallet ships those few constants and can then
 * verify any token any issuer deploys, on any chain, forever, per version.
 *
 * The set being closed is not a limitation to be engineered away; it is the
 * source of the guarantee. A token outside it is reported as unknown, exactly
 * as any other ERC-20 would be. There is deliberately no "conformance"
 * interface a third-party token could implement to be treated as a member:
 * whatever address a user transacts with decides whether the call reverts, so
 * only known bytecode can carry the claim.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT MAKES THE ANSWER COMPLETE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Two codehashes, and the claim needs both:
 *
 *   tokenCanonical   The entry point runs known code, so the transfer path is
 *                    one of the audited ones — whose only discretionary revert
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
 * distinction, and test/CodehashLimits.t.sol for a demonstration that a
 * codehash genuinely cannot carry a claim about history.
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
 * on-chain consumer should derive the hashes ONCE in its constructor and store
 * them in `immutable`s — a verifier holding immutables is fine, only the
 * VERIFIED contracts must be immutable-free.
 */
library PolicyVerification {
    /**
     * @notice The complete verified picture of a token's transfer policy.
     *
     * @param tokenCanonical  The token runs the code of a member of the
     *                        canonical set. If false, EVERY OTHER FIELD IS
     *                        MEANINGLESS — including `standard`, which is left
     *                        at its zero value rather than detected.
     * @param policyCanonical The engine runs canonical PolicyEngine code.
     * @param standard        Which member of the set matched. Only meaningful
     *                        when `tokenCanonical` is true.
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
     * @param rules           The complete, exhaustive policy, across every
     *                        action. Each rule names the entry point it
     *                        governs.
     * @param activeActions   Bitmap of actions at least one rule governs,
     *                        indexed by Action. A zero bit means that entry
     *                        point is currently ungated.
     * @param allowedKindsBy  Per action, the bitmask of rule kinds that may
     *                        EVER govern it. Read off canonical `pure` code, so
     *                        this is a permanent bound rather than a current
     *                        state: a kind absent here can never apply to that
     *                        action, with or without notice. Strictly stronger
     *                        than what the timelock promises.
     */
    struct Report {
        bool tokenCanonical;
        bool policyCanonical;
        TokenStandard standard;
        bool hasExternalGate;
        uint256 swapDelay;
        uint256 pendingAt;
        address[] externalRefs;
        Rule[] rules;
        uint256 activeActions;
        uint256[5] allowedKindsBy;
    }

    // =========================================================================
    //                            THE CANONICAL SET
    // =========================================================================

    /// @dev Each hash is derived at compile time from imported source, so it
    ///      cannot drift from the code it describes. These compile only while
    ///      every token holds zero immutables — add one and the build breaks,
    ///      by design.

    function canonicalTokenHashERC20() internal pure returns (bytes32) {
        return keccak256(type(PolicyERC20).runtimeCode);
    }

    function canonicalTokenHashERC721() internal pure returns (bytes32) {
        return keccak256(type(PolicyERC721).runtimeCode);
    }

    function canonicalTokenHashERC1155() internal pure returns (bytes32) {
        return keccak256(type(PolicyERC1155).runtimeCode);
    }

    /// @notice Expected runtime codehash of a canonical PolicyEngine.
    /// @dev One value for every issuer of every standard on every chain,
    ///      forever, per version — which is what makes an off-chain consumer (a
    ///      wallet, an explorer) practical. Policy varies in storage; this never
    ///      does.
    function canonicalPolicyHash() internal pure returns (bytes32) {
        return keccak256(type(PolicyEngine).runtimeCode);
    }

    // =========================================================================
    //                              VERIFICATION
    // =========================================================================

    /**
     * @notice Verify a token against the whole canonical set and enumerate its
     *         complete transfer policy.
     * @dev The entry point an integrator should use when it does not already
     *      know which standard it is looking at — a wallet scanning an unknown
     *      address, for instance.
     *
     *      SAFE AGAINST UNTRUSTED INPUT — no call is made to `token` until its
     *      codehash has been matched, and none to the engine until its own has
     *      been.
     *
     *      A false `tokenCanonical` is not necessarily an attack; it is far
     *      more often an ordinary token that simply is not part of this set.
     *      Render it as "unknown", not "malicious".
     */
    function verify(address token) internal view returns (Report memory report) {
        bytes32 actual = token.codehash;

        if (actual == canonicalTokenHashERC20()) {
            report.standard = TokenStandard.ERC20;
        } else if (actual == canonicalTokenHashERC721()) {
            report.standard = TokenStandard.ERC721;
        } else if (actual == canonicalTokenHashERC1155()) {
            report.standard = TokenStandard.ERC1155;
        } else {
            return report;
        }

        report.tokenCanonical = true;
        _readPolicy(token, report);
    }

    /// @notice Verify a token known to be an ERC-20, rejecting other members of
    ///         the set.
    function verifyERC20(address token) internal view returns (Report memory report) {
        return _verifyAs(token, canonicalTokenHashERC20(), TokenStandard.ERC20);
    }

    /// @notice Verify a token known to be an ERC-721.
    function verifyERC721(address token) internal view returns (Report memory report) {
        return _verifyAs(token, canonicalTokenHashERC721(), TokenStandard.ERC721);
    }

    /// @notice Verify a token known to be an ERC-1155.
    function verifyERC1155(address token) internal view returns (Report memory report) {
        return _verifyAs(token, canonicalTokenHashERC1155(), TokenStandard.ERC1155);
    }

    function _verifyAs(address token, bytes32 expected, TokenStandard standard)
        private
        view
        returns (Report memory report)
    {
        report.tokenCanonical = CanonicalCode.isCanonical(token, expected);
        if (!report.tokenCanonical) return report;

        report.standard = standard;
        _readPolicy(token, report);
    }

    /// @dev Only ever reached once `token` has been established as canonical,
    ///      so `policy()` is a plain getter over a setter-less slot — the same
    ///      slot the transfer path reads.
    function _readPolicy(address token, Report memory report) private view {
        address engine = IPolicyGoverned(token).policy();

        report.policyCanonical = CanonicalCode.isCanonical(engine, canonicalPolicyHash());
        if (!report.policyCanonical) return;

        PolicyEngine policy = PolicyEngine(engine);
        report.rules = policy.rules();
        report.hasExternalGate = policy.hasExternalGate();
        report.externalRefs = policy.externalRefs();
        report.swapDelay = policy.swapDelay();
        (, report.pendingAt) = policy.pendingRules();
        report.activeActions = policy.activeActions();

        for (uint256 i; i < 5; ++i) {
            report.allowedKindsBy[i] = policy.allowedKinds(Action(i));
        }
    }

    // =========================================================================
    //                          THE TWO HEADLINE CLAIMS
    // =========================================================================

    /**
     * @notice The general claim, as a single boolean.
     * @dev True means: beyond the token standard's own requirements, the ONLY
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

    /**
     * @notice The strongest claim the design can make: NOTHING can block a
     *         transfer of this token.
     *
     * @dev Not a degenerate case of isFullyEnumerable — it is the case worth
     *      leading with. Establishing the ABSENCE of a hidden blocking
     *      condition is normally impossible: no amount of observed behaviour
     *      rules out a branch that has not been taken yet, and reading the
     *      source means reasoning over every path, again after every upgrade.
     *      A canonical codehash plus an empty rule array settles it by
     *      construction, in one call, for a token that is otherwise an entirely
     *      ordinary and fully marketplace-compatible ERC-20/721/1155.
     *
     *      `pendingAt == 0` IS PART OF THE CLAIM, not a detail. A token with no
     *      rules but a pending proposal is unconditional today and may not be
     *      tomorrow; reporting it as simply unconditional would put a green
     *      badge on a token that is days away from a lockup. A caller that
     *      wants the weaker "nothing blocks right now" reading should test the
     *      fields itself and say so in its UI.
     *
     *      An external gate cannot be present when this returns true, since a
     *      gate is itself a rule and the array is empty.
     */
    function isUnconditional(Report memory report) internal pure returns (bool) {
        return report.tokenCanonical && report.policyCanonical && report.rules.length == 0 && report.pendingAt == 0;
    }

    /**
     * @notice The same claim for one entry point: nothing can block this action.
     *
     * @dev Lets a reader render a token honestly when it is governed unevenly —
     *      "transfers unconditional, minting restricted" is the common shape for
     *      a collection that caps supply per wallet but never restricts
     *      secondary trading, and collapsing that to a single red badge would
     *      misrepresent it.
     *
     *      `pendingAt == 0` is part of this too: a pending proposal may add a
     *      rule to ANY action, so no action can be called unconditional while
     *      one is queued.
     */
    function isUnconditionalFor(Report memory report, Action action) internal pure returns (bool) {
        if (!report.tokenCanonical || !report.policyCanonical || report.pendingAt != 0) return false;
        return report.activeActions & (1 << uint256(action)) == 0;
    }

    /**
     * @notice Whether `kind` could ever govern `action` on this token.
     * @dev False is a permanent guarantee, not a snapshot — the answer comes
     *      from `pure` code inside the canonical engine, so no proposal and no
     *      elapsed timelock can change it.
     */
    function canEverApply(Report memory report, Action action, RuleKind kind) internal pure returns (bool) {
        if (!report.policyCanonical) return true; // unknown code: assume nothing
        return report.allowedKindsBy[uint256(action)] & (1 << uint256(kind)) != 0;
    }
}
