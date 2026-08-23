//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./PolicyTypes.sol";

/**
 * @title PolicyEngine
 * @notice One canonical, declarative transfer policy, shared by every issuer
 *         and every token standard.
 *
 * @dev Deployed by its token's constructor via CREATE2 and never separately —
 *      see contracts/token/PolicyERC20.sol, which holds the full statement of
 *      what the pair guarantees together.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY THIS EXISTS
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * A bespoke policy contract per issuer can never have a universal hash, so
 * verification could cover the token and the wrapper but never the thing that
 * actually decides whether your transfer goes through.
 *
 * Inverting it fixes that. Fix the CODE, vary the STORAGE — the same trick the
 * tokens already use to stay byte-identical — applied to policy. Rules live in
 * `_rules`; the bytecode evaluating them is identical for everyone. So:
 *
 *     keccak256(type(PolicyEngine).runtimeCode) == policy.codehash
 *
 * and the claim an integrator can then make is one nothing else in the
 * ecosystem offers:
 *
 *     Here is the complete, enumerable set of conditions under which this
 *     token can block a transfer. The code is canonical, so no other
 *     condition exists. It cannot change without `swapDelay` seconds of
 *     public, on-chain notice.
 *
 * Provable ABSENCE of arbitrary code in a transfer path is the product. Where
 * arbitrary code IS present it is made visible rather than assumed — see
 * hasExternalGate() and externalRefs(), and report both.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT THE TIMELOCK ACTUALLY COVERS
 * ─────────────────────────────────────────────────────────────────────────────
 *
 *     The timelock covers WHICH CONDITIONS EXIST, not WHO THEY APPLY TO.
 *
 * Worth stating precisely because the looser version — "the policy cannot
 * change without notice" — is false, and four of the ten rule kinds are why.
 * Allowlist, Blocklist, Frozen and ExternalGate consult a contract at `ref`
 * whose contents the timelock does not govern: an issuer can freeze an address
 * by editing a registry, instantly, with no notice at all.
 *
 * That is not fully fixable, and pretending otherwise would be worse than
 * documenting it — sanctions compliance REQUIRES the ability to block
 * immediately, so a notice period on membership would make the rules unusable
 * for the market that most wants them. What the timelock does guarantee is that
 * no NEW KIND of condition can appear: a token with no Frozen rule today cannot
 * acquire the power to freeze you without swapDelay seconds of public notice.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ZERO IMMUTABLES — LOAD-BEARING
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Every field below is plain storage. `admin`, `notifier` and `swapDelay` are
 * set once in the constructor with no setter, exactly as the tokens do it.
 * Adding a single `immutable` would stop `type(PolicyEngine).runtimeCode` from
 * compiling and destroy the canonical hash — the constraint enforces itself.
 * See contracts/verification/CanonicalCode.sol.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT THIS DOES NOT PROVE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * That the rules are GOOD. A canonical engine can enumerate rules that deny
 * every transfer. What changes is that they are visible in advance instead of
 * hidden in bespoke bytecode.
 */
contract PolicyEngine {
    // =========================================================================
    //                              ERRORS / EVENTS
    // =========================================================================

    error NotAdmin();
    error NotNotifier();
    error ZeroAddress();
    error NoPendingRules();
    error TimelockNotElapsed(uint256 effectiveAt);
    error RulesPending();
    error InvalidRule(uint256 index);
    error KindNotAllowedForAction(uint256 index, Action action, RuleKind kind);

    event RulesProposed(Rule[] rules, uint256 effectiveAt);
    event RulesCommitted(Rule[] rules);
    event RulesCancelled();
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    // =========================================================================
    //                        STATE — ALL PLAIN STORAGE
    // =========================================================================

    /// @notice May propose, commit and cancel rule changes.
    address public admin;

    /// @notice The only address permitted to record post-transfer state,
    ///         i.e. the token itself. Set once in the constructor, no setter.
    address public notifier;

    /// @notice Seconds of public notice required before a rule change commits.
    ///         Set once in the constructor, no setter — a policy cannot shorten
    ///         its own notice period.
    uint256 public swapDelay;

    Rule[] private _rules;
    Rule[] private _pendingRules;

    /// @notice When the pending rule set becomes committable. 0 = none pending.
    uint256 public pendingAt;

    /// @notice Last time an address received tokens, for MinHoldTime.
    mapping(address => uint256) public lastReceived;

    /// @notice Whether the active rule set contains a MinHoldTime rule, cached
    ///         so recordTransfer can skip its SSTORE when nothing reads it.
    /// @dev    Refreshed whenever `_rules` changes. Without this every transfer
    ///         on every policy pays ~20k gas to maintain state that only one of
    ///         ten rule kinds consults.
    bool public tracksHoldTime;

    /// @notice Bitmap of actions that at least one active rule governs, indexed
    ///         by `Action`. Cached so `evaluate` can return without scanning.
    /// @dev    This is what keeps the four newly-gated entry points cheap. An
    ///         ungated action costs one warm SLOAD and no array traversal, so a
    ///         token with an unconditional policy pays almost nothing for being
    ///         governed at all.
    uint256 public activeActions;

    // =========================================================================
    //                                MODIFIERS
    // =========================================================================

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyNotifier() {
        if (msg.sender != notifier) revert NotNotifier();
        _;
    }

    // =========================================================================
    //                               CONSTRUCTOR
    // =========================================================================

    /// @param admin_     Issuer admin, may change rules subject to the timelock.
    /// @param notifier_  The token that will report settled transfers.
    /// @param swapDelay_ Notice period for rule changes, in seconds.
    /// @param rules_     The initial policy.
    constructor(address admin_, address notifier_, uint256 swapDelay_, Rule[] memory rules_) {
        if (admin_ == address(0) || notifier_ == address(0)) revert ZeroAddress();
        admin = admin_;
        notifier = notifier_;
        swapDelay = swapDelay_;
        _validate(rules_);
        _writeRules(_rules, rules_);
        _refreshCaches();
    }

    // =========================================================================
    //                    ENUMERATION — THE INTEGRATOR SURFACE
    // =========================================================================

    /// @notice The complete policy. Because this contract's code is canonical,
    ///         nothing outside this array can block a transfer.
    function rules() external view returns (Rule[] memory) {
        return _rules;
    }

    function ruleCount() external view returns (uint256) {
        return _rules.length;
    }

    /// @notice The rules governing one entry point.
    /// @dev    A convenience over rules(); the flat array remains the complete
    ///         policy and the thing to hash or diff.
    function rulesFor(Action a) external view returns (Rule[] memory subset) {
        uint256 n = _rules.length;
        uint256 count;
        for (uint256 i; i < n; ++i) {
            if (_rules[i].action == a) ++count;
        }

        subset = new Rule[](count);
        uint256 j;
        for (uint256 i; i < n; ++i) {
            if (_rules[i].action == a) {
                subset[j] = _rules[i];
                ++j;
            }
        }
    }

    /// @notice The pending policy and when it becomes committable.
    function pendingRules() external view returns (Rule[] memory, uint256) {
        return (_pendingRules, pendingAt);
    }

    /// @notice Whether any rule defers to arbitrary external CODE — i.e. an
    ///         ExternalGate, whose contract may implement any condition at all.
    /// @dev    When true, the "no other condition exists" guarantee is reduced
    ///         to whatever that contract does. Surface this to users; never
    ///         suppress it.
    ///
    ///         NOT the whole story on its own: Allowlist, Blocklist and Frozen
    ///         also consult an external contract. Their CONDITION is fixed and
    ///         enumerable ("must be listed in ref"), so they are not gates in
    ///         this sense — but the membership they read is arbitrary, mutable
    ///         data controlled by whoever owns `ref`. Use externalRefs() to see
    ///         every address this policy depends on, of either kind.
    function hasExternalGate() external view returns (bool) {
        uint256 n = _rules.length;
        for (uint256 i; i < n; ++i) {
            if (_rules[i].kind == RuleKind.ExternalGate) return true;
        }
        return false;
    }

    /// @notice Every external address this policy consults, for any rule kind.
    /// @dev    The honest completion of hasExternalGate(). A policy of
    ///         [Allowlist(ref: hostileProxy)] contains no ExternalGate, yet its
    ///         verdicts are entirely controlled by unverified code at `ref`.
    ///         Reporting only gates would let that pass as fully enumerable.
    ///
    ///         An integrator should check the codehash of each address returned
    ///         here before treating this policy's rules as the complete story,
    ///         exactly as they check this engine's own.
    ///
    ///         May contain duplicates — one address can back several rules.
    function externalRefs() external view returns (address[] memory refs) {
        uint256 n = _rules.length;
        uint256 count;
        for (uint256 i; i < n; ++i) {
            if (_consultsExternal(_rules[i].kind)) ++count;
        }

        refs = new address[](count);
        uint256 j;
        for (uint256 i; i < n; ++i) {
            if (_consultsExternal(_rules[i].kind)) {
                refs[j] = _rules[i].ref;
                ++j;
            }
        }
    }

    function _consultsExternal(RuleKind k) private pure returns (bool) {
        return k == RuleKind.Allowlist || k == RuleKind.Blocklist || k == RuleKind.Frozen || k == RuleKind.ExternalGate;
    }

    // =========================================================================
    //                        THE PERMANENT ENVELOPE
    // =========================================================================

    /**
     * @notice Which rule kinds may EVER apply to `a`, as a bitmask indexed by
     *         RuleKind.
     *
     * @dev `pure`, so this lives in canonical bytecode and a reader need not
     *      trust an off-chain table. That makes it a claim the timelock cannot
     *      make:
     *
     *          The timelock says no new KIND can appear without notice.
     *          This says these kinds can never apply to this action AT ALL,
     *          regardless of notice, for the life of the contract.
     *
     *      It also sharpens the unconditional case from "no rules right now" to
     *      "no rules right now, and here is the finite envelope of everything
     *      that could ever be added."
     *
     *      The exclusions are not tidiness. Several kinds would SILENTLY
     *      MISBEHAVE rather than merely be useless:
     *
     *        HolderCap on Burn      `to` is address(0), so `toBalance` is 0 and
     *                               the rule fires on every burn, denying it
     *                               for a reason unrelated to holder counts.
     *        MaxBalance on Burn     compares against the zero address balance,
     *                               quietly behaving as a MaxTransfer.
     *        MinHoldTime on Mint    reads lastReceived[address(0)], never set.
     *
     *      A rule that means something other than its name is worse than one
     *      that is refused, so these are rejected at propose time.
     *
     *      Identity rules and the escape hatch apply everywhere. Quantity rules
     *      apply only where a quantity is meaningful — MaxTransfer on Approve
     *      is an allowance cap, MinHoldTime on Approve or SetOperator is an
     *      anti-sniping rule: both unusual, both coherent.
     */
    function allowedKinds(Action a) public pure returns (uint256) {
        uint256 identity = _bit(RuleKind.Allowlist) | _bit(RuleKind.Blocklist) | _bit(RuleKind.Frozen)
            | _bit(RuleKind.LockupUntil) | _bit(RuleKind.ExternalGate);

        if (a == Action.Transfer) {
            return identity | _bit(RuleKind.MaxTransfer) | _bit(RuleKind.MaxBalance) | _bit(RuleKind.MaxBalanceBps)
                | _bit(RuleKind.MinHoldTime) | _bit(RuleKind.HolderCap);
        }
        if (a == Action.Approve) {
            return identity | _bit(RuleKind.MaxTransfer) | _bit(RuleKind.MinHoldTime);
        }
        if (a == Action.SetOperator) {
            return identity | _bit(RuleKind.MinHoldTime);
        }
        if (a == Action.Mint) {
            return identity | _bit(RuleKind.MaxTransfer) | _bit(RuleKind.MaxBalance) | _bit(RuleKind.MaxBalanceBps)
                | _bit(RuleKind.HolderCap);
        }
        // Action.Burn
        return identity | _bit(RuleKind.MaxTransfer) | _bit(RuleKind.MinHoldTime);
    }

    function _bit(RuleKind k) private pure returns (uint256) {
        return 1 << uint256(k);
    }

    // =========================================================================
    //                               EVALUATION
    // =========================================================================

    /// @notice Evaluate the policy against a pending action.
    /// @dev    `view`, so it can never mutate state — the deny gate is
    ///         STATICCALL-enforced end to end. Rules are ANDed; the first
    ///         failure short-circuits and names itself.
    ///
    ///         Returns immediately for an action no rule governs, so the four
    ///         entry points beyond Transfer cost one warm SLOAD when ungated.
    function evaluate(ActionContext calldata ctx) public view returns (bool ok, string memory reason) {
        if (activeActions & (1 << uint256(ctx.action)) == 0) return (true, "");

        uint256 n = _rules.length;
        for (uint256 i; i < n; ++i) {
            Rule storage r = _rules[i];

            // A rule governs exactly one entry point.
            if (r.action != ctx.action) continue;

            // ERC-1155: a scoped rule applies only to its own token id.
            if (r.scoped && r.scopeId != ctx.id) continue;

            (bool pass, string memory why) = _evaluateOne(r, ctx);
            if (!pass) return (false, why);
        }
        return (true, "");
    }

    function _evaluateOne(Rule storage r, ActionContext calldata ctx) private view returns (bool, string memory) {
        RuleKind k = r.kind;

        if (k == RuleKind.Allowlist) {
            // Zero address is skipped so mint/burn are not blocked by membership.
            if (ctx.from != address(0) && !IPolicyRegistry(r.ref).isListed(ctx.from)) {
                return (false, "sender not allowlisted");
            }
            if (ctx.to != address(0) && !IPolicyRegistry(r.ref).isListed(ctx.to)) {
                return (false, "recipient not allowlisted");
            }
            return (true, "");
        }

        if (k == RuleKind.Blocklist) {
            if (ctx.from != address(0) && IPolicyRegistry(r.ref).isListed(ctx.from)) {
                return (false, "sender blocklisted");
            }
            if (ctx.to != address(0) && IPolicyRegistry(r.ref).isListed(ctx.to)) {
                return (false, "recipient blocklisted");
            }
            return (true, "");
        }

        if (k == RuleKind.Frozen) {
            if (ctx.from != address(0) && IPolicyRegistry(r.ref).isListed(ctx.from)) {
                return (false, "sender frozen");
            }
            if (ctx.to != address(0) && IPolicyRegistry(r.ref).isListed(ctx.to)) {
                return (false, "recipient frozen");
            }
            return (true, "");
        }

        if (k == RuleKind.LockupUntil) {
            if (block.timestamp < r.value) return (false, "locked up");
            return (true, "");
        }

        if (k == RuleKind.MaxTransfer) {
            if (ctx.amount > r.value) return (false, "exceeds max transfer");
            return (true, "");
        }

        if (k == RuleKind.MaxBalance) {
            if (ctx.toBalance + ctx.amount > r.value) return (false, "exceeds max balance");
            return (true, "");
        }

        if (k == RuleKind.MaxBalanceBps) {
            // (toBalance + amount) / totalSupply > value / 10000, cross-multiplied.
            if ((ctx.toBalance + ctx.amount) * 10_000 > ctx.totalSupply * r.value) {
                return (false, "exceeds max balance share");
            }
            return (true, "");
        }

        if (k == RuleKind.MinHoldTime) {
            uint256 since = lastReceived[ctx.from];
            if (since != 0 && block.timestamp < since + r.value) return (false, "min hold time");
            return (true, "");
        }

        if (k == RuleKind.HolderCap) {
            // Only a NEW holder can push the count up.
            if (ctx.toBalance == 0 && ctx.amount > 0 && ctx.holderCount + 1 > r.value) {
                return (false, "holder cap reached");
            }
            return (true, "");
        }

        // ExternalGate — untrusted. A reverting gate denies (fail closed).
        try IPolicyGate(r.ref).check(ctx) returns (bool gateOk, string memory gateReason) {
            if (!gateOk) return (false, gateReason);
            return (true, "");
        } catch {
            return (false, "external gate reverted");
        }
    }

    // =========================================================================
    //                        POST-TRANSFER STATE
    // =========================================================================

    /// @notice Record a settled transfer. Only the notifier may call this.
    /// @dev    MinHoldTime needs writable state, and `evaluate` is `view`, so
    ///         the write happens here — on the existing after-transfer hook,
    ///         adding no new call path and no reverse call into the token.
    function recordTransfer(ActionContext calldata ctx) external onlyNotifier {
        if (!tracksHoldTime) return;
        if (ctx.to != address(0) && ctx.amount > 0) {
            lastReceived[ctx.to] = block.timestamp;
        }
    }

    // =========================================================================
    //                     TIMELOCKED RULE CHANGES
    // =========================================================================

    /// @notice Begin a rule change. Emits the full proposed policy so holders
    ///         can see exactly what is coming without polling.
    function proposeRules(Rule[] calldata newRules) external onlyAdmin {
        if (pendingAt != 0) revert RulesPending();
        _validate(newRules);

        delete _pendingRules;
        for (uint256 i; i < newRules.length; ++i) {
            _pendingRules.push(newRules[i]);
        }

        pendingAt = block.timestamp + swapDelay;
        emit RulesProposed(newRules, pendingAt);
    }

    /// @notice Apply a proposal once its notice period has elapsed.
    /// @dev    Because this contract's code is canonical, this is the ONLY way
    ///         the policy can ever change — there is no swappable logic
    ///         contract to replace, so the timelock covers every possible
    ///         change rather than merely wholesale replacement.
    function commitRules() external onlyAdmin {
        uint256 at = pendingAt;
        if (at == 0) revert NoPendingRules();
        if (block.timestamp < at) revert TimelockNotElapsed(at);

        _writeRules(_rules, _pendingRules);
        _refreshCaches();
        delete _pendingRules;
        pendingAt = 0;

        emit RulesCommitted(_rules);
    }

    function cancelRules() external onlyAdmin {
        if (pendingAt == 0) revert NoPendingRules();
        delete _pendingRules;
        pendingAt = 0;
        emit RulesCancelled();
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    // =========================================================================
    //                              INTERNAL
    // =========================================================================

    /// @dev Applied to the launch policy as well as to every proposal — an
    ///      issuer must not be able to deploy with a rule that could never be
    ///      proposed. Rejects rules whose parameters could never be satisfied or
    ///      whose registry is unset — a malformed rule would otherwise deny every
    ///      transfer with a confusing reason, or revert on a call to address(0).
    function _validate(Rule[] memory newRules) private pure {
        for (uint256 i; i < newRules.length; ++i) {
            Rule memory r = newRules[i];
            RuleKind k = r.kind;

            // The permanent envelope: this kind may never govern this action.
            if (allowedKinds(r.action) & _bit(k) == 0) revert KindNotAllowedForAction(i, r.action, k);

            bool needsRef = k == RuleKind.Allowlist || k == RuleKind.Blocklist || k == RuleKind.Frozen
                || k == RuleKind.ExternalGate;

            // Field schema, enforced. Unused fields MUST be zero so two engines
            // holding the same logical policy return byte-identical rules() -
            // canonical encoding, not stylistic tidiness.
            if (needsRef) {
                if (r.ref == address(0) || r.value != 0) revert InvalidRule(i);
            } else {
                if (r.ref != address(0)) revert InvalidRule(i);
            }
            if (k == RuleKind.MaxBalanceBps && r.value > 10_000) revert InvalidRule(i);
        }
    }

    /// @dev Recomputes cached summaries of the ACTIVE rule set. Must be called
    ///      after every write to `_rules` and never after a write to
    ///      `_pendingRules` — a proposal must not change evaluation until it
    ///      commits.
    function _refreshCaches() private {
        bool tracks;
        uint256 actions;
        uint256 n = _rules.length;
        for (uint256 i; i < n; ++i) {
            if (_rules[i].kind == RuleKind.MinHoldTime) tracks = true;
            actions |= 1 << uint256(_rules[i].action);
        }
        tracksHoldTime = tracks;
        activeActions = actions;
    }

    /// @dev `delete` cannot be applied to a storage-pointer parameter, so the
    ///      target is cleared by popping.
    function _writeRules(Rule[] storage target, Rule[] memory source) private {
        while (target.length > 0) {
            target.pop();
        }
        for (uint256 i; i < source.length; ++i) {
            target.push(source[i]);
        }
    }
}
