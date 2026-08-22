// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../contracts/token/PolicyERC20.sol";
import "../contracts/engine/PolicyEngine.sol";
import "../contracts/engine/PolicyTypes.sol";
import "../contracts/verification/PolicyVerification.sol";
import "../contracts/verification/CanonicalCode.sol";

contract Registry is IPolicyRegistry {
    mapping(address => bool) public listed;

    function set(address a, bool v) external {
        listed[a] = v;
    }

    function isListed(address a) external view returns (bool) {
        return listed[a];
    }
}

contract Gate is IPolicyGate {
    bool public allow = true;

    function set(bool v) external {
        allow = v;
    }

    function check(TransferContext calldata) external view returns (bool, string memory) {
        return allow ? (true, "") : (false, "gate denied");
    }
}

/**
 * End-to-end proof of the tier-1 claim: a canonical token whose complete
 * transfer policy is enumerable data in a canonical engine.
 *
 * The load-bearing tests are grouped under THE CLAIM. The rest guard the
 * mechanics that make it true.
 */
contract PolicyERC20Test is Test {
    address internal constant ADMIN = address(0xA11CE);
    address internal constant ALICE = address(0xA1);
    address internal constant BOB = address(0xB0);
    address internal constant CAROL = address(0xC0);

    uint256 internal constant DELAY = 7 days;

    Registry internal registry;
    Gate internal gate;

    function setUp() public {
        registry = new Registry();
        gate = new Gate();
    }

    // ---- helpers -----------------------------------------------------------

    function _token(Rule[] memory rules_) internal returns (PolicyERC20 t) {
        t = new PolicyERC20(ADMIN, "Token", "TKN", DELAY, rules_);
        vm.prank(ADMIN);
        t.mint(ALICE, 1_000e18);
    }

    function _noRules() internal pure returns (Rule[] memory) {
        return new Rule[](0);
    }

    function _one(RuleKind kind, uint256 value, address ref) internal pure returns (Rule[] memory rules_) {
        rules_ = new Rule[](1);
        rules_[0] = Rule({kind: kind, value: value, ref: ref, scoped: false, scopeId: 0});
    }

    function _engineOf(PolicyERC20 t) internal view returns (PolicyEngine) {
        return PolicyEngine(t.policy());
    }

    // =========================================================================
    //                               THE CLAIM
    // =========================================================================

    /// The thesis, stated as bytes: two tokens with completely different
    /// policies run byte-identical code, at BOTH layers. Policy varies in
    /// storage; nothing varies in bytecode.
    function test_CLAIM_codehashIdenticalAcrossDifferentPolicies() public {
        PolicyERC20 lenient = _token(_noRules());

        Rule[] memory strict = new Rule[](3);
        strict[0] = Rule(RuleKind.Allowlist, 0, address(registry), false, 0);
        strict[1] = Rule(RuleKind.MaxTransfer, 5e18, address(0), false, 0);
        strict[2] = Rule(RuleKind.LockupUntil, block.timestamp + 365 days, address(0), false, 0);
        PolicyERC20 restricted = _token(strict);

        assertEq(address(lenient).codehash, address(restricted).codehash, "token code must not vary");
        assertEq(
            address(_engineOf(lenient)).codehash, address(_engineOf(restricted)).codehash, "engine code must not vary"
        );

        // And both match what a verifier derives from source at compile time.
        assertEq(address(lenient).codehash, PolicyVerification.canonicalTokenHashERC20());
        assertEq(address(_engineOf(restricted)).codehash, PolicyVerification.canonicalPolicyHash());

        // Yet the policies genuinely differ.
        assertEq(_engineOf(lenient).ruleCount(), 0);
        assertEq(_engineOf(restricted).ruleCount(), 3);
    }

    /// One call answers "under what conditions can this token block me?".
    function test_CLAIM_oneCallEnumeratesTheCompletePolicy() public {
        Rule[] memory input = new Rule[](2);
        input[0] = Rule(RuleKind.MaxTransfer, 100e18, address(0), false, 0);
        input[1] = Rule(RuleKind.MinHoldTime, 1 days, address(0), false, 0);
        PolicyERC20 t = _token(input);

        PolicyVerification.Report memory r = PolicyVerification.verifyERC20(address(t));

        assertTrue(r.tokenCanonical, "entry point must be canonical");
        assertTrue(r.policyCanonical, "engine must be canonical");
        assertTrue(PolicyVerification.isFullyEnumerable(r), "claim must hold");
        assertFalse(r.hasExternalGate);
        assertEq(r.externalRefs.length, 0);
        assertEq(r.swapDelay, DELAY);
        assertEq(r.pendingAt, 0);

        assertEq(r.rules.length, 2);
        assertEq(uint256(r.rules[0].kind), uint256(RuleKind.MaxTransfer));
        assertEq(r.rules[0].value, 100e18);
        assertEq(uint256(r.rules[1].kind), uint256(RuleKind.MinHoldTime));
        assertEq(r.rules[1].value, 1 days);
    }

    /// The claim's teeth: there is NO pause, and no other discretionary lever.
    /// A pause would be a blocking condition outside the rule array, which is
    /// exactly what this design forbids — halting transfers must go through the
    /// timelock like any other rule.
    function test_CLAIM_noDiscretionaryBlockingLeversExist() public {
        PolicyERC20 t = _token(_noRules());

        string[5] memory forbidden =
            ["pause()", "unpause()", "freeze(address)", "blacklist(address)", "setPolicy(address)"];

        for (uint256 i; i < forbidden.length; ++i) {
            (bool ok,) = address(t).call(abi.encodeWithSignature(forbidden[i]));
            assertFalse(ok, forbidden[i]);
        }

        // Even the admin cannot stop a transfer that the policy permits.
        vm.prank(ALICE);
        t.transfer(BOB, 1e18);
        assertEq(t.balanceOf(BOB), 1e18);
    }

    /// A new KIND of condition cannot appear without public notice.
    function test_CLAIM_newConditionRequiresTimelock() public {
        PolicyERC20 t = _token(_noRules());
        PolicyEngine e = _engineOf(t);

        // Freely transferable today.
        vm.prank(ALICE);
        t.transfer(BOB, 10e18);

        // The admin wants to add a freeze. They must announce it first.
        Rule[] memory freeze = _one(RuleKind.Frozen, 0, address(registry));
        vm.prank(ADMIN);
        e.proposeRules(freeze);

        // Notice is public and the policy has NOT changed yet.
        (Rule[] memory pending, uint256 at) = e.pendingRules();
        assertEq(pending.length, 1);
        assertEq(at, block.timestamp + DELAY);
        assertEq(e.ruleCount(), 0, "pending must not affect evaluation");

        registry.set(ALICE, true);
        vm.prank(ALICE);
        t.transfer(BOB, 10e18); // still fine — the rule is not active

        // Cannot be rushed.
        vm.warp(block.timestamp + DELAY - 1);
        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(PolicyEngine.TimelockNotElapsed.selector, at));
        e.commitRules();

        // After the notice window it takes effect.
        vm.warp(at);
        vm.prank(ADMIN);
        e.commitRules();

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "sender frozen"));
        t.transfer(BOB, 1e18);
    }

    /// An unverified entry point makes the whole report meaningless, and the
    /// verifier must say so rather than enumerating rules that describe only
    /// one condition among unknown others.
    function test_CLAIM_nonCanonicalTokenReportsNothing() public {
        PolicyVerification.Report memory r = PolicyVerification.verifyERC20(address(this));

        assertFalse(r.tokenCanonical);
        assertFalse(r.policyCanonical);
        assertFalse(PolicyVerification.isFullyEnumerable(r));
        assertEq(r.rules.length, 0, "must not enumerate an unverified token");
    }

    // =========================================================================
    //                    HONEST REPORTING OF EXTERNAL CODE
    // =========================================================================

    /// A registry-backed rule contains no ExternalGate, yet its verdicts are
    /// controlled by arbitrary code. externalRefs() is what stops that passing
    /// as fully self-contained.
    function test_registryBackedRuleIsReportedAsExternal() public {
        PolicyERC20 t = _token(_one(RuleKind.Allowlist, 0, address(registry)));

        PolicyVerification.Report memory r = PolicyVerification.verifyERC20(address(t));

        assertFalse(r.hasExternalGate, "an allowlist is not an arbitrary-code gate");
        assertEq(r.externalRefs.length, 1, "but it IS an external dependency");
        assertEq(r.externalRefs[0], address(registry));

        // The condition is fixed and enumerable, so the claim still holds...
        assertTrue(PolicyVerification.isFullyEnumerable(r));
        // ...but membership is arbitrary and instantly mutable, with no notice.
        registry.set(ALICE, true);
        registry.set(BOB, true);
        vm.prank(ALICE);
        t.transfer(BOB, 1e18);

        registry.set(BOB, false);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "recipient not allowlisted"));
        t.transfer(BOB, 1e18);
    }

    function test_externalGateBreaksTheEnumerabilityClaim() public {
        PolicyERC20 t = _token(_one(RuleKind.ExternalGate, 0, address(gate)));

        PolicyVerification.Report memory r = PolicyVerification.verifyERC20(address(t));

        assertTrue(r.tokenCanonical);
        assertTrue(r.policyCanonical);
        assertTrue(r.hasExternalGate);
        assertFalse(PolicyVerification.isFullyEnumerable(r), "a gate must void the claim");
        assertEq(r.externalRefs[0], address(gate));
    }

    // =========================================================================
    //                          POLICY ENFORCEMENT
    // =========================================================================

    function test_transferSucceedsWhenPolicyIsEmpty() public {
        PolicyERC20 t = _token(_noRules());

        vm.prank(ALICE);
        assertTrue(t.transfer(BOB, 100e18));
        assertEq(t.balanceOf(ALICE), 900e18);
        assertEq(t.balanceOf(BOB), 100e18);
    }

    function test_maxTransferDeniesAndNamesTheRule() public {
        PolicyERC20 t = _token(_one(RuleKind.MaxTransfer, 5e18, address(0)));

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "exceeds max transfer"));
        t.transfer(BOB, 6e18);

        vm.prank(ALICE);
        t.transfer(BOB, 5e18);
        assertEq(t.balanceOf(BOB), 5e18);
    }

    function test_maxBalanceUsesPreTransferBalances() public {
        PolicyERC20 t = _token(_one(RuleKind.MaxBalance, 10e18, address(0)));

        vm.prank(ALICE);
        t.transfer(BOB, 10e18);

        // Exactly at the cap; one more wei must fail. If the token pushed
        // POST-transfer balances the arithmetic here would double-count.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "exceeds max balance"));
        t.transfer(BOB, 1);
    }

    function test_lockupBlocksUntilTimestamp() public {
        uint256 until = block.timestamp + 30 days;
        PolicyERC20 t = _token(_one(RuleKind.LockupUntil, until, address(0)));

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "locked up"));
        t.transfer(BOB, 1e18);

        vm.warp(until);
        vm.prank(ALICE);
        t.transfer(BOB, 1e18);
        assertEq(t.balanceOf(BOB), 1e18);
    }

    function test_holderCapCountsDistinctHolders() public {
        PolicyERC20 t = _token(_one(RuleKind.HolderCap, 2, address(0)));
        assertEq(t.holderCount(), 1, "alice only");

        vm.prank(ALICE);
        t.transfer(BOB, 1e18);
        assertEq(t.holderCount(), 2);

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "holder cap reached"));
        t.transfer(CAROL, 1e18);

        // Topping up an EXISTING holder is fine — no new holder is created.
        vm.prank(ALICE);
        t.transfer(BOB, 1e18);
        assertEq(t.balanceOf(BOB), 2e18);
    }

    function test_holderCountDecrementsWhenBalanceEmpties() public {
        PolicyERC20 t = _token(_noRules());

        vm.prank(ALICE);
        t.transfer(BOB, 1_000e18);

        assertEq(t.holderCount(), 1, "alice emptied, bob created");
        assertEq(t.balanceOf(ALICE), 0);
    }

    function test_minHoldTimeBlocksThenAllows() public {
        PolicyERC20 t = _token(_one(RuleKind.MinHoldTime, 1 days, address(0)));

        vm.prank(ALICE);
        t.transfer(BOB, 10e18);

        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "min hold time"));
        t.transfer(CAROL, 1e18);

        vm.warp(block.timestamp + 1 days);
        vm.prank(BOB);
        t.transfer(CAROL, 1e18);
        assertEq(t.balanceOf(CAROL), 1e18);
    }

    /// The engine only maintains hold-time state when a rule actually reads it.
    function test_holdTimeStateOnlyTrackedWhenARuleNeedsIt() public {
        PolicyERC20 plain = _token(_noRules());
        assertFalse(_engineOf(plain).tracksHoldTime());

        vm.prank(ALICE);
        plain.transfer(BOB, 1e18);
        assertEq(_engineOf(plain).lastReceived(BOB), 0, "must not write unread state");

        PolicyERC20 held = _token(_one(RuleKind.MinHoldTime, 1 days, address(0)));
        assertTrue(_engineOf(held).tracksHoldTime());

        vm.prank(ALICE);
        held.transfer(BOB, 1e18);
        assertEq(_engineOf(held).lastReceived(BOB), block.timestamp);
    }

    function test_rulesAreAndedAndFirstFailureNamesItself() public {
        Rule[] memory both = new Rule[](2);
        both[0] = Rule(RuleKind.MaxTransfer, 5e18, address(0), false, 0);
        both[1] = Rule(RuleKind.LockupUntil, block.timestamp + 1 days, address(0), false, 0);
        PolicyERC20 t = _token(both);

        // Passes rule 0, fails rule 1.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "locked up"));
        t.transfer(BOB, 1e18);

        // Fails rule 0 first, and says so.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "exceeds max transfer"));
        t.transfer(BOB, 6e18);
    }

    function test_canTransferPreviewsWithoutStateChange() public {
        PolicyERC20 t = _token(_one(RuleKind.MaxTransfer, 5e18, address(0)));

        (bool ok, string memory reason) = t.canTransfer(ALICE, BOB, 6e18);
        assertFalse(ok);
        assertEq(reason, "exceeds max transfer");

        (ok, reason) = t.canTransfer(ALICE, BOB, 5e18);
        assertTrue(ok);
        assertEq(t.balanceOf(BOB), 0, "preview must not move anything");
    }

    // =========================================================================
    //                        WIRING AND STRUCTURE
    // =========================================================================

    /// The token deploys its own engine, so there is no window in which it
    /// exists unpoliced and no setter by which the policy could be swapped.
    function test_engineIsDeployedByTheTokenAtConstruction() public {
        PolicyERC20 t = _token(_noRules());
        PolicyEngine e = _engineOf(t);

        assertTrue(address(e) != address(0));
        assertEq(e.notifier(), address(t), "the token is the only notifier");
        assertEq(e.admin(), ADMIN);
        assertEq(e.swapDelay(), DELAY);
    }

    /// Only the token may record settled transfers.
    function test_recordTransferRejectsEveryoneButTheToken() public {
        PolicyERC20 t = _token(_one(RuleKind.MinHoldTime, 1 days, address(0)));
        PolicyEngine e = _engineOf(t);

        TransferContext memory ctx = TransferContext({
            standard: TokenStandard.ERC20,
            from: ALICE,
            to: BOB,
            id: 0,
            amount: 1e18,
            fromBalance: 0,
            toBalance: 0,
            totalSupply: 0,
            holderCount: 0
        });

        vm.prank(ALICE);
        vm.expectRevert(PolicyEngine.NotNotifier.selector);
        e.recordTransfer(ctx);
    }

    /// Each token gets its own engine even though both are canonical — the
    /// CREATE2 salt is constant, but the deployer differs.
    function test_eachTokenGetsItsOwnEngine() public {
        PolicyERC20 a = _token(_noRules());
        PolicyERC20 b = _token(_noRules());

        assertTrue(a.policy() != b.policy());
        assertEq(address(_engineOf(a)).codehash, address(_engineOf(b)).codehash);
    }

    /// Admin handover moves the token's admin only; the engine keeps its own,
    /// and a report should show both rather than assuming they agree.
    function test_tokenAndEngineAdminsAreSeparate() public {
        PolicyERC20 t = _token(_noRules());

        vm.prank(ADMIN);
        t.transferIssuerAdmin(BOB);

        assertEq(t.issuerAdmin(), BOB);
        assertEq(t.deployAdmin(), ADMIN, "deploy admin must be permanent");
        assertEq(_engineOf(t).admin(), ADMIN, "engine admin is unaffected");
    }

    // =========================================================================
    //                          ERC-20 CONFORMANCE
    // =========================================================================

    function test_zeroValueTransferSucceeds() public {
        PolicyERC20 t = _token(_noRules());

        vm.prank(ALICE);
        assertTrue(t.transfer(BOB, 0));
        assertEq(t.holderCount(), 1, "a zero transfer creates no holder");
    }

    function test_transferFromSpendsAllowance() public {
        PolicyERC20 t = _token(_noRules());

        vm.prank(ALICE);
        t.approve(BOB, 50e18);

        vm.prank(BOB);
        t.transferFrom(ALICE, CAROL, 20e18);

        assertEq(t.allowance(ALICE, BOB), 30e18);
        assertEq(t.balanceOf(CAROL), 20e18);
    }

    function test_infiniteAllowanceIsNotDecremented() public {
        PolicyERC20 t = _token(_noRules());

        vm.prank(ALICE);
        t.approve(BOB, type(uint256).max);

        vm.prank(BOB);
        t.transferFrom(ALICE, CAROL, 20e18);

        assertEq(t.allowance(ALICE, BOB), type(uint256).max);
    }

    function test_transferFromIsPolicyGatedToo() public {
        PolicyERC20 t = _token(_one(RuleKind.MaxTransfer, 5e18, address(0)));

        vm.prank(ALICE);
        t.approve(BOB, 100e18);

        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "exceeds max transfer"));
        t.transferFrom(ALICE, CAROL, 6e18);
    }

    function test_revertsOnInsufficientBalanceAndAllowance() public {
        PolicyERC20 t = _token(_noRules());

        vm.prank(ALICE);
        vm.expectRevert(InsufficientBalance.selector);
        t.transfer(BOB, 2_000e18);

        vm.prank(BOB);
        vm.expectRevert(InsufficientAllowance.selector);
        t.transferFrom(ALICE, CAROL, 1e18);
    }

    function test_revertsOnZeroRecipient() public {
        PolicyERC20 t = _token(_noRules());

        vm.prank(ALICE);
        vm.expectRevert(ZeroAddress.selector);
        t.transfer(address(0), 1e18);
    }

    function test_selfTransferPreservesBalanceAndHolderCount() public {
        PolicyERC20 t = _token(_noRules());

        vm.prank(ALICE);
        t.transfer(ALICE, 100e18);

        assertEq(t.balanceOf(ALICE), 1_000e18, "self-transfer must not corrupt balance");
        assertEq(t.holderCount(), 1);
    }

    function test_mintAndBurnAreIssuerAdminOnly() public {
        PolicyERC20 t = _token(_noRules());

        vm.prank(ALICE);
        vm.expectRevert(NotIssuerAdmin.selector);
        t.mint(ALICE, 1e18);

        vm.prank(ALICE);
        vm.expectRevert(NotIssuerAdmin.selector);
        t.burn(ALICE, 1e18);

        vm.prank(ADMIN);
        t.burn(ALICE, 1_000e18);
        assertEq(t.totalSupply(), 0);
        assertEq(t.holderCount(), 0);
    }

    /// Mint and burn are outside the policy by design — the issuer already
    /// controls supply unconditionally, so gating them adds nothing a holder
    /// could rely on, and a lockup would make distribution impossible.
    function test_mintIsNotPolicyGated() public {
        PolicyERC20 t = _token(_one(RuleKind.LockupUntil, block.timestamp + 365 days, address(0)));

        vm.prank(ADMIN);
        t.mint(BOB, 1e18);
        assertEq(t.balanceOf(BOB), 1e18);

        // But transfers are still locked.
        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(PolicyERC20.PolicyDenied.selector, "locked up"));
        t.transfer(CAROL, 1);
    }
}
