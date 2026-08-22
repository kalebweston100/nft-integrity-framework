// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../contracts/engine/PolicyEngine.sol";
import "../contracts/engine/PolicyTypes.sol";
import "../contracts/verification/CanonicalCode.sol";

contract MockRegistry is IPolicyRegistry {
    mapping(address => bool) public listed;

    function set(address a, bool v) external {
        listed[a] = v;
    }

    function isListed(address a) external view returns (bool) {
        return listed[a];
    }
}

contract MockGate is IPolicyGate {
    bool public allow = true;

    function set(bool v) external {
        allow = v;
    }

    function check(TransferContext calldata) external view returns (bool, string memory) {
        return allow ? (true, "") : (false, "gate denied");
    }
}

contract RevertingGate is IPolicyGate {
    function check(TransferContext calldata) external pure returns (bool, string memory) {
        revert("boom");
    }
}

contract PolicyEngineTest is Test {
    address internal constant ADMIN = address(0xA11CE);
    address internal constant WRAPPER = address(0x3333);
    address internal constant ALICE = address(0xA1);
    address internal constant BOB = address(0xB0);

    uint256 internal constant DELAY = 30 days;

    MockRegistry internal registry;
    MockGate internal gate;

    function setUp() public {
        registry = new MockRegistry();
        gate = new MockGate();
    }

    // ---- helpers -----------------------------------------------------------

    function _engine(Rule[] memory rules_) internal returns (PolicyEngine) {
        return new PolicyEngine(ADMIN, WRAPPER, DELAY, rules_);
    }

    function _one(Rule memory r) internal pure returns (Rule[] memory out) {
        out = new Rule[](1);
        out[0] = r;
    }

    function _rule(RuleKind k, uint256 v, address ref) internal pure returns (Rule memory) {
        return Rule({kind: k, value: v, ref: ref, scoped: false, scopeId: 0});
    }

    function _ctx(address from, address to, uint256 amount) internal pure returns (TransferContext memory) {
        return TransferContext({
            standard: TokenStandard.ERC20,
            from: from,
            to: to,
            id: 0,
            amount: amount,
            fromBalance: 1_000,
            toBalance: 0,
            totalSupply: 10_000,
            holderCount: 5
        });
    }

    // =========================================================================
    //   THE CORE PROPERTY — one canonical hash across every configuration
    // =========================================================================

    /// @notice Policy is data, so two engines with completely different rules
    ///         are byte-identical. This is what makes the policy layer
    ///         hash-verifiable at all, and it compiles ONLY because the
    ///         contract holds zero immutables.
    function test_codehash_identicalAcrossDifferentPolicies() public {
        Rule[] memory a = _one(_rule(RuleKind.LockupUntil, block.timestamp + 365 days, address(0)));

        Rule[] memory b = new Rule[](3);
        b[0] = _rule(RuleKind.Allowlist, 0, address(registry));
        b[1] = _rule(RuleKind.MaxTransfer, 42, address(0));
        b[2] = _rule(RuleKind.ExternalGate, 0, address(gate));

        PolicyEngine e1 = _engine(a);
        PolicyEngine e2 = _engine(b);

        bytes32 canonical = keccak256(type(PolicyEngine).runtimeCode);

        assertEq(address(e1).codehash, address(e2).codehash, "different rules, identical code");
        assertTrue(CanonicalCode.isCanonical(address(e1), canonical));
        assertTrue(CanonicalCode.isCanonical(address(e2), canonical));
    }

    /// @notice The rules are readable, so an integrator can render the complete
    ///         policy — and the canonical codehash is what proves the list is
    ///         exhaustive.
    function test_rules_areEnumerable() public {
        Rule[] memory r = new Rule[](2);
        r[0] = _rule(RuleKind.Allowlist, 0, address(registry));
        r[1] = _rule(RuleKind.MaxBalanceBps, 1_000, address(0));

        PolicyEngine e = _engine(r);
        Rule[] memory got = e.rules();

        assertEq(got.length, 2);
        assertEq(uint256(got[0].kind), uint256(RuleKind.Allowlist));
        assertEq(got[1].value, 1_000);
        assertEq(e.ruleCount(), 2);
    }

    function test_hasExternalGate_flagsArbitraryCode() public {
        assertFalse(_engine(_one(_rule(RuleKind.MaxTransfer, 1, address(0)))).hasExternalGate());
        assertTrue(_engine(_one(_rule(RuleKind.ExternalGate, 0, address(gate)))).hasExternalGate());
    }

    // =========================================================================
    //   EVALUATION — each rule kind, allow and deny
    // =========================================================================

    function test_emptyPolicy_allowsEverything() public {
        PolicyEngine e = _engine(new Rule[](0));
        (bool ok,) = e.evaluate(_ctx(ALICE, BOB, 100));
        assertTrue(ok);
    }

    function test_allowlist() public {
        PolicyEngine e = _engine(_one(_rule(RuleKind.Allowlist, 0, address(registry))));

        (bool ok, string memory why) = e.evaluate(_ctx(ALICE, BOB, 100));
        assertFalse(ok);
        assertEq(why, "sender not allowlisted");

        registry.set(ALICE, true);
        (ok, why) = e.evaluate(_ctx(ALICE, BOB, 100));
        assertEq(why, "recipient not allowlisted");

        registry.set(BOB, true);
        (ok,) = e.evaluate(_ctx(ALICE, BOB, 100));
        assertTrue(ok);
    }

    /// @notice Mint and burn must not be blocked by membership rules.
    function test_allowlist_skipsZeroAddress() public {
        PolicyEngine e = _engine(_one(_rule(RuleKind.Allowlist, 0, address(registry))));
        registry.set(BOB, true);

        (bool ok,) = e.evaluate(_ctx(address(0), BOB, 100)); // mint
        assertTrue(ok, "mint not blocked");

        registry.set(ALICE, true);
        (ok,) = e.evaluate(_ctx(ALICE, address(0), 100)); // burn
        assertTrue(ok, "burn not blocked");
    }

    function test_blocklistAndFrozen() public {
        PolicyEngine block_ = _engine(_one(_rule(RuleKind.Blocklist, 0, address(registry))));
        PolicyEngine frozen = _engine(_one(_rule(RuleKind.Frozen, 0, address(registry))));

        (bool ok,) = block_.evaluate(_ctx(ALICE, BOB, 100));
        assertTrue(ok);

        registry.set(ALICE, true);
        string memory why;
        (ok, why) = block_.evaluate(_ctx(ALICE, BOB, 100));
        assertFalse(ok);
        assertEq(why, "sender blocklisted");

        (ok, why) = frozen.evaluate(_ctx(ALICE, BOB, 100));
        assertEq(why, "sender frozen");
    }

    function test_lockupUntil() public {
        PolicyEngine e = _engine(_one(_rule(RuleKind.LockupUntil, block.timestamp + 1 days, address(0))));

        (bool ok, string memory why) = e.evaluate(_ctx(ALICE, BOB, 1));
        assertFalse(ok);
        assertEq(why, "locked up");

        vm.warp(block.timestamp + 1 days);
        (ok,) = e.evaluate(_ctx(ALICE, BOB, 1));
        assertTrue(ok);
    }

    function test_maxTransfer() public {
        PolicyEngine e = _engine(_one(_rule(RuleKind.MaxTransfer, 100, address(0))));

        (bool ok,) = e.evaluate(_ctx(ALICE, BOB, 100));
        assertTrue(ok);

        (ok,) = e.evaluate(_ctx(ALICE, BOB, 101));
        assertFalse(ok);
    }

    function test_maxBalance_usesPostTransferBalance() public {
        PolicyEngine e = _engine(_one(_rule(RuleKind.MaxBalance, 500, address(0))));

        TransferContext memory c = _ctx(ALICE, BOB, 100);
        c.toBalance = 400;
        (bool ok,) = e.evaluate(c);
        assertTrue(ok, "400 + 100 == cap");

        c.toBalance = 401;
        (ok,) = e.evaluate(c);
        assertFalse(ok, "401 + 100 > cap");
    }

    function test_maxBalanceBps() public {
        // 10% of a 10_000 supply == 1_000.
        PolicyEngine e = _engine(_one(_rule(RuleKind.MaxBalanceBps, 1_000, address(0))));

        TransferContext memory c = _ctx(ALICE, BOB, 1_000);
        (bool ok,) = e.evaluate(c);
        assertTrue(ok);

        c.amount = 1_001;
        (ok,) = e.evaluate(c);
        assertFalse(ok);
    }

    function test_holderCap_onlyCountsNewHolders() public {
        PolicyEngine e = _engine(_one(_rule(RuleKind.HolderCap, 5, address(0))));

        TransferContext memory c = _ctx(ALICE, BOB, 100); // holderCount 5, toBalance 0
        (bool ok,) = e.evaluate(c);
        assertFalse(ok, "new holder would exceed the cap");

        c.toBalance = 1; // already a holder
        (ok,) = e.evaluate(c);
        assertTrue(ok, "existing holder does not raise the count");
    }

    function test_minHoldTime_usesRecordedReceipt() public {
        PolicyEngine e = _engine(_one(_rule(RuleKind.MinHoldTime, 7 days, address(0))));

        // Nothing recorded yet — nothing to enforce.
        (bool ok,) = e.evaluate(_ctx(ALICE, BOB, 1));
        assertTrue(ok);

        vm.prank(WRAPPER);
        e.recordTransfer(_ctx(address(0), ALICE, 100));

        (ok,) = e.evaluate(_ctx(ALICE, BOB, 1));
        assertFalse(ok, "still inside the holding period");

        vm.warp(block.timestamp + 7 days);
        (ok,) = e.evaluate(_ctx(ALICE, BOB, 1));
        assertTrue(ok);
    }

    function test_recordTransfer_isNotifierOnly() public {
        PolicyEngine e = _engine(new Rule[](0));

        vm.expectRevert(PolicyEngine.NotNotifier.selector);
        e.recordTransfer(_ctx(address(0), ALICE, 1));
    }

    // =========================================================================
    //   ERC-1155 SCOPING
    // =========================================================================

    function test_scopedRule_appliesOnlyToItsTokenId() public {
        Rule[] memory r = _one(Rule({kind: RuleKind.MaxTransfer, value: 10, ref: address(0), scoped: true, scopeId: 7}));
        PolicyEngine e = _engine(r);

        TransferContext memory c = _ctx(ALICE, BOB, 100);
        c.standard = TokenStandard.ERC1155;

        c.id = 7;
        (bool ok,) = e.evaluate(c);
        assertFalse(ok, "rule applies to id 7");

        c.id = 8;
        (ok,) = e.evaluate(c);
        assertTrue(ok, "and is skipped for every other id");
    }

    // =========================================================================
    //   THE ESCAPE HATCH
    // =========================================================================

    function test_externalGate_delegatesAndFailsClosed() public {
        PolicyEngine e = _engine(_one(_rule(RuleKind.ExternalGate, 0, address(gate))));

        (bool ok,) = e.evaluate(_ctx(ALICE, BOB, 1));
        assertTrue(ok);

        gate.set(false);
        string memory why;
        (ok, why) = e.evaluate(_ctx(ALICE, BOB, 1));
        assertFalse(ok);
        assertEq(why, "gate denied");
    }

    function test_externalGate_revertIsDenial() public {
        PolicyEngine e = _engine(_one(_rule(RuleKind.ExternalGate, 0, address(new RevertingGate()))));

        (bool ok, string memory why) = e.evaluate(_ctx(ALICE, BOB, 1));
        assertFalse(ok, "fails closed");
        assertEq(why, "external gate reverted");
    }

    // =========================================================================
    //   TIMELOCK — the only way policy can ever change
    // =========================================================================

    function test_proposeThenCommit_requiresTheFullDelay() public {
        PolicyEngine e = _engine(new Rule[](0));
        Rule[] memory next = _one(_rule(RuleKind.MaxTransfer, 5, address(0)));

        vm.prank(ADMIN);
        e.proposeRules(next);

        (Rule[] memory pending, uint256 at) = e.pendingRules();
        assertEq(pending.length, 1);
        assertEq(at, block.timestamp + DELAY);

        vm.warp(block.timestamp + DELAY - 1);
        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(PolicyEngine.TimelockNotElapsed.selector, at));
        e.commitRules();

        // The live policy is untouched while a change is pending.
        (bool ok,) = e.evaluate(_ctx(ALICE, BOB, 1_000_000));
        assertTrue(ok);

        vm.warp(at);
        vm.prank(ADMIN);
        e.commitRules();

        assertEq(e.ruleCount(), 1);
        (ok,) = e.evaluate(_ctx(ALICE, BOB, 1_000_000));
        assertFalse(ok, "new policy is live");
    }

    function test_cancelRules_discardsTheProposal() public {
        PolicyEngine e = _engine(new Rule[](0));

        vm.startPrank(ADMIN);
        e.proposeRules(_one(_rule(RuleKind.MaxTransfer, 5, address(0))));
        e.cancelRules();
        vm.stopPrank();

        (, uint256 at) = e.pendingRules();
        assertEq(at, 0);
        assertEq(e.ruleCount(), 0);
    }

    function test_onlyOneProposalAtATime() public {
        PolicyEngine e = _engine(new Rule[](0));
        Rule[] memory next = _one(_rule(RuleKind.MaxTransfer, 5, address(0)));

        vm.startPrank(ADMIN);
        e.proposeRules(next);
        vm.expectRevert(PolicyEngine.RulesPending.selector);
        e.proposeRules(next);
        vm.stopPrank();
    }

    function test_ruleChanges_areAdminOnly() public {
        PolicyEngine e = _engine(new Rule[](0));

        vm.expectRevert(PolicyEngine.NotAdmin.selector);
        e.proposeRules(_one(_rule(RuleKind.MaxTransfer, 5, address(0))));

        vm.expectRevert(PolicyEngine.NotAdmin.selector);
        e.commitRules();
    }

    /// @notice The delay is written once in the constructor with no setter, so
    ///         a policy cannot shorten its own notice period.
    function test_swapDelay_hasNoSetter() public {
        PolicyEngine e = _engine(new Rule[](0));
        assertEq(e.swapDelay(), DELAY);

        // No selector exists to change it.
        (bool hit,) = address(e).call(abi.encodeWithSignature("setSwapDelay(uint256)", 0));
        assertFalse(hit);
    }

    // =========================================================================
    //   VALIDATION
    // =========================================================================

    function test_rejectsRuleWithMissingRegistry() public {
        PolicyEngine e = _engine(new Rule[](0));

        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(PolicyEngine.InvalidRule.selector, 0));
        e.proposeRules(_one(_rule(RuleKind.Allowlist, 0, address(0))));
    }

    function test_rejectsOutOfRangeBps() public {
        PolicyEngine e = _engine(new Rule[](0));

        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(PolicyEngine.InvalidRule.selector, 0));
        e.proposeRules(_one(_rule(RuleKind.MaxBalanceBps, 10_001, address(0))));
    }

    // =========================================================================
    //   COMPOSITION
    // =========================================================================

    /// @notice Rules are ANDed and the first failure names itself.
    function test_rulesAreAnded_firstFailureWins() public {
        Rule[] memory r = new Rule[](2);
        r[0] = _rule(RuleKind.MaxTransfer, 50, address(0));
        r[1] = _rule(RuleKind.Allowlist, 0, address(registry));

        PolicyEngine e = _engine(r);

        (bool ok, string memory why) = e.evaluate(_ctx(ALICE, BOB, 100));
        assertFalse(ok);
        assertEq(why, "exceeds max transfer", "earlier rule reports first");

        registry.set(ALICE, true);
        registry.set(BOB, true);
        (ok,) = e.evaluate(_ctx(ALICE, BOB, 10));
        assertTrue(ok, "both satisfied");
    }
}
