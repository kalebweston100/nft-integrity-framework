// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../contracts/token/PolicyERC20.sol";
import "../contracts/token/PolicyERC721.sol";
import "../contracts/token/PolicyERC1155.sol";
import "../contracts/token/PolicyTokenBase.sol";
import "../contracts/engine/PolicyEngine.sol";
import "../contracts/engine/PolicyTypes.sol";
import "../contracts/verification/PolicyVerification.sol";

contract Reg is IPolicyRegistry {
    mapping(address => bool) public listed;

    function set(address a, bool v) external {
        listed[a] = v;
    }

    function isListed(address a) external view returns (bool) {
        return listed[a];
    }
}

/**
 * @notice The policy governs EVERY entry point, not just transfers.
 *
 * The point of this suite is not that more things can be blocked — it is that
 * the mint/burn carve-out is gone. A carve-out is where a claim goes to die:
 * the burn(address,uint256) confiscation hole lived inside exactly that
 * exemption. With every action routed through the same enumerable policy, the
 * claim is total over the ABI rather than scoped to one function.
 */
contract PerActionPolicyTest is Test {
    address internal constant ADMIN = address(0xA11CE);
    address internal constant ALICE = address(0xA);
    address internal constant BOB = address(0xB);
    address internal constant CAROL = address(0xC);

    uint256 internal constant DELAY = 7 days;

    function _rules(Action a, RuleKind k, uint256 v, address ref) internal pure returns (Rule[] memory rs) {
        rs = new Rule[](1);
        rs[0] = Rule({action: a, kind: k, value: v, ref: ref, scoped: false, scopeId: 0});
    }

    function _none() internal pure returns (Rule[] memory) {
        return new Rule[](0);
    }

    function _erc20(Rule[] memory rs) internal returns (PolicyERC20 t) {
        t = new PolicyERC20(ADMIN, "T", "T", 18, DELAY, rs);
    }

    function _denied(string memory reason) internal {
        vm.expectRevert(abi.encodeWithSelector(PolicyTokenBase.PolicyDenied.selector, reason));
    }

    // =========================================================================
    //                     EVERY ACTION IS ACTUALLY GATED
    // =========================================================================

    function test_mintIsGated() public {
        Reg reg = new Reg();
        PolicyERC20 t = _erc20(_rules(Action.Mint, RuleKind.Allowlist, 0, address(reg)));

        vm.prank(ADMIN);
        _denied("recipient not allowlisted");
        t.mint(ALICE, 1e18);

        reg.set(ALICE, true);
        vm.prank(ADMIN);
        t.mint(ALICE, 1e18);
        assertEq(t.balanceOf(ALICE), 1e18);
    }

    /// Supply caps become a policy any holder can read in advance, rather than
    /// a promise in a whitepaper.
    function test_mintCapIsEnumerable() public {
        PolicyERC20 t = _erc20(_rules(Action.Mint, RuleKind.MaxTransfer, 100e18, address(0)));

        vm.prank(ADMIN);
        _denied("exceeds max transfer");
        t.mint(ALICE, 101e18);

        vm.prank(ADMIN);
        t.mint(ALICE, 100e18);
    }

    function test_approveIsGated() public {
        Reg reg = new Reg();
        PolicyERC20 t = _erc20(_rules(Action.Approve, RuleKind.Allowlist, 0, address(reg)));
        reg.set(ALICE, true);

        vm.prank(ALICE);
        _denied("recipient not allowlisted");
        t.approve(BOB, 1e18);

        reg.set(BOB, true);
        vm.prank(ALICE);
        t.approve(BOB, 1e18);
        assertEq(t.allowance(ALICE, BOB), 1e18);
    }

    function test_burnIsGated() public {
        PolicyERC20 t = _erc20(_rules(Action.Burn, RuleKind.LockupUntil, block.timestamp + 30 days, address(0)));

        vm.prank(ADMIN);
        t.mint(ALICE, 10e18);

        vm.prank(ALICE);
        _denied("locked up");
        t.burn(1e18);

        vm.warp(block.timestamp + 31 days);
        vm.prank(ALICE);
        t.burn(1e18);
        assertEq(t.totalSupply(), 9e18);
    }

    function test_setOperatorIsGated_erc721() public {
        Reg reg = new Reg();
        Rule[] memory rs = _rules(Action.SetOperator, RuleKind.Allowlist, 0, address(reg));
        PolicyERC721 t = new PolicyERC721(ADMIN, "C", "C", "ipfs://", DELAY, rs);
        reg.set(ALICE, true);

        vm.prank(ADMIN);
        t.mint(ALICE, 1);

        // An operator allowlist, expressed honestly: enumerable, and it took
        // the notice period to appear. This is the operator filter done in the
        // open rather than as a silent modifier.
        vm.prank(ALICE);
        _denied("recipient not allowlisted");
        t.setApprovalForAll(BOB, true);

        reg.set(BOB, true);
        vm.prank(ALICE);
        t.setApprovalForAll(BOB, true);
        assertTrue(t.isApprovedForAll(ALICE, BOB));
    }

    function test_mintIsGated_erc1155_perItemInBatch() public {
        Rule[] memory rs = _rules(Action.Mint, RuleKind.MaxTransfer, 50, address(0));
        PolicyERC1155 t = new PolicyERC1155(ADMIN, "u", DELAY, rs);

        uint256[] memory ids = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;
        uint256[] memory amts = new uint256[](2);
        amts[0] = 50;
        amts[1] = 51; // second item breaches the cap

        vm.prank(ADMIN);
        _denied("exceeds max transfer");
        t.mintBatch(ALICE, ids, amts);

        assertEq(t.balanceOf(ALICE, 1), 0, "the whole call reverted");
    }

    // =========================================================================
    //                      THE STRUCTURAL EXEMPTIONS
    // =========================================================================

    /// A policy able to stop you LOWERING an approval could pin you to it.
    function test_CLAIM_reducingAnAllowanceIsNeverGated() public {
        Reg reg = new Reg();
        PolicyERC20 t = _erc20(_rules(Action.Approve, RuleKind.Allowlist, 0, address(reg)));
        reg.set(ALICE, true);
        reg.set(BOB, true);

        vm.prank(ALICE);
        t.approve(BOB, 100e18);

        // Bob falls off the allowlist. Alice must still be able to withdraw.
        reg.set(BOB, false);

        vm.prank(ALICE);
        t.approve(BOB, 0);
        assertEq(t.allowance(ALICE, BOB), 0, "de-risking must always succeed");
    }

    /// Stopping you REMOVING an operator is strictly worse than stopping you
    /// adding one.
    function test_CLAIM_revokingAnOperatorIsNeverGated() public {
        Reg reg = new Reg();
        Rule[] memory rs = _rules(Action.SetOperator, RuleKind.Allowlist, 0, address(reg));
        PolicyERC721 t = new PolicyERC721(ADMIN, "C", "C", "ipfs://", DELAY, rs);
        reg.set(ALICE, true);
        reg.set(BOB, true);

        vm.prank(ALICE);
        t.setApprovalForAll(BOB, true);

        reg.set(ALICE, false); // Alice herself is now delisted

        vm.prank(ALICE);
        t.setApprovalForAll(BOB, false);
        assertFalse(t.isApprovedForAll(ALICE, BOB), "revocation must always succeed");
    }

    // =========================================================================
    //                        ACTIONS ARE ISOLATED
    // =========================================================================

    /// A rule on one entry point must not leak into another. This is what makes
    /// each row of the policy independently meaningful.
    function test_transferRuleDoesNotBlockMintOrBurn() public {
        PolicyERC20 t = _erc20(_rules(Action.Transfer, RuleKind.LockupUntil, block.timestamp + 365 days, address(0)));

        vm.prank(ADMIN);
        t.mint(ALICE, 10e18); // mint is a different action

        vm.prank(ALICE);
        t.burn(1e18); // so is burn

        vm.prank(ALICE);
        _denied("locked up");
        t.transfer(BOB, 1e18);
    }

    function test_activeActionsReportsOnlyGovernedEntryPoints() public {
        PolicyERC20 t = _erc20(_rules(Action.Mint, RuleKind.HolderCap, 5, address(0)));
        PolicyEngine e = PolicyEngine(t.policy());

        assertEq(e.activeActions(), 1 << uint256(Action.Mint));
        assertEq(e.rulesFor(Action.Mint).length, 1);
        assertEq(e.rulesFor(Action.Transfer).length, 0);
    }

    // =========================================================================
    //              THE PERMANENT ENVELOPE — allowedKinds
    // =========================================================================

    /// These are rejected because they would SILENTLY MISBEHAVE, not merely be
    /// useless: HolderCap on Burn sees to == address(0), so toBalance is 0 and
    /// it fires on every burn.
    function test_CLAIM_nonsensicalPairingsCannotBeDeployed() public {
        vm.expectRevert(
            abi.encodeWithSelector(PolicyEngine.KindNotAllowedForAction.selector, 0, Action.Burn, RuleKind.HolderCap)
        );
        _erc20(_rules(Action.Burn, RuleKind.HolderCap, 5, address(0)));

        vm.expectRevert();
        _erc20(_rules(Action.Burn, RuleKind.MaxBalance, 5, address(0)));

        vm.expectRevert();
        _erc20(_rules(Action.Mint, RuleKind.MinHoldTime, 1 days, address(0)));

        vm.expectRevert();
        _erc20(_rules(Action.SetOperator, RuleKind.MaxTransfer, 5, address(0)));
    }

    function test_CLAIM_nonsensicalPairingsCannotBeProposedEither() public {
        PolicyERC20 t = _erc20(_none());
        PolicyEngine e = PolicyEngine(t.policy());

        vm.prank(ADMIN);
        vm.expectRevert();
        e.proposeRules(_rules(Action.Burn, RuleKind.HolderCap, 5, address(0)));
    }

    /// The claim the timelock cannot make. `allowedKinds` is `pure`, so this is
    /// a bound on every policy this engine could EVER hold — not a description
    /// of the one it holds now.
    function test_CLAIM_envelopeIsPermanentNotCurrent() public {
        PolicyERC20 t = _erc20(_none());
        PolicyVerification.Report memory r = PolicyVerification.verify(address(t));

        assertTrue(PolicyVerification.isUnconditional(r), "nothing gates anything today");

        // ...and minting can never be gated on how long someone has held.
        assertFalse(PolicyVerification.canEverApply(r, Action.Mint, RuleKind.MinHoldTime));
        assertFalse(PolicyVerification.canEverApply(r, Action.Burn, RuleKind.HolderCap));

        // ...while these remain possible, subject to the notice period.
        assertTrue(PolicyVerification.canEverApply(r, Action.Transfer, RuleKind.LockupUntil));
        assertTrue(PolicyVerification.canEverApply(r, Action.Mint, RuleKind.HolderCap));
    }

    // =========================================================================
    //                      FIELD SCHEMA IS ENFORCED
    // =========================================================================

    /// Unused fields MUST be zero, so two engines holding the same logical
    /// policy return byte-identical rules().
    function test_canonicalEncodingIsEnforced() public {
        Reg reg = new Reg();

        // A registry-backed kind may not also carry a value.
        Rule[] memory bad = _rules(Action.Transfer, RuleKind.Allowlist, 7, address(reg));
        vm.expectRevert(abi.encodeWithSelector(PolicyEngine.InvalidRule.selector, 0));
        _erc20(bad);

        // A numeric kind may not also carry a ref.
        bad = _rules(Action.Transfer, RuleKind.MaxTransfer, 5, address(reg));
        vm.expectRevert(abi.encodeWithSelector(PolicyEngine.InvalidRule.selector, 0));
        _erc20(bad);
    }

    /// Launch rules go through the same validation as proposals — an issuer
    /// must not be able to deploy with a rule that could never be proposed.
    function test_launchRulesAreValidated() public {
        vm.expectRevert(abi.encodeWithSelector(PolicyEngine.InvalidRule.selector, 0));
        _erc20(_rules(Action.Transfer, RuleKind.Allowlist, 0, address(0)));
    }

    // =========================================================================
    //                     PER-ACTION VERIFICATION SURFACE
    // =========================================================================

    /// A collection that caps supply per wallet but never restricts secondary
    /// trading is the common shape. Collapsing that to one red badge would
    /// misrepresent it.
    function test_isUnconditionalForRendersUnevenGovernance() public {
        PolicyERC20 t = _erc20(_rules(Action.Mint, RuleKind.MaxBalance, 100e18, address(0)));
        PolicyVerification.Report memory r = PolicyVerification.verify(address(t));

        assertFalse(PolicyVerification.isUnconditional(r), "the token as a whole is governed");
        assertTrue(PolicyVerification.isUnconditionalFor(r, Action.Transfer), "but transfers are free");
        assertFalse(PolicyVerification.isUnconditionalFor(r, Action.Mint));
        assertTrue(PolicyVerification.isUnconditionalFor(r, Action.Burn));
    }

    /// A queued proposal may add a rule to any action, so none can be called
    /// unconditional while one is pending.
    function test_pendingProposalVoidsEveryPerActionClaim() public {
        PolicyERC20 t = _erc20(_none());
        PolicyEngine e = PolicyEngine(t.policy());

        vm.prank(ADMIN);
        e.proposeRules(_rules(Action.Mint, RuleKind.HolderCap, 1, address(0)));

        PolicyVerification.Report memory r = PolicyVerification.verify(address(t));
        assertFalse(PolicyVerification.isUnconditionalFor(r, Action.Transfer));
        assertFalse(PolicyVerification.isUnconditionalFor(r, Action.Mint));
    }

    // =========================================================================
    //                       GAS: UNGATED STAYS CHEAP
    // =========================================================================

    /// The four newly-gated entry points must not become expensive for a token
    /// that does not use them. An action no rule governs returns on one SLOAD.
    function test_ungatedActionIsNearlyFree() public {
        PolicyERC20 governed = _erc20(_rules(Action.Transfer, RuleKind.MaxTransfer, 1e18, address(0)));

        vm.prank(ALICE);
        uint256 before = gasleft();
        governed.approve(BOB, 1e18);
        uint256 used = before - gasleft();

        // Approve is ungated here; the engine short-circuits on the bitmap.
        assertLt(used, 60_000, "an ungated action must not pay for the array");
    }
}
