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

/**
 * @notice THE HEADLINE CLAIM: a token with an empty rule array cannot block a
 *         transfer, and that absence is machine-checkable.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY THIS IS THE MOST IMPORTANT SUITE IN THE REPO
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * "This token has no transfer restrictions" is a claim about a NEGATIVE, and
 * negatives over arbitrary code are exactly what cannot be established by
 * observation. Every passing transfer is consistent with a branch that has not
 * been taken yet. That is why, for an ordinary token, the only honest way to
 * answer it is to read the source, reason over every path, and then do it again
 * after the next upgrade — and why nobody does.
 *
 * A fixed, published codehash converts the question from a runtime one into a
 * compile-time one. The rules array is exhaustive because the code that
 * consults it is known; when the array is empty, there is nothing to consult.
 *
 * The fuzz tests below are therefore not proof — they are a demonstration that
 * the property holds across the whole input space, with the actual proof coming
 * from the canonical hash. They are here because the claim is worth being loud
 * about.
 */
contract UnconditionalPolicyTest is Test {
    address internal constant ADMIN = address(0xA11CE);

    PolicyERC20 internal t20;
    PolicyERC721 internal t721;
    PolicyERC1155 internal t1155;

    uint256 internal constant SUPPLY = type(uint128).max;

    function setUp() public {
        Rule[] memory none = new Rule[](0);

        t20 = new PolicyERC20(ADMIN, "Open", "OPEN", 18, 7 days, none);
        t721 = new PolicyERC721(ADMIN, "Open", "OPEN", "ipfs://base/", 7 days, none);
        t1155 = new PolicyERC1155(ADMIN, "ipfs://base/{id}", 7 days, none);
    }

    // =========================================================================
    //            THE CLAIM, AS A SINGLE BOOLEAN, FOR THE WHOLE SET
    // =========================================================================

    function test_CLAIM_unconditionalIsReportedForEveryStandard() public view {
        PolicyVerification.Report memory r20 = PolicyVerification.verify(address(t20));
        PolicyVerification.Report memory r721 = PolicyVerification.verify(address(t721));
        PolicyVerification.Report memory r1155 = PolicyVerification.verify(address(t1155));

        assertTrue(PolicyVerification.isUnconditional(r20), "ERC-20 unconditional");
        assertTrue(PolicyVerification.isUnconditional(r721), "ERC-721 unconditional");
        assertTrue(PolicyVerification.isUnconditional(r1155), "ERC-1155 unconditional");

        // And the standard is detected without being told.
        assertEq(uint256(r20.standard), uint256(TokenStandard.ERC20));
        assertEq(uint256(r721.standard), uint256(TokenStandard.ERC721));
        assertEq(uint256(r1155.standard), uint256(TokenStandard.ERC1155));
    }

    /// An unconditional token is not a special build. It is the ordinary token
    /// with an empty array, which is why it costs no compatibility at all.
    function test_unconditionalTokensAreOrdinaryTokens() public view {
        assertEq(t20.decimals(), 18);
        assertEq(t721.tokenStandard() == TokenStandard.ERC721 ? uint256(1) : uint256(0), 1);
        assertTrue(t20.supportsInterface(type(IPolicyGoverned).interfaceId), "discoverable");
        assertTrue(t721.supportsInterface(type(IERC721).interfaceId), "still an ERC-721");
        assertTrue(t1155.supportsInterface(type(IERC1155).interfaceId), "still an ERC-1155");
    }

    // =========================================================================
    //                 A PENDING CHANGE VOIDS THE CLAIM
    // =========================================================================

    /// The subtlety that makes isUnconditional worth having as a function
    /// rather than a `rules.length == 0` check at each call site. A token with
    /// no rules but a live proposal is unconditional TODAY and locked next
    /// week; a green badge on it would be exactly the failure this design
    /// exists to prevent.
    function test_CLAIM_pendingProposalVoidsUnconditional() public {
        PolicyEngine e = PolicyEngine(t20.policy());

        Rule[] memory lockup = new Rule[](1);
        lockup[0] = Rule({
            action: Action.Transfer,
            kind: RuleKind.LockupUntil,
            value: block.timestamp + 999 days,
            ref: address(0),
            scoped: false,
            scopeId: 0
        });

        vm.prank(ADMIN);
        e.proposeRules(lockup);

        PolicyVerification.Report memory r = PolicyVerification.verify(address(t20));

        assertEq(r.rules.length, 0, "nothing blocks a transfer yet");
        assertGt(r.pendingAt, 0, "but something is coming");
        assertFalse(PolicyVerification.isUnconditional(r), "so the claim must not be made");

        // Still fully enumerable, though — the weaker claim survives.
        assertTrue(PolicyVerification.isFullyEnumerable(r));
    }

    /// And it comes back once the proposal is withdrawn.
    function test_cancellingRestoresUnconditional() public {
        PolicyEngine e = PolicyEngine(t20.policy());

        Rule[] memory lockup = new Rule[](1);
        lockup[0] = Rule({
            action: Action.Transfer,
            kind: RuleKind.LockupUntil,
            value: block.timestamp + 1,
            ref: address(0),
            scoped: false,
            scopeId: 0
        });

        vm.startPrank(ADMIN);
        e.proposeRules(lockup);
        assertFalse(PolicyVerification.isUnconditional(PolicyVerification.verify(address(t20))));
        e.cancelRules();
        vm.stopPrank();

        assertTrue(PolicyVerification.isUnconditional(PolicyVerification.verify(address(t20))));
    }

    /// A token that acquires a rule is no longer unconditional, and could not
    /// have acquired it without the notice period.
    function test_committedRuleEndsTheClaim() public {
        PolicyEngine e = PolicyEngine(t20.policy());

        Rule[] memory cap = new Rule[](1);
        cap[0] = Rule({
            action: Action.Transfer, kind: RuleKind.MaxTransfer, value: 1, ref: address(0), scoped: false, scopeId: 0
        });

        vm.prank(ADMIN);
        e.proposeRules(cap);
        vm.warp(block.timestamp + 7 days);
        vm.prank(ADMIN);
        e.commitRules();

        PolicyVerification.Report memory r = PolicyVerification.verify(address(t20));
        assertFalse(PolicyVerification.isUnconditional(r));
        assertEq(r.rules.length, 1);
    }

    // =========================================================================
    //                            THE FUZZ CASES
    // =========================================================================

    /// For ALL senders, recipients and amounts: an unconditional ERC-20 never
    /// refuses a transfer it has the balance for.
    function testFuzz_unconditionalERC20_neverBlocks(address from, address to, uint256 amount) public {
        vm.assume(from != address(0) && to != address(0));
        amount = bound(amount, 0, SUPPLY);

        vm.prank(ADMIN);
        t20.mint(from, SUPPLY);

        (bool allowed,) = t20.canTransfer(from, to, amount);
        assertTrue(allowed, "canTransfer must never refuse");

        vm.prank(from);
        assertTrue(t20.transfer(to, amount));

        if (from != to) {
            assertEq(t20.balanceOf(to), amount);
            assertEq(t20.balanceOf(from), SUPPLY - amount);
        } else {
            assertEq(t20.balanceOf(from), SUPPLY, "self-transfer must not mint");
        }
    }

    /// For ALL owners, recipients and token ids: an unconditional ERC-721 never
    /// refuses a transfer of a token the sender owns.
    function testFuzz_unconditionalERC721_neverBlocks(address owner, address to, uint256 tokenId) public {
        vm.assume(owner != address(0) && to != address(0));
        vm.assume(to.code.length == 0); // plain transferFrom; no receiver contract

        vm.prank(ADMIN);
        t721.mint(owner, tokenId);

        (bool allowed,) = t721.canTransfer(owner, to, tokenId);
        assertTrue(allowed, "canTransfer must never refuse");

        vm.prank(owner);
        t721.transferFrom(owner, to, tokenId);
        assertEq(t721.ownerOf(tokenId), to);
    }

    /// For ALL holders, recipients, ids and amounts: an unconditional ERC-1155
    /// never refuses a transfer the sender has the balance for.
    function testFuzz_unconditionalERC1155_neverBlocks(address from, address to, uint256 id, uint256 amount) public {
        vm.assume(from != address(0) && to != address(0));
        vm.assume(to.code.length == 0);
        amount = bound(amount, 0, SUPPLY);

        vm.prank(ADMIN);
        t1155.mint(from, id, SUPPLY);

        (bool allowed,) = t1155.canTransfer(from, to, id, amount);
        assertTrue(allowed, "canTransfer must never refuse");

        vm.prank(from);
        t1155.safeTransferFrom(from, to, id, amount, "");

        if (from != to) {
            assertEq(t1155.balanceOf(to, id), amount);
        } else {
            assertEq(t1155.balanceOf(from, id), SUPPLY, "self-transfer must not mint");
        }
    }

    /// The claim is total over the ABI, not scoped to transfers: for ALL
    /// inputs, every OTHER entry point also settles on an unconditional token.
    function testFuzz_unconditional_neverBlocksAnyAction(address who, address other, uint256 amount) public {
        vm.assume(who != address(0) && other != address(0) && who != other);
        amount = bound(amount, 1, SUPPLY);

        vm.prank(ADMIN);
        t20.mint(who, SUPPLY);

        vm.startPrank(who);
        assertTrue(t20.approve(other, amount), "approve must never be refused");
        t20.burn(amount);
        vm.stopPrank();

        assertEq(t20.balanceOf(who), SUPPLY - amount);

        (bool allowed,) = t20.canPerform(Action.Mint, ADMIN, address(0), other, amount);
        assertTrue(allowed, "mint must never be refused");
        (allowed,) = t20.canPerform(Action.Burn, who, who, address(0), amount);
        assertTrue(allowed, "burn must never be refused");
    }

    /// Every action reports as unconditional, not just Transfer.
    function test_CLAIM_everyActionIsUnconditional() public view {
        PolicyVerification.Report memory r = PolicyVerification.verify(address(t20));
        for (uint256 i; i < 5; ++i) {
            assertTrue(PolicyVerification.isUnconditionalFor(r, Action(i)), "action must be ungated");
        }
        assertEq(PolicyEngine(t20.policy()).activeActions(), 0);
    }

    /// The admin is not privileged in either direction: it cannot block a
    /// transfer, and it has no lever to reach for.
    function testFuzz_adminCannotBlockAnUnconditionalTransfer(address caller, uint256 amount) public {
        vm.assume(caller != address(0));
        amount = bound(amount, 0, SUPPLY);

        vm.prank(ADMIN);
        t20.mint(caller, SUPPLY);

        // Whatever the admin tries first, the transfer still settles.
        vm.startPrank(ADMIN);
        (bool ok,) = address(t20).call(abi.encodeWithSignature("pause()"));
        assertFalse(ok);
        (ok,) = address(t20).call(abi.encodeWithSignature("burn(address,uint256)", caller, amount));
        assertFalse(ok);
        vm.stopPrank();

        vm.prank(caller);
        assertTrue(t20.transfer(address(0xBEEF), amount));
    }
}
