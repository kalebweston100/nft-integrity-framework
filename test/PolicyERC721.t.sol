// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../contracts/token/PolicyERC721.sol";
import "../contracts/token/PolicyTokenBase.sol";
import "../contracts/engine/PolicyEngine.sol";
import "../contracts/engine/PolicyTypes.sol";
import "../contracts/verification/PolicyVerification.sol";

contract GoodReceiver is IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
}

contract BadReceiver {
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return 0xdeadbeef;
    }
}

contract Registry is IPolicyRegistry {
    mapping(address => bool) public listed;

    function set(address a, bool v) external {
        listed[a] = v;
    }

    function isListed(address a) external view returns (bool) {
        return listed[a];
    }
}

contract PolicyERC721Test is Test {
    address internal constant ADMIN = address(0xA11CE);
    address internal constant ALICE = address(0xA);
    address internal constant BOB = address(0xB);
    address internal constant CAROL = address(0xC);

    uint256 internal constant DELAY = 7 days;

    function _noRules() internal pure returns (Rule[] memory) {
        return new Rule[](0);
    }

    function _oneFor(Action action, RuleKind kind, uint256 value, address ref)
        internal
        pure
        returns (Rule[] memory rs)
    {
        rs = new Rule[](1);
        rs[0] = Rule({action: action, kind: kind, value: value, ref: ref, scoped: false, scopeId: 0});
    }

    function _one(RuleKind kind, uint256 value, address ref) internal pure returns (Rule[] memory rs) {
        rs = new Rule[](1);
        rs[0] = Rule({action: Action.Transfer, kind: kind, value: value, ref: ref, scoped: false, scopeId: 0});
    }

    /// Mints ids 1..3 to Alice.
    function _token(Rule[] memory rules_) internal returns (PolicyERC721 t) {
        t = new PolicyERC721(ADMIN, "Collection", "COLL", "ipfs://base/", DELAY, rules_);
        vm.startPrank(ADMIN);
        t.mint(ALICE, 1);
        t.mint(ALICE, 2);
        t.mint(ALICE, 3);
        vm.stopPrank();
    }

    // =========================================================================
    //                            THE CLAIM
    // =========================================================================

    function test_CLAIM_verifiesAndEnumerates() public {
        PolicyERC721 t = _token(_one(RuleKind.MaxBalance, 5, address(0)));

        PolicyVerification.Report memory r = PolicyVerification.verify(address(t));
        assertTrue(r.tokenCanonical);
        assertTrue(r.policyCanonical);
        assertEq(uint256(r.standard), uint256(TokenStandard.ERC721));
        assertTrue(PolicyVerification.isFullyEnumerable(r));
        assertEq(r.rules.length, 1);
        assertEq(uint256(r.rules[0].kind), uint256(RuleKind.MaxBalance));
    }

    /// No pause, no freeze, and — the addition that matters most for an NFT —
    /// no path by which anyone but the owner can destroy a token.
    function test_CLAIM_noDiscretionaryOrConfiscatoryLeversExist() public {
        PolicyERC721 t = _token(_noRules());

        string[6] memory forbidden = [
            "pause()",
            "unpause()",
            "freeze(address)",
            "blacklist(address)",
            "setPolicy(address)",
            "burnFrom(address,uint256)"
        ];

        for (uint256 i; i < forbidden.length; ++i) {
            (bool ok,) = address(t).call(abi.encodeWithSignature(forbidden[i]));
            assertFalse(ok, forbidden[i]);
        }

        // The admin cannot burn a token it does not own.
        vm.prank(ADMIN);
        vm.expectRevert(NotOwnerOrApproved.selector);
        t.burn(1);
        assertEq(t.ownerOf(1), ALICE);
    }

    /// Approving a marketplace to SELL an NFT must never be approval to DESTROY
    /// it. ERC721Burnable allows exactly that; this deliberately does not.
    function test_CLAIM_approvedOperatorCannotBurn() public {
        PolicyERC721 t = _token(_noRules());

        vm.prank(ALICE);
        t.setApprovalForAll(BOB, true);

        vm.prank(BOB);
        vm.expectRevert(NotOwnerOrApproved.selector);
        t.burn(1);

        // But it can still transfer, which is what the approval was for.
        vm.prank(BOB);
        t.transferFrom(ALICE, CAROL, 1);
        assertEq(t.ownerOf(1), CAROL);
    }

    function test_ownerCanBurnOwnToken() public {
        PolicyERC721 t = _token(_noRules());

        vm.prank(ALICE);
        t.burn(1);

        assertEq(t.totalSupply(), 2);
        assertEq(t.balanceOf(ALICE), 2);
        vm.expectRevert(NonexistentToken.selector);
        t.ownerOf(1);
    }

    // =========================================================================
    //                          POLICY ENFORCEMENT
    // =========================================================================

    function test_lockupBlocksTransfer() public {
        PolicyERC721 t = _token(_one(RuleKind.LockupUntil, block.timestamp + 30 days, address(0)));

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyTokenBase.PolicyDenied.selector, "locked up"));
        t.transferFrom(ALICE, BOB, 1);

        vm.warp(block.timestamp + 31 days);
        vm.prank(ALICE);
        t.transferFrom(ALICE, BOB, 1);
        assertEq(t.ownerOf(1), BOB);
    }

    function test_maxBalanceCountsTokens() public {
        PolicyERC721 t = _token(_one(RuleKind.MaxBalance, 1, address(0)));

        vm.prank(ALICE);
        t.transferFrom(ALICE, BOB, 1);

        // Bob already holds one; a second would exceed the cap.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyTokenBase.PolicyDenied.selector, "exceeds max balance"));
        t.transferFrom(ALICE, BOB, 2);
    }

    function test_allowlistGatesBothParties() public {
        Registry reg = new Registry();
        PolicyERC721 t = _token(_one(RuleKind.Allowlist, 0, address(reg)));

        reg.set(ALICE, true);

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyTokenBase.PolicyDenied.selector, "recipient not allowlisted"));
        t.transferFrom(ALICE, BOB, 1);

        reg.set(BOB, true);
        vm.prank(ALICE);
        t.transferFrom(ALICE, BOB, 1);
        assertEq(t.ownerOf(1), BOB);
    }

    function test_holderCapCountsOwners() public {
        PolicyERC721 t = _token(_one(RuleKind.HolderCap, 1, address(0)));

        // Alice is the only holder and the cap is 1, so a new holder is refused.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyTokenBase.PolicyDenied.selector, "holder cap reached"));
        t.transferFrom(ALICE, BOB, 1);
    }

    function test_canTransferMatchesTheRealVerdict() public {
        PolicyERC721 t = _token(_one(RuleKind.LockupUntil, block.timestamp + 1 days, address(0)));

        (bool allowed, string memory reason) = t.canTransfer(ALICE, BOB, 1);
        assertFalse(allowed);
        assertEq(reason, "locked up");

        (allowed,) = t.canTransfer(ALICE, BOB, 99);
        assertFalse(allowed, "unowned token id");
    }

    function test_mintIsNotPolicyGated() public {
        PolicyERC721 t = _token(_one(RuleKind.LockupUntil, block.timestamp + 365 days, address(0)));

        vm.prank(ADMIN);
        t.mint(BOB, 42);
        assertEq(t.ownerOf(42), BOB);
    }

    // =========================================================================
    //                       ERC-721 CONFORMANCE
    // =========================================================================

    function test_metadataAndSupply() public {
        PolicyERC721 t = _token(_noRules());

        assertEq(t.name(), "Collection");
        assertEq(t.symbol(), "COLL");
        assertEq(t.totalSupply(), 3);
        assertEq(t.balanceOf(ALICE), 3);
        assertEq(t.tokenURI(2), "ipfs://base/2");
        assertEq(t.holderCount(), 1);
    }

    function test_supportsExpectedInterfaces() public {
        PolicyERC721 t = _token(_noRules());

        assertTrue(t.supportsInterface(type(IERC721).interfaceId));
        assertTrue(t.supportsInterface(type(IERC721Metadata).interfaceId));
        assertTrue(t.supportsInterface(type(IERC2981).interfaceId));
        assertTrue(t.supportsInterface(type(IERC165).interfaceId));
        assertTrue(t.supportsInterface(type(IPolicyGoverned).interfaceId), "policy must be discoverable");
        assertFalse(t.supportsInterface(0xdeadbeef));
    }

    function test_approvalIsClearedOnTransfer() public {
        PolicyERC721 t = _token(_noRules());

        vm.prank(ALICE);
        t.approve(BOB, 1);
        assertEq(t.getApproved(1), BOB);

        vm.prank(BOB);
        t.transferFrom(ALICE, CAROL, 1);
        assertEq(t.getApproved(1), address(0), "stale approval must not survive");
    }

    function test_safeTransferChecksReceiver() public {
        PolicyERC721 t = _token(_noRules());
        GoodReceiver good = new GoodReceiver();
        BadReceiver bad = new BadReceiver();

        vm.prank(ALICE);
        t.safeTransferFrom(ALICE, address(good), 1);
        assertEq(t.ownerOf(1), address(good));

        vm.prank(ALICE);
        vm.expectRevert(NotERC721Receiver.selector);
        t.safeTransferFrom(ALICE, address(bad), 2);
    }

    function test_selfTransferDoesNotCorruptBalance() public {
        PolicyERC721 t = _token(_noRules());

        vm.prank(ALICE);
        t.transferFrom(ALICE, ALICE, 1);

        assertEq(t.balanceOf(ALICE), 3, "self-transfer must not change the count");
        assertEq(t.ownerOf(1), ALICE);
        assertEq(t.holderCount(), 1);
    }

    function test_unauthorisedTransferReverts() public {
        PolicyERC721 t = _token(_noRules());

        vm.prank(BOB);
        vm.expectRevert(NotOwnerOrApproved.selector);
        t.transferFrom(ALICE, BOB, 1);
    }

    function test_cannotMintTwice() public {
        PolicyERC721 t = _token(_noRules());

        vm.prank(ADMIN);
        vm.expectRevert(TokenAlreadyMinted.selector);
        t.mint(BOB, 1);
    }

    function test_mintIsIssuerAdminOnly() public {
        PolicyERC721 t = _token(_noRules());

        vm.prank(ALICE);
        vm.expectRevert(NotIssuerAdmin.selector);
        t.mint(ALICE, 99);
    }

    function test_holderCountTracksZeroCrossings() public {
        PolicyERC721 t = _token(_noRules());
        assertEq(t.holderCount(), 1);

        vm.startPrank(ALICE);
        t.transferFrom(ALICE, BOB, 1);
        assertEq(t.holderCount(), 2, "Bob became a holder");
        t.transferFrom(ALICE, BOB, 2);
        assertEq(t.holderCount(), 2, "no new holder");
        t.transferFrom(ALICE, BOB, 3);
        vm.stopPrank();
        assertEq(t.holderCount(), 1, "Alice stopped being one");
    }

    // =========================================================================
    //                            ROYALTIES
    // =========================================================================

    function test_royaltiesAreAdminSetAndInformationalOnly() public {
        PolicyERC721 t = _token(_noRules());

        vm.prank(ADMIN);
        t.setDefaultRoyalty(CAROL, 500);

        (address receiver, uint256 amount) = t.royaltyInfo(1, 10_000);
        assertEq(receiver, CAROL);
        assertEq(amount, 500);

        // Setting a royalty cannot block a transfer: still unconditional.
        assertTrue(PolicyVerification.isUnconditional(PolicyVerification.verify(address(t))));

        vm.prank(ADMIN);
        vm.expectRevert(RoyaltyTooHigh.selector);
        t.setDefaultRoyalty(CAROL, 10_001);
    }
}
