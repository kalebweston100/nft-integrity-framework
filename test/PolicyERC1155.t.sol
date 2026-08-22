// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../contracts/token/PolicyERC1155.sol";
import "../contracts/token/PolicyTokenBase.sol";
import "../contracts/engine/PolicyEngine.sol";
import "../contracts/engine/PolicyTypes.sol";
import "../contracts/verification/PolicyVerification.sol";

contract Receiver1155 is IERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }
}

contract RejectingReceiver1155 {
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return 0xdeadbeef;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return 0xdeadbeef;
    }
}

contract PolicyERC1155Test is Test {
    address internal constant ADMIN = address(0xA11CE);
    address internal constant ALICE = address(0xA);
    address internal constant BOB = address(0xB);
    address internal constant CAROL = address(0xC);

    uint256 internal constant DELAY = 7 days;

    function _noRules() internal pure returns (Rule[] memory) {
        return new Rule[](0);
    }

    function _one(RuleKind kind, uint256 value, address ref) internal pure returns (Rule[] memory rs) {
        rs = new Rule[](1);
        rs[0] = Rule({kind: kind, value: value, ref: ref, scoped: false, scopeId: 0});
    }

    function _scoped(RuleKind kind, uint256 value, uint256 id) internal pure returns (Rule[] memory rs) {
        rs = new Rule[](1);
        rs[0] = Rule({kind: kind, value: value, ref: address(0), scoped: true, scopeId: id});
    }

    /// Mints 100 of id 1 and 100 of id 2 to Alice.
    function _token(Rule[] memory rules_) internal returns (PolicyERC1155 t) {
        t = new PolicyERC1155(ADMIN, "ipfs://base/{id}", DELAY, rules_);
        vm.startPrank(ADMIN);
        t.mint(ALICE, 1, 100);
        t.mint(ALICE, 2, 100);
        vm.stopPrank();
    }

    function _arr(uint256 a, uint256 b) internal pure returns (uint256[] memory xs) {
        xs = new uint256[](2);
        xs[0] = a;
        xs[1] = b;
    }

    // =========================================================================
    //                            THE CLAIM
    // =========================================================================

    function test_CLAIM_verifiesAndEnumerates() public {
        PolicyERC1155 t = _token(_one(RuleKind.MaxTransfer, 50, address(0)));

        PolicyVerification.Report memory r = PolicyVerification.verify(address(t));
        assertTrue(r.tokenCanonical);
        assertTrue(r.policyCanonical);
        assertEq(uint256(r.standard), uint256(TokenStandard.ERC1155));
        assertTrue(PolicyVerification.isFullyEnumerable(r));
        assertEq(r.rules.length, 1);
    }

    function test_CLAIM_noDiscretionaryOrConfiscatoryLeversExist() public {
        PolicyERC1155 t = _token(_noRules());

        string[6] memory forbidden = [
            "pause()",
            "unpause()",
            "freeze(address)",
            "blacklist(address)",
            "setPolicy(address)",
            "burn(address,uint256,uint256)"
        ];

        for (uint256 i; i < forbidden.length; ++i) {
            (bool ok,) = address(t).call(abi.encodeWithSignature(forbidden[i]));
            assertFalse(ok, forbidden[i]);
        }

        // The admin holds nothing, so the burn it does have reaches nobody.
        vm.prank(ADMIN);
        vm.expectRevert(InsufficientBalance.selector);
        t.burn(1, 1);
        assertEq(t.balanceOf(ALICE, 1), 100);
    }

    function test_holderCanBurnOwnBalance() public {
        PolicyERC1155 t = _token(_noRules());

        vm.prank(ALICE);
        t.burn(1, 40);

        assertEq(t.balanceOf(ALICE, 1), 60);
        assertEq(t.totalSupply(1), 60);
        assertEq(t.holderCount(1), 1);

        vm.prank(ALICE);
        t.burn(1, 60);
        assertEq(t.holderCount(1), 0, "burning out must clear the holder");
    }

    // =========================================================================
    //                        BATCH == N SEQUENTIAL SINGLES
    // =========================================================================

    /// The defining property of the batch path. If it did not hold, a rule
    /// would mean something different inside a batch than outside one — and an
    /// issuer's cap could be overshot by bundling.
    function test_CLAIM_batchIsExactlyNSequentialSingles() public {
        PolicyERC1155 batched = _token(_noRules());
        PolicyERC1155 singly = _token(_noRules());

        vm.prank(ALICE);
        batched.safeBatchTransferFrom(ALICE, BOB, _arr(1, 2), _arr(30, 40), "");

        vm.startPrank(ALICE);
        singly.safeTransferFrom(ALICE, BOB, 1, 30, "");
        singly.safeTransferFrom(ALICE, BOB, 2, 40, "");
        vm.stopPrank();

        assertEq(batched.balanceOf(BOB, 1), singly.balanceOf(BOB, 1));
        assertEq(batched.balanceOf(BOB, 2), singly.balanceOf(BOB, 2));
        assertEq(batched.balanceOf(ALICE, 1), singly.balanceOf(ALICE, 1));
        assertEq(batched.balanceOf(ALICE, 2), singly.balanceOf(ALICE, 2));
        assertEq(batched.holderCount(1), singly.holderCount(1));
    }

    /// The consequence that matters: a cap cannot be evaded by bundling two
    /// transfers of the same id into one call. Item 2 is evaluated against the
    /// balance item 1 left behind.
    function test_CLAIM_batchCannotOvershootAccumulatingRule() public {
        PolicyERC1155 t = _token(_one(RuleKind.MaxBalance, 50, address(0)));

        // 30 then 30 of the SAME id would leave Bob at 60, past the cap of 50.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyTokenBase.PolicyDenied.selector, "exceeds max balance"));
        t.safeBatchTransferFrom(ALICE, BOB, _arr(1, 1), _arr(30, 30), "");

        // Nothing settled: the whole call reverted.
        assertEq(t.balanceOf(BOB, 1), 0);
        assertEq(t.balanceOf(ALICE, 1), 100);
    }

    function test_batchEmitsOneTransferBatchNotNSingles() public {
        PolicyERC1155 t = _token(_noRules());

        vm.recordLogs();
        vm.prank(ALICE);
        t.safeBatchTransferFrom(ALICE, BOB, _arr(1, 2), _arr(10, 20), "");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 singles;
        uint256 batches;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == keccak256("TransferSingle(address,address,address,uint256,uint256)")) ++singles;
            if (logs[i].topics[0] == keccak256("TransferBatch(address,address,address,uint256[],uint256[])")) {
                ++batches;
            }
        }
        assertEq(batches, 1, "exactly one TransferBatch");
        assertEq(singles, 0, "and no TransferSingle, or indexers double-count");
    }

    function test_batchRejectsLengthMismatch() public {
        PolicyERC1155 t = _token(_noRules());
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;

        vm.prank(ALICE);
        vm.expectRevert(LengthMismatch.selector);
        t.safeBatchTransferFrom(ALICE, BOB, ids, _arr(1, 2), "");
    }

    // =========================================================================
    //                        PER-ID SCOPING AND ACCOUNTING
    // =========================================================================

    function test_scopedRuleAppliesToItsIdOnly() public {
        PolicyERC1155 t = _token(_scoped(RuleKind.LockupUntil, block.timestamp + 30 days, 1));

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyTokenBase.PolicyDenied.selector, "locked up"));
        t.safeTransferFrom(ALICE, BOB, 1, 10, "");

        // id 2 is untouched by the rule.
        vm.prank(ALICE);
        t.safeTransferFrom(ALICE, BOB, 2, 10, "");
        assertEq(t.balanceOf(BOB, 2), 10);
    }

    function test_supplyAndHolderCountArePerId() public {
        PolicyERC1155 t = _token(_noRules());

        assertEq(t.totalSupply(1), 100);
        assertEq(t.totalSupply(2), 100);
        assertEq(t.holderCount(1), 1);
        assertEq(t.holderCount(2), 1);

        vm.prank(ALICE);
        t.safeTransferFrom(ALICE, BOB, 1, 10, "");

        assertEq(t.holderCount(1), 2, "id 1 gained a holder");
        assertEq(t.holderCount(2), 1, "id 2 did not");
    }

    /// A per-id HolderCap must count only the holders of that id.
    function test_holderCapIsPerId() public {
        PolicyERC1155 t = _token(_scoped(RuleKind.HolderCap, 1, 1));

        // id 1 already has one holder and the cap is 1.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyTokenBase.PolicyDenied.selector, "holder cap reached"));
        t.safeTransferFrom(ALICE, BOB, 1, 10, "");

        // id 2 is not scoped by the rule at all.
        vm.prank(ALICE);
        t.safeTransferFrom(ALICE, BOB, 2, 10, "");
        assertEq(t.holderCount(2), 2);
    }

    // =========================================================================
    //                          POLICY ENFORCEMENT
    // =========================================================================

    function test_maxTransferBlocksOversizedItem() public {
        PolicyERC1155 t = _token(_one(RuleKind.MaxTransfer, 25, address(0)));

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(PolicyTokenBase.PolicyDenied.selector, "exceeds max transfer"));
        t.safeTransferFrom(ALICE, BOB, 1, 26, "");

        vm.prank(ALICE);
        t.safeTransferFrom(ALICE, BOB, 1, 25, "");
        assertEq(t.balanceOf(BOB, 1), 25);
    }

    function test_canTransferMatchesTheRealVerdict() public {
        PolicyERC1155 t = _token(_one(RuleKind.MaxTransfer, 5, address(0)));

        (bool allowed, string memory reason) = t.canTransfer(ALICE, BOB, 1, 10);
        assertFalse(allowed);
        assertEq(reason, "exceeds max transfer");

        (allowed,) = t.canTransfer(ALICE, BOB, 1, 5);
        assertTrue(allowed);
    }

    function test_mintIsNotPolicyGated() public {
        PolicyERC1155 t = _token(_one(RuleKind.LockupUntil, block.timestamp + 365 days, address(0)));

        vm.prank(ADMIN);
        t.mint(BOB, 3, 7);
        assertEq(t.balanceOf(BOB, 3), 7);
    }

    // =========================================================================
    //                       ERC-1155 CONFORMANCE
    // =========================================================================

    function test_supportsExpectedInterfaces() public {
        PolicyERC1155 t = _token(_noRules());

        assertTrue(t.supportsInterface(type(IERC1155).interfaceId));
        assertTrue(t.supportsInterface(type(IERC1155MetadataURI).interfaceId));
        assertTrue(t.supportsInterface(type(IERC2981).interfaceId));
        assertTrue(t.supportsInterface(type(IERC165).interfaceId));
        assertTrue(t.supportsInterface(type(IPolicyGoverned).interfaceId), "policy must be discoverable");
        assertFalse(t.supportsInterface(0xdeadbeef));
    }

    function test_operatorApprovalGovernsTransfers() public {
        PolicyERC1155 t = _token(_noRules());

        vm.prank(BOB);
        vm.expectRevert(NotOwnerOrApproved.selector);
        t.safeTransferFrom(ALICE, BOB, 1, 10, "");

        vm.prank(ALICE);
        t.setApprovalForAll(BOB, true);
        assertTrue(t.isApprovedForAll(ALICE, BOB));

        vm.prank(BOB);
        t.safeTransferFrom(ALICE, BOB, 1, 10, "");
        assertEq(t.balanceOf(BOB, 1), 10);
    }

    function test_receiverChecksAreEnforced() public {
        PolicyERC1155 t = _token(_noRules());
        Receiver1155 good = new Receiver1155();
        RejectingReceiver1155 bad = new RejectingReceiver1155();

        vm.startPrank(ALICE);
        t.safeTransferFrom(ALICE, address(good), 1, 5, "");
        t.safeBatchTransferFrom(ALICE, address(good), _arr(1, 2), _arr(5, 5), "");

        vm.expectRevert(NotERC1155Receiver.selector);
        t.safeTransferFrom(ALICE, address(bad), 1, 5, "");

        vm.expectRevert(NotERC1155Receiver.selector);
        t.safeBatchTransferFrom(ALICE, address(bad), _arr(1, 2), _arr(5, 5), "");
        vm.stopPrank();

        assertEq(t.balanceOf(address(good), 1), 10);
    }

    function test_selfTransferDoesNotCorruptBalance() public {
        PolicyERC1155 t = _token(_noRules());

        vm.prank(ALICE);
        t.safeTransferFrom(ALICE, ALICE, 1, 50, "");

        assertEq(t.balanceOf(ALICE, 1), 100, "self-transfer must not mint");
        assertEq(t.holderCount(1), 1);
    }

    function test_zeroAmountTransferIsAllowed() public {
        PolicyERC1155 t = _token(_noRules());

        vm.prank(ALICE);
        t.safeTransferFrom(ALICE, BOB, 1, 0, "");

        assertEq(t.balanceOf(BOB, 1), 0);
        assertEq(t.holderCount(1), 1, "a zero transfer creates no holder");
    }

    function test_mintBatchAndBurnBatch() public {
        PolicyERC1155 t = _token(_noRules());

        vm.prank(ADMIN);
        t.mintBatch(BOB, _arr(5, 6), _arr(10, 20));
        assertEq(t.balanceOf(BOB, 5), 10);
        assertEq(t.balanceOf(BOB, 6), 20);

        vm.prank(BOB);
        t.burnBatch(_arr(5, 6), _arr(10, 20));
        assertEq(t.totalSupply(5), 0);
        assertEq(t.holderCount(6), 0);
    }

    function test_mintIsIssuerAdminOnly() public {
        PolicyERC1155 t = _token(_noRules());

        vm.prank(ALICE);
        vm.expectRevert(NotIssuerAdmin.selector);
        t.mint(ALICE, 9, 1);
    }

    function test_balanceOfBatch() public {
        PolicyERC1155 t = _token(_noRules());

        address[] memory accounts = new address[](2);
        accounts[0] = ALICE;
        accounts[1] = ALICE;

        uint256[] memory got = t.balanceOfBatch(accounts, _arr(1, 2));
        assertEq(got[0], 100);
        assertEq(got[1], 100);
    }

    function test_uriIsSharedAcrossIds() public {
        PolicyERC1155 t = _token(_noRules());
        assertEq(t.uri(1), "ipfs://base/{id}");
        assertEq(t.uri(999), "ipfs://base/{id}");
    }
}
