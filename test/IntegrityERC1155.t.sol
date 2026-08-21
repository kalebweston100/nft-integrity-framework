// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";

contract IntegrityERC1155Test is Fixtures {
    address internal admin = address(0xA11CE);
    address internal alice = address(0xBEEF);
    address internal bob = address(0xCAFE);

    TestHooksERC1155 internal hooks;
    IntegrityERC1155 internal token;

    function setUp() public {
        (hooks,, token) = _deployERC1155(admin);
    }

    // ─── Mint / burn ─────────────────────────────────────────────────────────

    function test_mint_creditsBalanceAndSupply() public {
        vm.prank(admin);
        token.mint(alice, 1, 10, "");

        assertEq(token.balanceOf(alice, 1), 10);
        assertEq(token.totalSupply(1), 10);
        assertEq(hooks.beforeMintCount(), 1);
        assertEq(hooks.afterMintCount(), 1);
    }

    function test_mintBatch_creditsAllIds() public {
        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;
        amounts[0] = 5;
        amounts[1] = 7;

        vm.prank(admin);
        token.mintBatch(alice, ids, amounts, "");

        assertEq(token.balanceOf(alice, 1), 5);
        assertEq(token.balanceOf(alice, 2), 7);
        assertEq(token.totalSupply(1), 5);
        assertEq(token.totalSupply(2), 7);
    }

    function test_burn_reducesBalanceAndSupply() public {
        vm.startPrank(admin);
        token.mint(alice, 1, 10, "");
        token.burn(alice, 1, 4);
        vm.stopPrank();

        assertEq(token.balanceOf(alice, 1), 6);
        assertEq(token.totalSupply(1), 6);
    }

    // ─── Transfers ───────────────────────────────────────────────────────────

    function test_safeTransferFrom_movesBalance() public {
        vm.prank(admin);
        token.mint(alice, 1, 10, "");

        vm.prank(alice);
        token.safeTransferFrom(alice, bob, 1, 4, "");

        assertEq(token.balanceOf(alice, 1), 6);
        assertEq(token.balanceOf(bob, 1), 4);
        assertEq(hooks.afterTransferCount(), 1);
    }

    /// Regression: EIP-1155 requires a batch transfer to emit exactly one
    /// TransferBatch. Emitting per-item TransferSingle as well makes indexers
    /// double-count balances.
    function test_batchTransfer_emitsOnlyTransferBatch() public {
        uint256[] memory ids = new uint256[](2);
        uint256[] memory amounts = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;
        amounts[0] = 5;
        amounts[1] = 7;

        vm.prank(admin);
        token.mintBatch(alice, ids, amounts, "");

        vm.recordLogs();
        vm.prank(alice);
        token.safeBatchTransferFrom(alice, bob, ids, amounts, "");

        Vm.Log[] memory entries = vm.getRecordedLogs();

        bytes32 singleSig = keccak256("TransferSingle(address,address,address,uint256,uint256)");
        bytes32 batchSig = keccak256("TransferBatch(address,address,address,uint256[],uint256[])");

        uint256 singles;
        uint256 batches;
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].emitter != address(token)) continue;
            if (entries[i].topics[0] == singleSig) singles++;
            if (entries[i].topics[0] == batchSig) batches++;
        }

        assertEq(batches, 1, "exactly one TransferBatch");
        assertEq(singles, 0, "no per-item TransferSingle alongside it");
    }

    /// Regression: ERC-1155 requires zero-amount transfers to be treated normally.
    function test_zeroAmountTransfer_succeeds() public {
        vm.prank(admin);
        token.mint(alice, 1, 10, "");

        vm.prank(alice);
        token.safeTransferFrom(alice, bob, 1, 0, "");

        assertEq(token.balanceOf(alice, 1), 10);
        assertEq(token.balanceOf(bob, 1), 0);
    }

    function test_transfer_revertsIfNotOwnerOrApproved() public {
        vm.prank(admin);
        token.mint(alice, 1, 10, "");

        vm.prank(bob);
        vm.expectRevert(NotOwnerOrApproved.selector);
        token.safeTransferFrom(alice, bob, 1, 1, "");
    }

    // ─── Pause ───────────────────────────────────────────────────────────────

    function test_pause_blocksTransfers() public {
        vm.startPrank(admin);
        token.mint(alice, 1, 10, "");
        token.pause();
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(TokenPaused.selector);
        token.safeTransferFrom(alice, bob, 1, 1, "");
    }

    // ─── Hook deny gates ─────────────────────────────────────────────────────

    function test_hook_canBlockTransferGlobally() public {
        vm.prank(admin);
        token.mint(alice, 1, 10, "");

        vm.prank(admin);
        hooks.setBlockTransfers(true, "nope");

        vm.prank(alice);
        vm.expectRevert(bytes("nope"));
        token.safeTransferFrom(alice, bob, 1, 1, "");
    }

    function test_hook_canBlockTransferPerTokenId() public {
        vm.startPrank(admin);
        token.mint(alice, 1, 10, "");
        token.mint(alice, 2, 10, "");
        hooks.setBlockTransfersById(2, true, "id 2 is locked");
        vm.stopPrank();

        vm.prank(alice);
        token.safeTransferFrom(alice, bob, 1, 1, "");
        assertEq(token.balanceOf(bob, 1), 1);

        vm.prank(alice);
        vm.expectRevert(bytes("id 2 is locked"));
        token.safeTransferFrom(alice, bob, 2, 1, "");
    }

    function test_hook_canBlockMintPerTokenId() public {
        vm.prank(admin);
        hooks.setBlockMintsById(3, true, "id 3 is closed");

        vm.startPrank(admin);
        token.mint(alice, 1, 1, "");

        vm.expectRevert(bytes("id 3 is closed"));
        token.mint(alice, 3, 1, "");
        vm.stopPrank();
    }

    function test_hook_canBlockBurn() public {
        vm.startPrank(admin);
        token.mint(alice, 1, 10, "");
        hooks.setBlockBurns(true, "no burning");

        vm.expectRevert(bytes("no burning"));
        token.burn(alice, 1, 1);
        vm.stopPrank();
    }

    // ─── Metadata / introspection ────────────────────────────────────────────

    function test_uri_fallsBackToBase() public view {
        assertEq(token.uri(1), "ipfs://base/{id}");
    }

    function test_uri_overrideWins() public {
        vm.prank(admin);
        token.setTokenURI(1, "ipfs://custom");
        assertEq(token.uri(1), "ipfs://custom");
    }

    function test_supportsInterface() public view {
        assertTrue(token.supportsInterface(type(IERC1155).interfaceId));
        assertTrue(token.supportsInterface(type(IERC1155MetadataURI).interfaceId));
        assertTrue(token.supportsInterface(type(IERC2981).interfaceId));
        assertTrue(token.supportsInterface(type(IERC165).interfaceId));
        assertFalse(token.supportsInterface(0xdeadbeef));
    }
}
