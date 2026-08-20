// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";

contract IntegrityERC721Test is Fixtures {
    address internal admin = address(0xA11CE);
    address internal alice = address(0xBEEF);
    address internal bob = address(0xCAFE);

    TestHooksERC721 internal hooks;
    IntegrityERC721 internal token;

    function setUp() public {
        (hooks, token) = _deployERC721(admin);
    }

    // ─── Mint / burn ─────────────────────────────────────────────────────────

    function test_mint_setsOwnerAndSupply() public {
        vm.prank(admin);
        token.mint(alice, 1, "");

        assertEq(token.ownerOf(1), alice);
        assertEq(token.balanceOf(alice), 1);
        assertEq(token.totalSupply(), 1);
        assertEq(hooks.beforeMintCount(), 1);
        assertEq(hooks.afterMintCount(), 1);
    }

    function test_mint_revertsOnDuplicateTokenId() public {
        vm.startPrank(admin);
        token.mint(alice, 1, "");
        vm.expectRevert(TokenAlreadyMinted.selector);
        token.mint(bob, 1, "");
        vm.stopPrank();
    }

    function test_onlyIssuerAdmin_canMint() public {
        vm.prank(alice);
        vm.expectRevert(NotIssuerAdmin.selector);
        token.mint(alice, 1, "");
    }

    function test_burn_clearsOwnership() public {
        vm.startPrank(admin);
        token.mint(alice, 1, "");
        token.burn(1);
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 0);
        assertEq(token.totalSupply(), 0);
        vm.expectRevert(NonexistentToken.selector);
        token.ownerOf(1);
    }

    // ─── Transfers ───────────────────────────────────────────────────────────

    function test_transferFrom_movesOwnership() public {
        vm.prank(admin);
        token.mint(alice, 1, "");

        vm.prank(alice);
        token.transferFrom(alice, bob, 1);

        assertEq(token.ownerOf(1), bob);
        assertEq(token.balanceOf(alice), 0);
        assertEq(token.balanceOf(bob), 1);
        assertEq(hooks.afterTransferCount(), 1);
    }

    function test_transferFrom_revertsIfNotOwnerOrApproved() public {
        vm.prank(admin);
        token.mint(alice, 1, "");

        vm.prank(bob);
        vm.expectRevert(NotOwnerOrApproved.selector);
        token.transferFrom(alice, bob, 1);
    }

    /// Regression: a self-transfer must not corrupt balances.
    function test_selfTransfer_leavesBalanceIntact() public {
        vm.prank(admin);
        token.mint(alice, 1, "");

        vm.prank(alice);
        token.transferFrom(alice, alice, 1);

        assertEq(token.ownerOf(1), alice);
        assertEq(token.balanceOf(alice), 1, "self-transfer must not change balance");
        assertEq(token.totalSupply(), 1);
    }

    // ─── Pause ───────────────────────────────────────────────────────────────

    /// Regression: EVERY transfer entry point must respect pause, including the
    /// 4-argument safeTransferFrom overload.
    function test_pause_blocksAllTransferEntryPoints() public {
        vm.startPrank(admin);
        token.mint(alice, 1, "");
        token.pause();
        vm.stopPrank();

        vm.startPrank(alice);
        vm.expectRevert(TokenPaused.selector);
        token.transferFrom(alice, bob, 1);

        vm.expectRevert(TokenPaused.selector);
        token.safeTransferFrom(alice, bob, 1);

        vm.expectRevert(TokenPaused.selector);
        token.safeTransferFrom(alice, bob, 1, "");
        vm.stopPrank();

        assertEq(token.ownerOf(1), alice, "no transfer may land while paused");
    }

    function test_pause_blocksMintAndBurn() public {
        vm.startPrank(admin);
        token.mint(alice, 1, "");
        token.pause();

        vm.expectRevert(TokenPaused.selector);
        token.mint(bob, 2, "");

        vm.expectRevert(TokenPaused.selector);
        token.burn(1);
        vm.stopPrank();
    }

    // ─── Hook deny gates ─────────────────────────────────────────────────────

    function test_hook_canBlockTransferViaValidateGate() public {
        vm.prank(admin);
        token.mint(alice, 1, "");

        vm.prank(admin);
        hooks.setBlockTransfers(true, "nope");

        vm.prank(alice);
        vm.expectRevert(bytes("nope"));
        token.transferFrom(alice, bob, 1);

        assertEq(token.ownerOf(1), alice);
    }

    function test_hook_canBlockMint() public {
        vm.prank(admin);
        hooks.setBlockMints(true, "no minting");

        vm.prank(admin);
        vm.expectRevert(bytes("no minting"));
        token.mint(alice, 1, "");
    }

    function test_hook_canBlockBurn() public {
        vm.startPrank(admin);
        token.mint(alice, 1, "");
        hooks.setBlockBurns(true, "no burning");

        vm.expectRevert(bytes("no burning"));
        token.burn(1);
        vm.stopPrank();

        assertEq(token.ownerOf(1), alice);
    }

    function test_canTransfer_reflectsHookDecision() public {
        vm.prank(admin);
        token.mint(alice, 1, "");

        (bool ok,) = token.canTransfer(alice, bob, 1);
        assertTrue(ok);

        vm.prank(admin);
        hooks.setBlockTransfers(true, "denied");

        (bool ok2, string memory reason) = token.canTransfer(alice, bob, 1);
        assertFalse(ok2);
        assertEq(reason, "denied");
    }

    // ─── After-hooks are fail-open ───────────────────────────────────────────

    /// A reverting after-hook must not be able to brick the token.
    function test_revertingAfterHook_doesNotBrickToken() public {
        vm.startPrank(admin);
        token.mint(alice, 1, "");
        hooks.setRevertInAfterHooks(true);
        vm.stopPrank();

        vm.prank(alice);
        token.transferFrom(alice, bob, 1);

        assertEq(token.ownerOf(1), bob, "transfer must still settle");
        assertEq(hooks.afterTransferCount(), 0, "after-hook did revert");
    }

    // ─── Hook-initiated mint ─────────────────────────────────────────────────

    function test_hookMint_onlyCallableByHooksContract() public {
        vm.prank(admin);
        vm.expectRevert(NotHooksContract.selector);
        token.hookMint(alice, 1);
    }

    function test_hookMint_viaHooksContract() public {
        vm.prank(admin);
        hooks.issuerMint(alice, 7);

        assertEq(token.ownerOf(7), alice);
        assertEq(token.totalSupply(), 1);
    }

    // ─── Metadata ────────────────────────────────────────────────────────────

    function test_tokenURI_fallsBackToBaseURI() public {
        vm.prank(admin);
        token.mint(alice, 42, "");
        assertEq(token.tokenURI(42), "ipfs://base/42");
    }

    function test_tokenURI_overrideWins() public {
        vm.startPrank(admin);
        token.mint(alice, 42, "");
        token.setTokenURI(42, "ipfs://custom");
        vm.stopPrank();

        assertEq(token.tokenURI(42), "ipfs://custom");
        assertEq(hooks.afterSetTokenURICount(), 1);
    }

    function test_hook_canBlockBaseURIChange() public {
        vm.startPrank(admin);
        hooks.setBlockBaseURI(true);
        vm.expectRevert(bytes("TestHooks: baseURI locked"));
        token.setBaseURI("ipfs://new/");
        vm.stopPrank();
    }

    // ─── Royalties / introspection ───────────────────────────────────────────

    function test_royaltyInfo_reflectsConfiguredFee() public {
        vm.prank(admin);
        token.setDefaultRoyalty(bob, 500);

        (address receiver, uint256 amount) = token.royaltyInfo(1, 10_000);
        assertEq(receiver, bob);
        assertEq(amount, 500);
    }

    function test_supportsInterface() public view {
        assertTrue(token.supportsInterface(type(IERC721).interfaceId));
        assertTrue(token.supportsInterface(type(IERC721Metadata).interfaceId));
        assertTrue(token.supportsInterface(type(IERC2981).interfaceId));
        assertTrue(token.supportsInterface(type(IERC165).interfaceId));
        assertFalse(token.supportsInterface(0xdeadbeef));
    }
}
