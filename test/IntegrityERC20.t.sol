// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";

contract IntegrityERC20Test is Fixtures {
    address internal admin = address(0xA11CE);
    address internal alice = address(0xBEEF);
    address internal bob = address(0xCAFE);

    TestHooksERC20 internal hooks;
    IntegrityERC20 internal token;

    function setUp() public {
        (hooks,, token) = _deployERC20(admin);
    }

    // ─── Mint / burn ─────────────────────────────────────────────────────────

    function test_mint_creditsBalance() public {
        vm.prank(admin);
        token.mint(alice, 100e18, "");

        assertEq(token.balanceOf(alice), 100e18);
        assertEq(token.totalSupply(), 100e18);
        assertEq(hooks.beforeMintCount(), 1);
        assertEq(hooks.afterMintCount(), 1);
    }

    function test_onlyIssuerAdmin_canMint() public {
        vm.prank(alice);
        vm.expectRevert(NotIssuerAdmin.selector);
        token.mint(alice, 1e18, "");
    }

    function test_burn_reducesSupplyAndBalance() public {
        vm.startPrank(admin);
        token.mint(alice, 100e18, "");
        token.burn(alice, 40e18);
        vm.stopPrank();

        assertEq(token.balanceOf(alice), 60e18);
        assertEq(token.totalSupply(), 60e18);
    }

    // ─── Transfers ───────────────────────────────────────────────────────────

    function test_transfer_movesBalance() public {
        vm.prank(admin);
        token.mint(alice, 100e18, "");

        vm.prank(alice);
        token.transfer(bob, 30e18);

        assertEq(token.balanceOf(alice), 70e18);
        assertEq(token.balanceOf(bob), 30e18);
        assertEq(hooks.afterTransferCount(), 1);
    }

    function test_transfer_revertsOnInsufficientBalance() public {
        vm.prank(alice);
        vm.expectRevert(InsufficientBalance.selector);
        token.transfer(bob, 1e18);
    }

    function test_transferFrom_revertsOnInsufficientAllowance() public {
        vm.prank(admin);
        token.mint(alice, 100e18, "");

        vm.prank(bob);
        vm.expectRevert(InsufficientAllowance.selector);
        token.transferFrom(alice, bob, 1e18);
    }

    function test_transferFrom_spendsAllowance() public {
        vm.prank(admin);
        token.mint(alice, 100e18, "");
        vm.prank(alice);
        token.approve(bob, 40e18);

        vm.prank(bob);
        token.transferFrom(alice, bob, 25e18);

        assertEq(token.balanceOf(bob), 25e18);
        assertEq(token.allowance(alice, bob), 15e18);
    }

    /// Regression: ERC-20 requires zero-value transfers to succeed and emit Transfer.
    function test_zeroValueTransfer_succeeds() public {
        vm.prank(admin);
        token.mint(alice, 100e18, "");

        vm.expectEmit(true, true, false, true, address(token));
        emit IERC20.Transfer(alice, bob, 0);

        vm.prank(alice);
        assertTrue(token.transfer(bob, 0));

        assertEq(token.balanceOf(alice), 100e18);
        assertEq(token.balanceOf(bob), 0);
    }

    function test_zeroValueTransfer_worksFromEmptyAccount() public {
        vm.prank(alice);
        assertTrue(token.transfer(bob, 0));
    }

    // ─── Pause ───────────────────────────────────────────────────────────────

    function test_pause_blocksTransferMintBurn() public {
        vm.startPrank(admin);
        token.mint(alice, 100e18, "");
        token.pause();

        vm.expectRevert(TokenPaused.selector);
        token.mint(alice, 1e18, "");

        vm.expectRevert(TokenPaused.selector);
        token.burn(alice, 1e18);
        vm.stopPrank();

        vm.prank(alice);
        vm.expectRevert(TokenPaused.selector);
        token.transfer(bob, 1e18);
    }

    function test_unpause_restoresTransfers() public {
        vm.startPrank(admin);
        token.mint(alice, 100e18, "");
        token.pause();
        token.unpause();
        vm.stopPrank();

        vm.prank(alice);
        token.transfer(bob, 1e18);
        assertEq(token.balanceOf(bob), 1e18);
    }

    // ─── Hook deny gates ─────────────────────────────────────────────────────

    function test_hook_canBlockTransferViaValidateGate() public {
        vm.prank(admin);
        token.mint(alice, 100e18, "");

        vm.prank(admin);
        hooks.setBlockTransfers(true, "denied");

        vm.prank(alice);
        vm.expectRevert(bytes("denied"));
        token.transfer(bob, 1e18);

        assertEq(token.balanceOf(alice), 100e18);
    }

    function test_hook_canBlockMint() public {
        vm.prank(admin);
        hooks.setBlockMints(true, "no minting");

        vm.prank(admin);
        vm.expectRevert(bytes("no minting"));
        token.mint(alice, 1e18, "");
    }

    function test_hook_canBlockBurn() public {
        vm.startPrank(admin);
        token.mint(alice, 100e18, "");
        hooks.setBlockBurns(true, "no burning");

        vm.expectRevert(bytes("no burning"));
        token.burn(alice, 1e18);
        vm.stopPrank();
    }

    function test_canTransfer_reflectsHookDecision() public {
        vm.prank(admin);
        token.mint(alice, 100e18, "");

        (bool ok,) = token.canTransfer(alice, bob, 1e18);
        assertTrue(ok);

        vm.prank(admin);
        hooks.setBlockTransfers(true, "denied");

        (bool ok2, string memory reason) = token.canTransfer(alice, bob, 1e18);
        assertFalse(ok2);
        assertEq(reason, "denied");
    }

    // ─── After-hooks are fail-open ───────────────────────────────────────────

    function test_revertingAfterHook_doesNotBrickToken() public {
        vm.startPrank(admin);
        token.mint(alice, 100e18, "");
        hooks.setRevertInAfterHooks(true);
        vm.stopPrank();

        vm.prank(alice);
        token.transfer(bob, 10e18);

        assertEq(token.balanceOf(bob), 10e18, "transfer must still settle");
        assertEq(hooks.afterTransferCount(), 0, "after-hook did revert");
    }

    // ─── Admin ───────────────────────────────────────────────────────────────

    function test_transferIssuerAdmin() public {
        vm.prank(admin);
        token.transferIssuerAdmin(bob);
        assertEq(token.issuerAdmin(), bob);

        vm.prank(bob);
        token.mint(alice, 1e18, "");
        assertEq(token.balanceOf(alice), 1e18);
    }
}
