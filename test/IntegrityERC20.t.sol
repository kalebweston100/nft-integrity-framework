// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";
import "../contracts/interfaces/Errors.sol";

contract IntegrityERC20Test is Fixtures {
    address internal issuer = makeAddr("issuer");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    // ─── Mint / transfer / burn happy path ──────────────────────────────────

    function test_mint_creditsBalanceAndTracksHolder() public {
        (, IntegrityERC20 token) = _deployERC20(issuer);

        vm.prank(issuer);
        token.mint(alice, 100, "");

        assertEq(token.balanceOf(alice), 100);
        assertEq(token.totalSupply(), 100);
        assertEq(token.holderCount(), 1);
    }

    function test_transfer_movesBalance() public {
        (, IntegrityERC20 token) = _deployERC20(issuer);
        vm.prank(issuer);
        token.mint(alice, 100, "");

        vm.prank(alice);
        token.transfer(bob, 40);

        assertEq(token.balanceOf(alice), 60);
        assertEq(token.balanceOf(bob), 40);
    }

    function test_transfer_revertsOnInsufficientBalance() public {
        (, IntegrityERC20 token) = _deployERC20(issuer);
        vm.prank(alice);
        vm.expectRevert(InsufficientBalance.selector);
        token.transfer(bob, 1);
    }

    function test_transferFrom_revertsOnInsufficientAllowance() public {
        (, IntegrityERC20 token) = _deployERC20(issuer);
        vm.prank(issuer);
        token.mint(alice, 100, "");

        vm.prank(bob);
        vm.expectRevert(InsufficientAllowance.selector);
        token.transferFrom(alice, bob, 10);
    }

    function test_burn_reducesSupplyAndBalance() public {
        (, IntegrityERC20 token) = _deployERC20(issuer);
        vm.prank(issuer);
        token.mint(alice, 100, "");

        vm.prank(issuer);
        token.burn(alice, 30);

        assertEq(token.balanceOf(alice), 70);
        assertEq(token.totalSupply(), 70);
    }

    // ─── Pause / admin ───────────────────────────────────────────────────────

    function test_pause_blocksTransfer() public {
        (, IntegrityERC20 token) = _deployERC20(issuer);
        vm.prank(issuer);
        token.mint(alice, 100, "");

        vm.prank(issuer);
        token.pause();

        vm.prank(alice);
        vm.expectRevert(TokenPaused.selector);
        token.transfer(bob, 1);
    }

    function test_onlyIssuerAdmin_canMint() public {
        (, IntegrityERC20 token) = _deployERC20(issuer);
        vm.prank(alice);
        vm.expectRevert(NotIssuerAdmin.selector);
        token.mint(alice, 1, "");
    }

    // ─── Hooks: denial paths ────────────────────────────────────────────────

    function test_hook_canBlockTransfer() public {
        (TestHooksERC20 hooks, IntegrityERC20 token) = _deployERC20(issuer);
        vm.prank(issuer);
        token.mint(alice, 100, "");

        // An allowed transfer runs the hook and leaves its call log updated.
        vm.prank(alice);
        token.transfer(bob, 1);
        assertEq(hooks.beforeTransferCount(), 1);

        // Once the hook starts denying, the whole transfer reverts — including the
        // hook's own state changes from that same call, which never get committed.
        vm.prank(issuer);
        hooks.setRevertOnTransfer(true, "blocked by policy");

        vm.prank(alice);
        vm.expectRevert(bytes("blocked by policy"));
        token.transfer(bob, 1);

        assertEq(token.balanceOf(bob), 1);
        assertEq(hooks.beforeTransferCount(), 1);
    }

    function test_hook_canBlockMint() public {
        (TestHooksERC20 hooks, IntegrityERC20 token) = _deployERC20(issuer);
        vm.prank(issuer);
        hooks.setBlockMints(true, "kyc required");

        vm.prank(issuer);
        vm.expectRevert(bytes("kyc required"));
        token.mint(alice, 1, "");
    }

    function test_hook_canBlockBurn() public {
        (TestHooksERC20 hooks, IntegrityERC20 token) = _deployERC20(issuer);
        vm.prank(issuer);
        token.mint(alice, 100, "");
        vm.prank(issuer);
        hooks.setBlockBurns(true, "locked");

        vm.prank(issuer);
        vm.expectRevert(bytes("locked"));
        token.burn(alice, 1);
    }

    // ─── Hooks: cannot bypass core rules ─────────────────────────────────────

    function test_hookMint_onlyCallableByHooksContract() public {
        (, IntegrityERC20 token) = _deployERC20(issuer);
        vm.prank(alice);
        vm.expectRevert(NotHooksContract.selector);
        token.hookMint(alice, 1);
    }

    function test_hookMint_viaHooksContractSucceeds() public {
        (TestHooksERC20 hooks, IntegrityERC20 token) = _deployERC20(issuer);

        vm.prank(issuer);
        hooks.issuerMint(alice, 50);

        assertEq(token.balanceOf(alice), 50);
    }
}
