// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";
import "../contracts/interfaces/Errors.sol";

contract IntegrityERC721Test is Fixtures {
    address internal issuer = makeAddr("issuer");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    uint8 internal constant FLAG_AUTHENTIC = 0;
    uint8 internal constant FLAG_LIMITED = 1;

    // ─── Mint / transfer / burn happy path ──────────────────────────────────

    function test_mint_setsOwnerAndTracksHolder() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        vm.prank(issuer);
        token.mint(alice, 1, 0, bytes32(0), "");

        assertEq(token.ownerOf(1), alice);
        assertEq(token.balanceOf(alice), 1);
        assertEq(token.holderCount(), 1);
    }

    function test_mint_revertsOnDuplicateTokenId() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        vm.startPrank(issuer);
        token.mint(alice, 1, 0, bytes32(0), "");
        vm.expectRevert(TokenAlreadyMinted.selector);
        token.mint(bob, 1, 0, bytes32(0), "");
        vm.stopPrank();
    }

    function test_transferFrom_movesOwnership() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        vm.prank(issuer);
        token.mint(alice, 1, 0, bytes32(0), "");

        vm.prank(alice);
        token.transferFrom(alice, bob, 1);

        assertEq(token.ownerOf(1), bob);
    }

    function test_transferFrom_revertsIfNotOwnerOrApproved() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        vm.prank(issuer);
        token.mint(alice, 1, 0, bytes32(0), "");

        vm.prank(bob);
        vm.expectRevert(NotOwnerOrApproved.selector);
        token.transferFrom(alice, bob, 1);
    }

    function test_burn_clearsOwnership() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        vm.prank(issuer);
        token.mint(alice, 1, 0, bytes32(0), "");

        vm.prank(issuer);
        token.burn(1);

        vm.expectRevert(NonexistentToken.selector);
        token.ownerOf(1);
    }

    // ─── Flags: append-only registry ────────────────────────────────────────

    function test_defineFlag_cannotBeRedefined() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        vm.startPrank(issuer);
        token.defineFlag(FLAG_AUTHENTIC, "Authentic");
        vm.expectRevert(FlagAlreadyDefined.selector);
        token.defineFlag(FLAG_AUTHENTIC, "Something else");
        vm.stopPrank();
    }

    function test_mint_revertsOnUndefinedFlagBits() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        vm.prank(issuer);
        vm.expectRevert(UndefinedFlagBits.selector);
        token.mint(alice, 1, 1 << FLAG_AUTHENTIC, bytes32(0), "");
    }

    // ─── Flags: commit-once, permanently immutable ──────────────────────────

    function test_mint_commitsFlagsAndMetadataPermanently() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        bytes32 metaHash = keccak256("metadata-v1");

        vm.startPrank(issuer);
        token.defineFlag(FLAG_AUTHENTIC, "Authentic");
        token.defineFlag(FLAG_LIMITED, "Limited Edition");
        uint256 flags = (1 << FLAG_AUTHENTIC) | (1 << FLAG_LIMITED);
        token.mint(alice, 1, flags, metaHash, "");
        vm.stopPrank();

        assertTrue(token.hasFlag(1, FLAG_AUTHENTIC));
        assertTrue(token.hasFlag(1, FLAG_LIMITED));
        assertEq(token.flagsOf(1), flags);
        assertEq(token.metadataHashOf(1), metaHash);

        // No function exists to rewrite committed flags/metadata — not even for the
        // issuer admin. Transferring or burning-and-reminting does not resurrect them
        // (burn does not clear the commitment, and the tokenId can't be re-minted).
        vm.prank(alice);
        token.transferFrom(alice, bob, 1);
        assertEq(token.flagsOf(1), flags);
    }

    function test_verifyToken_trueOnlyWhenClaimsMatchCommitment() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        bytes32 metaHash = keccak256("metadata-v1");

        vm.startPrank(issuer);
        token.defineFlag(FLAG_AUTHENTIC, "Authentic");
        token.mint(alice, 1, 1 << FLAG_AUTHENTIC, metaHash, "");
        vm.stopPrank();

        (bool ok, uint256 actualFlags, bytes32 actualHash) = token.verifyToken(1, 1 << FLAG_AUTHENTIC, metaHash);
        assertTrue(ok);
        assertEq(actualFlags, 1 << FLAG_AUTHENTIC);
        assertEq(actualHash, metaHash);

        (bool okWrongFlag,,) = token.verifyToken(1, 1 << FLAG_LIMITED, bytes32(0));
        assertFalse(okWrongFlag);

        (bool okWrongHash,,) = token.verifyToken(1, 0, keccak256("wrong"));
        assertFalse(okWrongHash);
    }

    function test_verifyToken_falseForNonexistentToken() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        (bool ok,,) = token.verifyToken(999, 0, bytes32(0));
        assertFalse(ok);
    }

    // ─── Hooks: denial paths ────────────────────────────────────────────────

    function test_hook_canBlockTransfer() public {
        (TestHooksERC721 hooks, IntegrityERC721 token) = _deployERC721(issuer);
        vm.prank(issuer);
        token.mint(alice, 1, 0, bytes32(0), "");
        vm.prank(issuer);
        hooks.setRevertOnTransfer(true, "frozen");

        vm.prank(alice);
        vm.expectRevert(bytes("frozen"));
        token.transferFrom(alice, bob, 1);
    }

    function test_hook_canBlockMint() public {
        (TestHooksERC721 hooks, IntegrityERC721 token) = _deployERC721(issuer);
        vm.prank(issuer);
        hooks.setBlockMints(true, "allowlist only");

        vm.prank(issuer);
        vm.expectRevert(bytes("allowlist only"));
        token.mint(alice, 1, 0, bytes32(0), "");
    }

    // ─── Hooks: cannot bypass core rules ─────────────────────────────────────

    function test_hookMint_onlyCallableByHooksContract() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        vm.prank(alice);
        vm.expectRevert(NotHooksContract.selector);
        token.hookMint(alice, 1, 0, bytes32(0));
    }

    function test_hookMint_stillEnforcesFlagDefinitionRule() public {
        (TestHooksERC721 hooks,) = _deployERC721(issuer);
        // Even the hook-gated mint path cannot commit undefined flag bits — the
        // token contract enforces this centrally in _commitFlags, not per-caller.
        vm.prank(issuer);
        vm.expectRevert(UndefinedFlagBits.selector);
        hooks.issuerMint(alice, 1, 1 << FLAG_AUTHENTIC, bytes32(0));
    }

    // ─── ERC-2981 royalties ──────────────────────────────────────────────────

    function test_royaltyInfo_reflectsConfiguredFee() public {
        (, IntegrityERC721 token) = _deployERC721(issuer);
        vm.prank(issuer);
        token.setDefaultRoyalty(bob, 500); // 5%

        (address receiver, uint256 amount) = token.royaltyInfo(1, 1000 ether);
        assertEq(receiver, bob);
        assertEq(amount, 50 ether);
    }

    // ─── Royalties (pull model, 1 unit per NFT) ─────────────────────────────

    function test_royalties_splitEquallyPerToken() public {
        (TestHooksERC721 hooks, IntegrityERC721 token) = _deployERC721(issuer);
        vm.startPrank(issuer);
        token.mint(alice, 1, 0, bytes32(0), "");
        token.mint(alice, 2, 0, bytes32(0), "");
        token.mint(bob, 3, 0, bytes32(0), "");
        vm.stopPrank();

        hooks.distributeRoyalties{value: 3 ether}();

        assertEq(hooks.pendingRoyaltiesFor(alice), 2 ether);
        assertEq(hooks.pendingRoyaltiesFor(bob), 1 ether);
    }
}
