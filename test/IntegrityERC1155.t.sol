// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";
import "../contracts/interfaces/Errors.sol";
import "../contracts/interfaces/IERC1155Receiver.sol";

/// @dev A contract with no receiver functions: any acceptance check against it fails.
contract NonReceiver {}

/// @dev A contract that correctly accepts ERC-1155 tokens.
contract AcceptingReceiver is IERC1155Receiver {
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

contract IntegrityERC1155Test is Fixtures {
    address internal issuer = makeAddr("issuer");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    uint8 internal constant FLAG_AUTHENTIC = 0;
    uint256 internal constant ID = 1;

    // ─── Mint / transfer / burn happy path ──────────────────────────────────

    function test_mint_creditsBalance() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        vm.prank(issuer);
        token.mint(alice, ID, 10, 0, bytes32(0), "");

        assertEq(token.balanceOf(alice, ID), 10);
        assertEq(token.totalBalanceOf(alice), 10);
    }

    function test_safeTransferFrom_movesBalance() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        vm.prank(issuer);
        token.mint(alice, ID, 10, 0, bytes32(0), "");

        vm.prank(alice);
        token.safeTransferFrom(alice, bob, ID, 4, "");

        assertEq(token.balanceOf(alice, ID), 6);
        assertEq(token.balanceOf(bob, ID), 4);
    }

    function test_burn_reducesBalance() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        vm.prank(issuer);
        token.mint(alice, ID, 10, 0, bytes32(0), "");

        vm.prank(issuer);
        token.burn(alice, ID, 3);

        assertEq(token.balanceOf(alice, ID), 7);
    }

    // ─── Flags: commit on first mint, permanently locked thereafter ────────

    function test_secondMintOfSameId_mustMatchCommittedFlags() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        bytes32 metaHash = keccak256("meta-v1");

        vm.startPrank(issuer);
        token.defineFlag(FLAG_AUTHENTIC, "Authentic");
        token.mint(alice, ID, 10, 1 << FLAG_AUTHENTIC, metaHash, "");

        // Same flags/hash on a later mint of the same id succeeds and adds supply.
        token.mint(bob, ID, 5, 1 << FLAG_AUTHENTIC, metaHash, "");
        assertEq(token.balanceOf(bob, ID), 5);

        // A mismatched flags or metadata hash on the same id is rejected —
        // nobody, including the issuer, can change what an id's flags mean later.
        vm.expectRevert(FlagsAlreadyCommitted.selector);
        token.mint(bob, ID, 1, 0, metaHash, "");

        vm.expectRevert(FlagsAlreadyCommitted.selector);
        token.mint(bob, ID, 1, 1 << FLAG_AUTHENTIC, keccak256("different"), "");
        vm.stopPrank();
    }

    function test_mint_revertsOnUndefinedFlagBits() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        vm.prank(issuer);
        vm.expectRevert(UndefinedFlagBits.selector);
        token.mint(alice, ID, 1, 1 << FLAG_AUTHENTIC, bytes32(0), "");
    }

    function test_verifyToken_falseBeforeFirstMint() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        (bool ok,,) = token.verifyToken(ID, 0, bytes32(0));
        assertFalse(ok);
    }

    function test_verifyToken_trueAfterCommit() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        bytes32 metaHash = keccak256("meta-v1");
        vm.startPrank(issuer);
        token.defineFlag(FLAG_AUTHENTIC, "Authentic");
        token.mint(alice, ID, 10, 1 << FLAG_AUTHENTIC, metaHash, "");
        vm.stopPrank();

        (bool ok, uint256 flags, bytes32 hash_) = token.verifyToken(ID, 1 << FLAG_AUTHENTIC, metaHash);
        assertTrue(ok);
        assertEq(flags, 1 << FLAG_AUTHENTIC);
        assertEq(hash_, metaHash);
    }

    // ─── Hooks: denial paths (global and per-tokenId) ───────────────────────

    function test_hook_canBlockTransferGlobally() public {
        (TestHooksERC1155 hooks, IntegrityERC1155 token) = _deployERC1155(issuer);
        vm.prank(issuer);
        token.mint(alice, ID, 10, 0, bytes32(0), "");
        vm.prank(issuer);
        hooks.setRevertOnTransfer(true, "paused by policy");

        vm.prank(alice);
        vm.expectRevert(bytes("paused by policy"));
        token.safeTransferFrom(alice, bob, ID, 1, "");
    }

    function test_hook_canBlockMintPerTokenId() public {
        (TestHooksERC1155 hooks, IntegrityERC1155 token) = _deployERC1155(issuer);
        vm.prank(issuer);
        hooks.setBlockMintsById(ID, true, "id restricted");

        vm.prank(issuer);
        vm.expectRevert(bytes("id restricted"));
        token.mint(alice, ID, 1, 0, bytes32(0), "");

        // A different id is unaffected.
        vm.prank(issuer);
        token.mint(alice, ID + 1, 1, 0, bytes32(0), "");
        assertEq(token.balanceOf(alice, ID + 1), 1);
    }

    // ─── Hooks: cannot bypass core rules ─────────────────────────────────────

    function test_hookMint_onlyCallableByHooksContract() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        vm.prank(alice);
        vm.expectRevert(NotHooksContract.selector);
        token.hookMint(alice, ID, 1, 0, bytes32(0));
    }

    function test_hookMint_viaHooksContract() public {
        (TestHooksERC1155 hooks, IntegrityERC1155 token) = _deployERC1155(issuer);
        vm.prank(issuer);
        hooks.issuerMint(alice, ID, 7, 0, bytes32(0));

        assertEq(token.balanceOf(alice, ID), 7);
    }

    // ─── Regression: batch transfers emit exactly one TransferBatch ──────────

    function test_safeBatchTransferFrom_emitsOnlyTransferBatch() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        vm.startPrank(issuer);
        token.mint(alice, ID, 10, 0, bytes32(0), "");
        token.mint(alice, ID + 1, 10, 0, bytes32(0), "");
        vm.stopPrank();

        uint256[] memory ids = new uint256[](2);
        ids[0] = ID;
        ids[1] = ID + 1;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 3;
        amounts[1] = 4;

        vm.recordLogs();
        vm.prank(alice);
        token.safeBatchTransferFrom(alice, bob, ids, amounts, "");
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bytes32 singleSig = keccak256("TransferSingle(address,address,address,uint256,uint256)");
        bytes32 batchSig = keccak256("TransferBatch(address,address,address,uint256[],uint256[])");
        uint256 singles;
        uint256 batches;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].emitter != address(token) || logs[i].topics.length == 0) continue;
            if (logs[i].topics[0] == singleSig) {
                singles++;
            } else if (logs[i].topics[0] == batchSig) {
                batches++;
            }
        }

        // Previously 2 TransferSingle + 1 TransferBatch, so indexers counted 2x.
        assertEq(singles, 0);
        assertEq(batches, 1);
        assertEq(token.balanceOf(bob, ID), 3);
        assertEq(token.balanceOf(bob, ID + 1), 4);
    }

    // ─── Regression: mints run the EIP-1155 receiver check ──────────────────

    function test_mint_toNonReceiverContract_reverts() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        address sink = address(new NonReceiver());

        vm.prank(issuer);
        vm.expectRevert(NotERC1155Receiver.selector);
        token.mint(sink, ID, 1, 0, bytes32(0), "");
    }

    function test_mintBatch_toNonReceiverContract_reverts() public {
        (, IntegrityERC1155 token) = _deployERC1155(issuer);
        address sink = address(new NonReceiver());

        uint256[] memory ids = new uint256[](1);
        ids[0] = ID;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1;
        uint256[] memory flagsArr = new uint256[](1);
        bytes32[] memory hashes = new bytes32[](1);

        vm.prank(issuer);
        vm.expectRevert(NotERC1155Receiver.selector);
        token.mintBatch(sink, ids, amounts, flagsArr, hashes, "");
    }

    function test_hookMint_toNonReceiverContract_reverts() public {
        (TestHooksERC1155 hooks,) = _deployERC1155(issuer);
        address sink = address(new NonReceiver());

        vm.prank(issuer);
        vm.expectRevert(NotERC1155Receiver.selector);
        hooks.issuerMint(sink, ID, 1, 0, bytes32(0));
    }

    function test_mint_toAcceptingReceiver_succeeds() public {
        (TestHooksERC1155 hooks, IntegrityERC1155 token) = _deployERC1155(issuer);
        address receiver = address(new AcceptingReceiver());

        vm.prank(issuer);
        token.mint(receiver, ID, 2, 0, bytes32(0), "");
        vm.prank(issuer);
        hooks.issuerMint(receiver, ID, 3, 0, bytes32(0));

        assertEq(token.balanceOf(receiver, ID), 5);
    }
}
