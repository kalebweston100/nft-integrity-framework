// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../utils/Fixtures.sol";

/// @notice Drives random mint / transfer / batch transfer / burn sequences against an
///         IntegrityERC1155 and keeps ghost state the invariants check the token against.
contract Handler1155 is Test {
    IntegrityERC1155 internal immutable token;
    address internal immutable issuer;

    uint256 internal constant ID_COUNT = 4;
    /// @dev Flag bits 0-3 are defined in the test's setUp.
    uint256 internal constant FLAG_MASK = 0xF;

    address[] internal actors;

    mapping(uint256 => bool) public ghostCommitted;
    mapping(uint256 => uint256) public ghostFlags;
    mapping(uint256 => bytes32) public ghostMetaHash;
    mapping(uint256 => uint256) public ghostSupply;
    uint256 public ghostFlagRewriteSucceeded;

    constructor(IntegrityERC1155 token_, address issuer_, address[] memory actors_) {
        token = token_;
        issuer = issuer_;
        actors = actors_;
    }

    function mint(uint256 actorSeed, uint256 id, uint256 amount, uint256 flags, bytes32 metaHash) external {
        id = bound(id, 0, ID_COUNT - 1);
        amount = bound(amount, 1, 1_000);
        address to = actors[actorSeed % actors.length];

        // Later mints of an id must reuse its committed flags/hash.
        if (ghostCommitted[id]) {
            flags = ghostFlags[id];
            metaHash = ghostMetaHash[id];
        } else {
            flags &= FLAG_MASK;
        }

        vm.prank(issuer);
        token.mint(to, id, amount, flags, metaHash, "");

        if (!ghostCommitted[id]) {
            ghostCommitted[id] = true;
            ghostFlags[id] = flags;
            ghostMetaHash[id] = metaHash;
        }
        ghostSupply[id] += amount;
    }

    /// @dev Tries to mint more of a committed id with different flags. This must always
    ///      fail; a success is recorded and fails an invariant.
    function tryMintWithDifferentFlags(uint256 id, uint256 flags) external {
        id = bound(id, 0, ID_COUNT - 1);
        if (!ghostCommitted[id]) return;
        flags &= FLAG_MASK;
        if (flags == ghostFlags[id]) flags ^= 1;

        vm.prank(issuer);
        try token.mint(actors[0], id, 1, flags, ghostMetaHash[id], "") {
            ghostFlagRewriteSucceeded++;
            ghostSupply[id] += 1;
        } catch {}
    }

    function transfer(uint256 fromSeed, uint256 toSeed, uint256 id, uint256 amount) external {
        id = bound(id, 0, ID_COUNT - 1);
        address from = actors[fromSeed % actors.length];
        address to = actors[toSeed % actors.length];
        uint256 bal = token.balanceOf(from, id);
        if (bal == 0) return;
        amount = bound(amount, 1, bal);

        vm.prank(from);
        token.safeTransferFrom(from, to, id, amount, "");
    }

    function batchTransfer(uint256 fromSeed, uint256 toSeed, uint256 idSeed, uint256 amountA, uint256 amountB)
        external
    {
        address from = actors[fromSeed % actors.length];
        address to = actors[toSeed % actors.length];
        uint256 idA = idSeed % ID_COUNT;
        uint256 idB = (idA + 1) % ID_COUNT;
        uint256 balA = token.balanceOf(from, idA);
        uint256 balB = token.balanceOf(from, idB);
        if (balA == 0 || balB == 0) return;

        uint256[] memory ids = new uint256[](2);
        ids[0] = idA;
        ids[1] = idB;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = bound(amountA, 1, balA);
        amounts[1] = bound(amountB, 1, balB);

        vm.prank(from);
        token.safeBatchTransferFrom(from, to, ids, amounts, "");
    }

    function burn(uint256 fromSeed, uint256 id, uint256 amount) external {
        id = bound(id, 0, ID_COUNT - 1);
        address from = actors[fromSeed % actors.length];
        uint256 bal = token.balanceOf(from, id);
        if (bal == 0) return;
        amount = bound(amount, 1, bal);

        vm.prank(issuer);
        token.burn(from, id, amount);

        ghostSupply[id] -= amount;
    }
}

contract IntegrityERC1155InvariantTest is Fixtures {
    uint256 internal constant ID_COUNT = 4;

    IntegrityERC1155 internal token;
    Handler1155 internal handler;

    address internal issuer = makeAddr("issuer");
    address[] internal actors;

    function setUp() public {
        (, token) = _deployERC1155(issuer);

        vm.startPrank(issuer);
        token.defineFlag(0, "Authentic");
        token.defineFlag(1, "Limited Edition");
        token.defineFlag(2, "Graded");
        token.defineFlag(3, "Signed");
        vm.stopPrank();

        actors.push(makeAddr("alice"));
        actors.push(makeAddr("bob"));
        actors.push(makeAddr("carol"));
        actors.push(makeAddr("dave"));

        handler = new Handler1155(token, issuer, actors);
        targetContract(address(handler));

        // Fuzz only the handler's actions, not its getters or inherited Test helpers.
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = Handler1155.mint.selector;
        selectors[1] = Handler1155.tryMintWithDifferentFlags.selector;
        selectors[2] = Handler1155.transfer.selector;
        selectors[3] = Handler1155.batchTransfer.selector;
        selectors[4] = Handler1155.burn.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @notice Once an id's flags/metadata are committed they never change.
    function invariant_committedFlagsNeverChange() public view {
        for (uint256 id; id < ID_COUNT; id++) {
            if (!handler.ghostCommitted(id)) continue;
            assertTrue(token.flagsCommitted(id));
            assertEq(token.flagsOf(id), handler.ghostFlags(id));
            assertEq(token.metadataHashOf(id), handler.ghostMetaHash(id));
        }
        assertEq(handler.ghostFlagRewriteSucceeded(), 0);
    }

    /// @notice Per id, balances sum to minted-minus-burned supply, and
    ///         holderCountPerToken equals the number of addresses holding that id.
    function invariant_perIdSupplyAndHolders() public view {
        for (uint256 id; id < ID_COUNT; id++) {
            uint256 sum;
            uint256 holders;
            for (uint256 i; i < actors.length; i++) {
                uint256 bal = token.balanceOf(actors[i], id);
                sum += bal;
                if (bal > 0) holders++;
            }
            assertEq(sum, handler.ghostSupply(id));
            assertEq(token.holderCountPerToken(id), holders);
        }
    }

    /// @notice totalBalanceOf always equals the sum of an account's per-id balances.
    function invariant_aggregateBalanceMatchesPerIdBalances() public view {
        for (uint256 i; i < actors.length; i++) {
            uint256 sum;
            for (uint256 id; id < ID_COUNT; id++) {
                sum += token.balanceOf(actors[i], id);
            }
            assertEq(token.totalBalanceOf(actors[i]), sum);
        }
    }
}
