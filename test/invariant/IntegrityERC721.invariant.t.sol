// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../utils/Fixtures.sol";

/// @notice Drives random mint / transfer / self-transfer / burn / re-mint sequences
///         against an IntegrityERC721 and keeps ghost state the invariants check
///         the token against.
contract Handler721 is Test {
    IntegrityERC721 internal immutable token;
    address internal immutable issuer;

    uint256 internal constant MAX_TOKEN_ID = 32;
    /// @dev Flag bits 0-3 are defined in the test's setUp.
    uint256 internal constant FLAG_MASK = 0xF;

    address[] internal actors;

    uint256[] public everMinted;
    mapping(uint256 => uint256) public ghostFlags;
    mapping(uint256 => bytes32) public ghostMetaHash;
    mapping(uint256 => bool) public ghostAlive;
    uint256 public ghostLiveSupply;
    uint256 public ghostRemintSucceeded;

    constructor(IntegrityERC721 token_, address issuer_, address[] memory actors_) {
        token = token_;
        issuer = issuer_;
        actors = actors_;
    }

    function everMintedCount() external view returns (uint256) {
        return everMinted.length;
    }

    function mint(uint256 actorSeed, uint256 tokenId, uint256 flags, bytes32 metaHash) external {
        tokenId = bound(tokenId, 0, MAX_TOKEN_ID);
        if (token.flagsCommitted(tokenId)) return;
        flags &= FLAG_MASK;
        address to = actors[actorSeed % actors.length];

        vm.prank(issuer);
        token.mint(to, tokenId, flags, metaHash, "");

        everMinted.push(tokenId);
        ghostFlags[tokenId] = flags;
        ghostMetaHash[tokenId] = metaHash;
        ghostAlive[tokenId] = true;
        ghostLiveSupply++;
    }

    function transfer(uint256 tokenSeed, uint256 toSeed) external {
        (bool found, uint256 tokenId) = _pickLive(tokenSeed);
        if (!found) return;
        address from = token.ownerOf(tokenId);
        address to = actors[toSeed % actors.length];

        vm.prank(from);
        token.transferFrom(from, to, tokenId);
    }

    function selfTransfer(uint256 tokenSeed) external {
        (bool found, uint256 tokenId) = _pickLive(tokenSeed);
        if (!found) return;
        address owner = token.ownerOf(tokenId);

        vm.prank(owner);
        token.transferFrom(owner, owner, tokenId);
    }

    function burn(uint256 tokenSeed) external {
        (bool found, uint256 tokenId) = _pickLive(tokenSeed);
        if (!found) return;

        vm.prank(issuer);
        token.burn(tokenId);

        ghostAlive[tokenId] = false;
        ghostLiveSupply--;
    }

    /// @dev Tries to mint an id that has already been minted (live or burned). This
    ///      must always fail; a success is recorded and fails an invariant.
    function tryRemint(uint256 tokenSeed, uint256 flags, bytes32 metaHash) external {
        if (everMinted.length == 0) return;
        uint256 tokenId = everMinted[tokenSeed % everMinted.length];

        vm.prank(issuer);
        try token.mint(actors[0], tokenId, flags & FLAG_MASK, metaHash, "") {
            ghostRemintSucceeded++;
        } catch {}
    }

    function _pickLive(uint256 seed) internal view returns (bool, uint256) {
        uint256 n = everMinted.length;
        if (n == 0) return (false, 0);
        uint256 start = seed % n;
        for (uint256 i; i < n; i++) {
            uint256 tokenId = everMinted[(start + i) % n];
            if (ghostAlive[tokenId]) return (true, tokenId);
        }
        return (false, 0);
    }
}

contract IntegrityERC721InvariantTest is Fixtures {
    IntegrityERC721 internal token;
    Handler721 internal handler;

    address internal issuer = makeAddr("issuer");
    address[] internal actors;

    function setUp() public {
        (, token) = _deployERC721(issuer);

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

        handler = new Handler721(token, issuer, actors);
        targetContract(address(handler));

        // Fuzz only the handler's actions, not its getters or inherited Test helpers.
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = Handler721.mint.selector;
        selectors[1] = Handler721.transfer.selector;
        selectors[2] = Handler721.selfTransfer.selector;
        selectors[3] = Handler721.burn.selector;
        selectors[4] = Handler721.tryRemint.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @notice A token's committed flags and metadata hash never change, and every id
    ///         that was ever minted stays marked as committed, even after a burn.
    function invariant_committedFlagsNeverChange() public view {
        uint256 n = handler.everMintedCount();
        for (uint256 i; i < n; i++) {
            uint256 tokenId = handler.everMinted(i);
            assertTrue(token.flagsCommitted(tokenId));
            if (handler.ghostAlive(tokenId)) {
                assertEq(token.flagsOf(tokenId), handler.ghostFlags(tokenId));
                assertEq(token.metadataHashOf(tokenId), handler.ghostMetaHash(tokenId));
            }
        }
    }

    /// @notice No tokenId can ever be minted twice, including after a burn.
    function invariant_noTokenIdMintedTwice() public view {
        assertEq(handler.ghostRemintSucceeded(), 0);
    }

    /// @notice holderCount always equals the number of addresses that hold a token.
    function invariant_holderCountMatchesActualHolders() public view {
        uint256 holders;
        for (uint256 i; i < actors.length; i++) {
            if (token.balanceOf(actors[i]) > 0) holders++;
        }
        assertEq(token.holderCount(), holders);
    }

    /// @notice totalSupply and the sum of balances both equal the number of live tokens.
    function invariant_supplyMatchesBalances() public view {
        uint256 sum;
        for (uint256 i; i < actors.length; i++) {
            sum += token.balanceOf(actors[i]);
        }
        assertEq(sum, handler.ghostLiveSupply());
        assertEq(token.totalSupply(), handler.ghostLiveSupply());
    }
}
