// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../utils/Fixtures.sol";

/// @notice Drives random mint / hook-mint / transfer / transferFrom / burn sequences,
///         deliberately including zero-value transfers and zero-value burns from
///         non-holders, against an IntegrityERC20 and keeps ghost supply.
contract Handler20 is Test {
    IntegrityERC20 internal immutable token;
    TestHooksERC20 internal immutable hooks;
    address internal immutable issuer;

    uint256 internal constant MAX_AMOUNT = 1e24;

    address[] internal actors;

    uint256 public ghostSupply;

    constructor(IntegrityERC20 token_, TestHooksERC20 hooks_, address issuer_, address[] memory actors_) {
        token = token_;
        hooks = hooks_;
        issuer = issuer_;
        actors = actors_;
    }

    function mint(uint256 toSeed, uint256 amount) external {
        amount = bound(amount, 0, MAX_AMOUNT);
        vm.prank(issuer);
        token.mint(_actor(toSeed), amount, "");
        ghostSupply += amount;
    }

    function hookMint(uint256 toSeed, uint256 amount) external {
        amount = bound(amount, 0, MAX_AMOUNT);
        vm.prank(issuer);
        hooks.issuerMint(_actor(toSeed), amount);
        ghostSupply += amount;
    }

    /// @dev Amount is bounded to [0, balance], so zero-value transfers (including
    ///      from actors holding nothing) are exercised often.
    function transfer(uint256 fromSeed, uint256 toSeed, uint256 amount) external {
        address from = _actor(fromSeed);
        amount = bound(amount, 0, token.balanceOf(from));
        vm.prank(from);
        token.transfer(_actor(toSeed), amount);
    }

    function transferFrom(uint256 fromSeed, uint256 spenderSeed, uint256 toSeed, uint256 amount) external {
        address from = _actor(fromSeed);
        address spender = _actor(spenderSeed);
        amount = bound(amount, 0, token.balanceOf(from));

        vm.prank(from);
        token.approve(spender, amount);
        vm.prank(spender);
        token.transferFrom(from, _actor(toSeed), amount);
    }

    function burn(uint256 fromSeed, uint256 amount) external {
        address from = _actor(fromSeed);
        amount = bound(amount, 0, token.balanceOf(from));
        vm.prank(issuer);
        token.burn(from, amount);
        ghostSupply -= amount;
    }

    function warp(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 1, 30 days));
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % actors.length];
    }
}

contract IntegrityERC20InvariantTest is Fixtures {
    IntegrityERC20 internal token;
    Handler20 internal handler;

    address internal issuer = makeAddr("issuer");
    address[] internal actors;

    function setUp() public {
        TestHooksERC20 hooks;
        (hooks, token) = _deployERC20(issuer);

        actors.push(makeAddr("alice"));
        actors.push(makeAddr("bob"));
        actors.push(makeAddr("carol"));
        actors.push(makeAddr("dave"));

        handler = new Handler20(token, hooks, issuer, actors);
        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](6);
        selectors[0] = Handler20.mint.selector;
        selectors[1] = Handler20.hookMint.selector;
        selectors[2] = Handler20.transfer.selector;
        selectors[3] = Handler20.transferFrom.selector;
        selectors[4] = Handler20.burn.selector;
        selectors[5] = Handler20.warp.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @notice holderCount always equals the number of addresses with a non-zero balance.
    function invariant_holderCountMatchesActualHolders() public view {
        uint256 holders;
        for (uint256 i; i < actors.length; i++) {
            if (token.balanceOf(actors[i]) > 0) holders++;
        }
        assertEq(token.holderCount(), holders);
    }

    /// @notice firstReceivedAt is set exactly for current holders.
    function invariant_firstReceivedAtSetIffHolder() public view {
        for (uint256 i; i < actors.length; i++) {
            assertEq(token.firstReceivedAt(actors[i]) != 0, token.balanceOf(actors[i]) > 0);
        }
    }

    /// @notice totalSupply and the sum of balances both equal minted minus burned.
    function invariant_supplyMatchesBalances() public view {
        uint256 sum;
        for (uint256 i; i < actors.length; i++) {
            sum += token.balanceOf(actors[i]);
        }
        assertEq(sum, handler.ghostSupply());
        assertEq(token.totalSupply(), handler.ghostSupply());
    }
}
