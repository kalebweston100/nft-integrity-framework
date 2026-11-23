// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";
import "../contracts/libraries/Codehash.sol";

/// @notice Accepts every hook call. Stands in for whatever hooks address a poisoned
///         deployment chooses to report.
contract PermissiveHooks {
    function beforeTransfer(address, address, uint256) external {}

    function validateTransfer(address, address, uint256) external pure returns (bool, string memory) {
        return (true, "");
    }

    function afterTransfer(address, address, uint256) external {}
}

/// @notice Initcode that writes arbitrary storage and then installs the canonical
///         IntegrityERC20 runtime bytecode verbatim. The resulting account has the
///         canonical codehash, but none of its state came from the canonical constructor.
contract PoisonedERC20Deployer {
    constructor(bytes memory canonicalRuntime, address attacker, address fakeHooks, uint256 phantomBalance) {
        // Slots from `forge inspect IntegrityERC20 storageLayout`.
        bytes32 balanceSlot = keccak256(abi.encode(attacker, uint256(8))); // _balances[attacker]
        assembly {
            sstore(0, attacker) // _issuerAdmin = attacker, _paused = false
            sstore(3, fakeHooks) // _hooks
            sstore(7, 1) // _holderCount
            sstore(balanceSlot, phantomBalance) // _totalSupply (slot 6) stays 0
            return(add(canonicalRuntime, 0x20), mload(canonicalRuntime))
        }
    }
}

/// @notice Documents the limit of codehash verification (README: "Threat model and
///         limits"). EXTCODEHASH attests to code, never to state, and initcode is not
///         part of the codehash. A deployer can run any constructor it likes, poison
///         storage, and still end up with an account that `Codehash.isCanonical`
///         accepts.
contract PoisonedConstructorTest is Fixtures {
    address internal issuer = makeAddr("issuer");
    address internal attacker = makeAddr("attacker");
    address internal victim = makeAddr("victim");

    function test_canonicalCodehashDoesNotImplyCanonicalState() public {
        (, IntegrityERC20 genuine) = _deployERC20(issuer);
        bytes32 canonicalHash = address(genuine).codehash;

        PermissiveHooks fakeHooks = new PermissiveHooks();
        IntegrityERC20 poisoned = IntegrityERC20(
            address(new PoisonedERC20Deployer(address(genuine).code, attacker, address(fakeHooks), 1_000_000e18))
        );

        // Passes the codehash check...
        assertTrue(Codehash.isCanonical(address(poisoned), canonicalHash));

        // ...but the state is fabricated: a balance with no backing supply and no
        // Transfer(0, attacker, ...) event ever emitted, an attacker-chosen admin, and
        // a "hooks contract" that never deployed this token.
        assertEq(poisoned.balanceOf(attacker), 1_000_000e18);
        assertEq(poisoned.totalSupply(), 0);
        assertEq(poisoned.issuerAdmin(), attacker);
        assertEq(poisoned.hooksContract(), address(fakeHooks));

        // The phantom balance moves through the real, locked pipeline like any other.
        vm.prank(attacker);
        poisoned.transfer(victim, 500e18);
        assertEq(poisoned.balanceOf(victim), 500e18);
        assertEq(poisoned.totalSupply(), 0);
    }
}
