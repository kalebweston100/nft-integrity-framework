// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../contracts/token/PolicyERC20.sol";
import "../contracts/engine/PolicyEngine.sol";
import "../contracts/engine/PolicyTypes.sol";
import "../contracts/verification/PolicyVerification.sol";
import "../contracts/verification/CanonicalCode.sol";

/// @dev Deploys ARBITRARY runtime code under an ATTACKER-CHOSEN constructor.
///      Init code and runtime code are independent byte strings: CREATE stores
///      whatever the init code RETURNs. This contract writes storage of its
///      choosing, then returns bytes it was simply handed — so the deployed
///      code can be byte-identical to a canonical contract it never compiled.
contract Impostor {
    constructor(bytes memory runtimeCode, uint256[] memory slots, bytes32[] memory values) {
        assembly {
            let n := mload(slots)
            let sp := add(slots, 0x20)
            let vp := add(values, 0x20)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let slot := mload(add(sp, mul(i, 0x20)))
                let val := mload(add(vp, mul(i, 0x20)))
                sstore(slot, val)
            }
            return(add(runtimeCode, 0x20), mload(runtimeCode))
        }
    }
}

/**
 * @notice What a codehash can and cannot carry.
 *
 * This suite exists to justify a decision made elsewhere: PolicyVerification
 * deliberately implements NO provenance check. That is only defensible if the
 * headline claim is purely future-tense, so here is the demonstration that the
 * distinction is real and not a technicality.
 *
 *     Guarantees about FUTURE behaviour can ride on a codehash.
 *     Guarantees about HISTORY cannot.
 *
 * EXTCODEHASH covers runtime code only. The constructor that wrote a contract's
 * initial storage lives in creation code and is never hashed, so an attacker can
 * fabricate any state at all and still present byte-identical runtime code
 * copied off a real deployment.
 *
 * The conclusion is NOT that the report lies. Every claim it makes about an
 * impostor remains true — the impostor really does run canonical code, so from
 * this moment on only the enumerated policy can block a transfer of it. What no
 * codehash can establish is how the balances it reports came to exist. An
 * integrator that reads "canonical" as "these balances were honestly minted" is
 * making a HISTORY claim the report never made.
 */
contract CodehashLimitsTest is Test {
    address internal constant ADMIN = address(0xA11CE);
    address internal constant ATTACKER = address(0xBAD);

    // Verified against `forge inspect PolicyERC20 storageLayout`.
    uint256 internal constant SLOT_POLICY = 0;
    uint256 internal constant SLOT_ISSUER_ADMIN = 1;
    uint256 internal constant SLOT_DEPLOY_ADMIN = 2;
    uint256 internal constant SLOT_TOTAL_SUPPLY = 6;
    uint256 internal constant SLOT_HOLDER_COUNT = 7;
    uint256 internal constant SLOT_BALANCES = 8;

    PolicyERC20 internal real;

    function setUp() public {
        Rule[] memory none = new Rule[](0);
        real = new PolicyERC20(ADMIN, "Real", "REAL", 18, 7 days, none);
        vm.prank(ADMIN);
        real.mint(ADMIN, 1_000e18);
    }

    function _mappingSlot(address key, uint256 slot) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(key, slot)));
    }

    /// The impostor never compiles PolicyERC20. It copies the canonical runtime
    /// code off a real deployment — public by design, EXTCODECOPY-able on-chain
    /// — and returns it from a constructor that first fabricates token state.
    function _deployImpostor(address engine) internal returns (address) {
        uint256[] memory slots = new uint256[](6);
        bytes32[] memory values = new bytes32[](6);

        slots[0] = SLOT_POLICY;
        values[0] = bytes32(uint256(uint160(engine)));

        slots[1] = SLOT_ISSUER_ADMIN;
        values[1] = bytes32(uint256(uint160(ATTACKER)));

        slots[2] = SLOT_DEPLOY_ADMIN;
        values[2] = bytes32(uint256(uint160(ATTACKER)));

        // Supply that no mint() ever created and no Transfer event announced.
        slots[3] = SLOT_TOTAL_SUPPLY;
        values[3] = bytes32(uint256(1_000_000e18));

        slots[4] = SLOT_HOLDER_COUNT;
        values[4] = bytes32(uint256(1));

        slots[5] = _mappingSlot(ATTACKER, SLOT_BALANCES);
        values[5] = bytes32(uint256(1_000_000e18));

        return address(new Impostor(address(real).code, slots, values));
    }

    /// The honest worst case: an impostor that also deploys its OWN canonical
    /// engine, naming the impostor as notifier, so nothing about it is
    /// inconsistent. This is the version an attacker would actually build.
    function _deploySelfConsistentImpostor() internal returns (address) {
        address future = vm.computeCreateAddress(address(this), vm.getNonce(address(this)) + 1);
        PolicyEngine engine = new PolicyEngine(ATTACKER, future, 7 days, new Rule[](0));
        address fake = _deployImpostor(address(engine));
        assertEq(fake, future, "impostor landed where the engine expects");
        return fake;
    }

    // =========================================================================
    //                       WHAT THE CODEHASH MISSES
    // =========================================================================

    function test_fabricatedState_stillPassesTheCanonicalCheck() public {
        address fake = _deployImpostor(address(real.policy()));

        assertEq(fake.codehash, PolicyVerification.canonicalTokenHashERC20(), "runtime code is byte-identical");
        assertTrue(CanonicalCode.isCanonical(fake, PolicyVerification.canonicalTokenHashERC20()));
    }

    function test_canonicalCodehash_doesNotConstrainSupplyHistory() public {
        address fake = _deployImpostor(address(real.policy()));

        // A million tokens that no mint created.
        assertEq(PolicyERC20(fake).totalSupply(), 1_000_000e18);
        assertEq(PolicyERC20(fake).balanceOf(ATTACKER), 1_000_000e18);

        // And an admin nobody handed the role to.
        assertEq(PolicyERC20(fake).issuerAdmin(), ATTACKER);
    }

    /// The whole report passes, including the policy leg: an attacker willing
    /// to stand up their own canonical engine gets a fully consistent forgery
    /// whose only lie is its history.
    function test_fullReportPassesOnAnImpostor() public {
        address fake = _deploySelfConsistentImpostor();

        PolicyVerification.Report memory r = PolicyVerification.verifyERC20(fake);
        assertTrue(r.tokenCanonical, "token leg passes");
        assertTrue(r.policyCanonical, "policy leg passes");
        assertTrue(PolicyVerification.isFullyEnumerable(r), "and so does the headline claim");
    }

    // =========================================================================
    //                    WHAT THE CODEHASH STILL DELIVERS
    // =========================================================================

    /// The point of the distinction. Everything the report actually claims is
    /// future-tense, and all of it holds even here: the impostor runs canonical
    /// code, so from now on it can only do what that code does.
    function test_futureBehaviourIsStillConstrained() public {
        address fake = _deploySelfConsistentImpostor();

        // No discretionary lever appeared just because the storage was faked.
        (bool ok,) = fake.call(abi.encodeWithSignature("pause()"));
        assertFalse(ok, "canonical code has no pause, whoever deployed it");

        (ok,) = fake.call(abi.encodeWithSignature("burn(address,uint256)", ATTACKER, 1));
        assertFalse(ok, "and no confiscation path");

        // The fabricated balance moves under exactly the normal rules.
        vm.prank(ATTACKER);
        PolicyERC20(fake).transfer(address(0xBEEF), 1e18);
        assertEq(PolicyERC20(fake).balanceOf(address(0xBEEF)), 1e18);
    }

    /// An impostor that points at SOMEBODY ELSE'S engine rather than deploying
    /// its own is inert: recordTransfer is notifier-gated, that gate is checked
    /// before anything else, and the transfer path calls it unconditionally. So
    /// every transfer reverts — for every rule set, including the empty one.
    ///
    /// Not a security boundary, and the report does not check it. It is worth
    /// recording only because it shows the residual gap fails CLOSED: the cheap
    /// impostor is frozen, and a working one has to stand up its own engine and
    /// therefore its own honest policy.
    function test_borrowedEngine_failsClosedNotOpen() public {
        address fake = _deployImpostor(address(real.policy()));

        vm.prank(ATTACKER);
        vm.expectRevert(PolicyEngine.NotNotifier.selector);
        PolicyERC20(fake).transfer(address(0xBEEF), 1e18);
    }

    /// The honest deployment passes for the honest reason.
    function test_realDeployment_verifiesAndItsSupplyIsReal() public view {
        PolicyVerification.Report memory r = PolicyVerification.verifyERC20(address(real));
        assertTrue(PolicyVerification.isFullyEnumerable(r));
        assertEq(real.totalSupply(), 1_000e18);
        assertEq(real.issuerAdmin(), ADMIN);
    }

    // =========================================================================
    //                     THE TOOL THAT WOULD CLOSE IT
    // =========================================================================

    /// Not used by PolicyVerification, and this test records why it does not
    /// need to be: the gap only matters for claims about history, and the
    /// headline claim makes none. CanonicalCode still carries the primitive for
    /// any consumer that does want a history claim.
    function test_provenanceWouldSeparateThem() public {
        address fake = _deployImpostor(address(real.policy()));

        // A CREATE2 address commits to the init code, so a fabricating
        // constructor cannot land on the same address as an honest one.
        bytes32 initHash = CanonicalCode.initCodeHash(
            type(PolicyEngine).creationCode, abi.encode(ADMIN, address(real), uint256(7 days), new Rule[](0))
        );
        address expected = CanonicalCode.addressOf(address(real), keccak256("PolicyToken.policy.v1"), initHash);

        assertEq(expected, address(real.policy()), "the real engine is where its init code says");
        assertTrue(CanonicalCode.isCanonical(fake, PolicyVerification.canonicalTokenHashERC20()), "yet code matches");
    }
}
