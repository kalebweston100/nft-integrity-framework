// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../contracts/verification/CanonicalCode.sol";

// =============================================================================
//  Deliberately imports NOTHING from the token framework. CanonicalCode is
//  standalone; these throwaway contracts stand in for whatever a user of the
//  library would actually be verifying.
// =============================================================================

/// @dev Zero immutables, so type(Widget).runtimeCode compiles. Constructor
///      arguments land in plain storage, which EXTCODEHASH never covers — so
///      every Widget is byte-identical however it was configured.
contract Widget {
    address public owner;
    uint256 public value;

    constructor(address owner_, uint256 value_) {
        owner = owner_;
        value = value_;
    }
}

/// @dev Any contract can be the CREATE2 deployer. No factory or singleton is
///      required — this one is simply part of the structure being verified.
contract WidgetDeployer {
    bytes32 public constant SALT = keccak256("widget.v1");

    function deploy(address owner_, uint256 value_) external returns (address) {
        return address(new Widget{salt: SALT}(owner_, value_));
    }
}

/// @dev Returns runtime code it was handed, after writing storage of its own
///      choosing. Init code and runtime code are independent byte strings.
contract Impostor {
    constructor(bytes memory runtimeCode, address owner_, uint256 value_) {
        assembly {
            sstore(0, owner_)
            sstore(1, value_)
            return(add(runtimeCode, 0x20), mload(runtimeCode))
        }
    }
}

contract CanonicalCodeTest is Test {
    WidgetDeployer internal deployer;
    address internal constant ALICE = address(0xA11CE);
    address internal constant ATTACKER = address(0xBAD);

    function setUp() public {
        deployer = new WidgetDeployer();
    }

    function _expectedInitCodeHash(address owner_, uint256 value_) internal pure returns (bytes32) {
        return CanonicalCode.initCodeHash(type(Widget).creationCode, abi.encode(owner_, value_));
    }

    // =========================================================================
    //   Future behaviour — the codehash
    // =========================================================================

    function test_isCanonical_matchesCompileTimeDerivedHash() public {
        // Different arguments — so different init code, and a different CREATE2
        // address — but identical runtime code, which is the whole point.
        address a = deployer.deploy(ALICE, 42);
        address b = deployer.deploy(ATTACKER, 999);

        bytes32 expected = keccak256(type(Widget).runtimeCode);
        assertTrue(CanonicalCode.isCanonical(a, expected));
        assertTrue(CanonicalCode.isCanonical(b, expected));
        assertEq(a.codehash, b.codehash, "configuration lives in storage, not code");
    }

    function test_isCanonical_falseForUnrelatedAndEmptyAccounts() public view {
        bytes32 expected = keccak256(type(Widget).runtimeCode);
        assertFalse(CanonicalCode.isCanonical(address(deployer), expected));
        assertFalse(CanonicalCode.isCanonical(ATTACKER, expected), "EOA codehash is 0");
    }

    // =========================================================================
    //   History — CREATE2 provenance
    // =========================================================================

    function test_addressOf_predictsDeploymentBeforeItHappens() public {
        address predicted = CanonicalCode.addressOf(address(deployer), deployer.SALT(), _expectedInitCodeHash(ALICE, 7));

        address actual = deployer.deploy(ALICE, 7);
        assertEq(actual, predicted);
    }

    function test_isProvenanceVerified_holdsForRealDeployment() public {
        address w = deployer.deploy(ALICE, 7);

        assertTrue(
            CanonicalCode.isProvenanceVerified(w, address(deployer), deployer.SALT(), _expectedInitCodeHash(ALICE, 7))
        );
    }

    /// @notice Constructor arguments are self-certifying: reading them off the
    ///         contract under verification is not circular, because any lie
    ///         changes the init-code hash and therefore the expected address.
    function test_constructorArguments_areSelfCertifying() public {
        address w = deployer.deploy(ALICE, 7);

        // Read the arguments back off the target and recompute.
        bytes32 fromTarget = _expectedInitCodeHash(Widget(w).owner(), Widget(w).value());
        assertTrue(CanonicalCode.isProvenanceVerified(w, address(deployer), deployer.SALT(), fromTarget));

        // Any other argument set derives a different address.
        bytes32 lie = _expectedInitCodeHash(ATTACKER, 7);
        assertFalse(CanonicalCode.isProvenanceVerified(w, address(deployer), deployer.SALT(), lie));
    }

    // =========================================================================
    //   The boundary the library exists to make explicit
    // =========================================================================

    /// @notice A fabricated constructor passes the codehash check honestly —
    ///         it really does run canonical code — and fails provenance.
    function test_impostor_passesCodehash_failsProvenance() public {
        address real = deployer.deploy(ALICE, 42);
        address impostor = address(new Impostor(real.code, ATTACKER, 999_999));

        bytes32 expected = keccak256(type(Widget).runtimeCode);

        assertTrue(CanonicalCode.isCanonical(impostor, expected), "codehash: future behaviour is canonical");
        assertEq(Widget(impostor).owner(), ATTACKER, "state never written by a canonical constructor");
        assertEq(Widget(impostor).value(), 999_999);

        assertFalse(
            CanonicalCode.isProvenanceVerified(
                impostor, address(deployer), deployer.SALT(), _expectedInitCodeHash(ATTACKER, 999_999)
            ),
            "provenance: history is not"
        );
        assertFalse(
            CanonicalCode.isFullyVerified(
                impostor, expected, address(deployer), deployer.SALT(), _expectedInitCodeHash(ATTACKER, 999_999)
            )
        );
    }

    function test_isFullyVerified_holdsForRealDeployment() public {
        address w = deployer.deploy(ALICE, 7);

        assertTrue(
            CanonicalCode.isFullyVerified(
                w,
                keccak256(type(Widget).runtimeCode),
                address(deployer),
                deployer.SALT(),
                _expectedInitCodeHash(ALICE, 7)
            )
        );
    }
}
