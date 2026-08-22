// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";
import "../contracts/libraries/IntegrityVerifier.sol";

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
                sstore(mload(add(sp, mul(i, 0x20))), mload(add(vp, mul(i, 0x20))))
            }
            return(add(runtimeCode, 0x20), mload(runtimeCode))
        }
    }
}

/// @notice Two things at once:
///
///         1. EXTCODEHASH constrains FUTURE behaviour and cannot speak to how
///            current state arose — the constructor that wrote it is in the
///            creation code, which the runtime codehash never covers.
///         2. The CREATE2 provenance check closes exactly that gap, because a
///            CREATE2 address is a commitment to the init code.
contract CodehashLimitsTest is Fixtures {
    address internal constant ATTACKER = address(0xBAD);
    address internal constant FAKE_WRAPPER = address(0xF00D);

    // Verified against `forge inspect IntegrityERC721 storageLayout`.
    uint256 internal constant SLOT_ISSUER_ADMIN = 0;
    uint256 internal constant SLOT_DEPLOY_ADMIN = 1;
    uint256 internal constant SLOT_HOOKS = 3;
    uint256 internal constant SLOT_TOTAL_SUPPLY = 6;
    uint256 internal constant SLOT_OWNERS = 7;
    uint256 internal constant SLOT_BALANCES = 8;

    function _mappingSlot(uint256 key, uint256 slot) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(key, slot)));
    }

    function _mappingSlot(address key, uint256 slot) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(key, slot)));
    }

    /// The impostor never compiles IntegrityERC721. It copies the canonical
    /// runtime code off a real deployment — public by design, EXTCODECOPY-able
    /// on-chain — and returns it from a constructor that first fabricates the
    /// entire token state, `_deployAdmin` included.
    function _deployImpostor(bytes memory canonicalRuntime) internal returns (address) {
        uint256[] memory slots = new uint256[](6);
        bytes32[] memory values = new bytes32[](6);

        slots[0] = SLOT_ISSUER_ADMIN;
        values[0] = bytes32(uint256(uint160(ATTACKER)));

        slots[1] = SLOT_DEPLOY_ADMIN;
        values[1] = bytes32(uint256(uint160(ATTACKER)));

        slots[2] = SLOT_HOOKS;
        values[2] = bytes32(uint256(uint160(FAKE_WRAPPER)));

        // Supply that no mint() ever created and no Transfer event ever announced.
        slots[3] = SLOT_TOTAL_SUPPLY;
        values[3] = bytes32(uint256(1_000_000));

        slots[4] = _mappingSlot(uint256(1), SLOT_OWNERS);
        values[4] = bytes32(uint256(uint160(ATTACKER)));

        slots[5] = _mappingSlot(ATTACKER, SLOT_BALANCES);
        values[5] = bytes32(uint256(1_000_000));

        return address(new Impostor(canonicalRuntime, slots, values));
    }

    // =========================================================================
    //   PART 1 — the codehash check is SOUND, and proves less than it seems
    // =========================================================================

    /// @notice A contract with fabricated storage passes every codehash check.
    /// @dev Not a false positive: the impostor genuinely runs canonical code.
    ///      What is unverified is the constructor that wrote the initial state.
    function test_fabricatedState_stillPassesCanonicalCheck() public {
        (,, IntegrityERC721 real) = _deployERC721(address(0xA11CE));
        address impostor = _deployImpostor(address(real).code);

        assertEq(impostor.codehash, address(real).codehash, "byte-identical to a real deployment");
        assertEq(impostor.codehash, IntegrityVerifier.canonicalERC721Hash(), "matches the compile-time hash");
        assertTrue(IntegrityVerifier.isCanonicalERC721(impostor), "passes the one-call check");
    }

    /// @notice "Supply is provably confined to onlyIssuerAdmin" is a claim about
    ///         HISTORY, and EXTCODEHASH alone cannot carry it.
    function test_canonicalCodehash_doesNotConstrainSupplyHistory() public {
        (,, IntegrityERC721 real) = _deployERC721(address(0xA11CE));
        address impostor = _deployImpostor(address(real).code);

        assertTrue(IntegrityVerifier.isCanonicalERC721(impostor));
        assertEq(IntegrityERC721(impostor).totalSupply(), 1_000_000, "supply from nowhere");
        assertEq(IntegrityERC721(impostor).ownerOf(1), ATTACKER, "ownership never transferred");
        assertEq(IntegrityERC721(impostor).balanceOf(ATTACKER), 1_000_000, "balance never credited");
    }

    /// @notice "The wrapper reference is unspoofable — written from msg.sender,
    ///         no setter" holds for the runtime code only. The constructor is
    ///         where that slot is written, and it is outside the hashed region.
    function test_canonicalCodehash_doesNotProveWrapperProvenance() public {
        (,, IntegrityERC721 real) = _deployERC721(address(0xA11CE));
        address impostor = _deployImpostor(address(real).code);

        assertTrue(IntegrityVerifier.isCanonicalERC721(impostor));
        assertEq(IntegrityERC721(impostor).hooksContract(), FAKE_WRAPPER, "wrapper never deployed this token");
        assertEq(IntegrityERC721(impostor).issuerAdmin(), ATTACKER, "admin set by an unverified constructor");
    }

    /// @notice What the codehash DOES buy: every future state transition is
    ///         canonical, because canonical code is what executes. Mint stays
    ///         issuer-gated even though the initial supply was fabricated.
    function test_futureBehaviour_remainsCanonical() public {
        (,, IntegrityERC721 real) = _deployERC721(address(0xA11CE));
        address impostor = _deployImpostor(address(real).code);

        vm.prank(address(0xDEAD));
        vm.expectRevert();
        IntegrityERC721(impostor).mint(address(0xDEAD), 99, "");

        assertEq(IntegrityERC721(impostor).totalSupply(), 1_000_000, "no unauthorised mint succeeded");
    }

    // =========================================================================
    //   PART 2 — CREATE2 provenance closes the gap
    // =========================================================================

    /// @notice A real deployment passes the full check: canonical code AND a
    ///         canonical constructor, proven by recomputing its CREATE2 address.
    function test_realDeployment_passesFullVerification() public {
        (, HooksWrapperERC721 wrapper, IntegrityERC721 token) = _deployERC721(address(0xA11CE));

        assertTrue(IntegrityVerifier.isProvenanceVerifiedERC721(address(token), address(wrapper)), "provenance holds");
        assertTrue(IntegrityVerifier.isFullyVerifiedERC721(address(token), address(wrapper)), "full check holds");
    }

    /// @notice The impostor cannot reach the address. Its constructor differs,
    ///         so its init code hashes differently, so CREATE2 would have put it
    ///         somewhere else. Fabricating `_deployAdmin` does not help: any
    ///         lie about a constructor argument changes the expected address.
    function test_impostor_failsProvenanceCheck() public {
        (, HooksWrapperERC721 wrapper, IntegrityERC721 real) = _deployERC721(address(0xA11CE));
        address impostor = _deployImpostor(address(real).code);

        assertTrue(IntegrityVerifier.isCanonicalERC721(impostor), "still passes on code alone");

        assertFalse(IntegrityVerifier.isProvenanceVerifiedERC721(impostor, address(wrapper)), "caught by provenance");
        assertFalse(IntegrityVerifier.isFullyVerifiedERC721(impostor, address(wrapper)), "caught by full check");
        assertFalse(
            IntegrityVerifier.isProvenanceVerifiedERC721(impostor, FAKE_WRAPPER), "and against its claimed wrapper"
        );
    }

    /// @notice A canonical token cannot be paired with a wrapper that did not
    ///         deploy it — the CREATE2 deployer is part of the derivation.
    function test_provenance_rejectsMismatchedRealPairs() public {
        (, HooksWrapperERC721 wrapperA, IntegrityERC721 tokenA) = _deployERC721(address(0xA11CE));
        (, HooksWrapperERC721 wrapperB,) = _deployERC721(address(0xB0B));

        assertTrue(IntegrityVerifier.isProvenanceVerifiedERC721(address(tokenA), address(wrapperA)));
        assertFalse(IntegrityVerifier.isProvenanceVerifiedERC721(address(tokenA), address(wrapperB)));
    }

    /// @notice Provenance must survive an admin handover, which is why the
    ///         deploy-time admin is recorded in its own setter-less slot.
    function test_provenance_survivesIssuerAdminTransfer() public {
        address admin = address(0xA11CE);
        (, HooksWrapperERC721 wrapper, IntegrityERC721 token) = _deployERC721(admin);

        vm.prank(admin);
        token.transferIssuerAdmin(address(0xB0B));

        assertEq(token.issuerAdmin(), address(0xB0B), "admin moved");
        assertEq(token.deployAdmin(), admin, "deploy-time admin is a permanent record");
        assertTrue(IntegrityVerifier.isFullyVerifiedERC721(address(token), address(wrapper)), "still fully verifiable");
    }

    /// @notice The same closure for the other two standards.
    function test_provenance_allThreeStandards() public {
        (, HooksWrapperERC20 w20, IntegrityERC20 t20) = _deployERC20(address(0xA11CE));
        (, HooksWrapperERC1155 w1155, IntegrityERC1155 t1155) = _deployERC1155(address(0xA11CE));

        assertTrue(IntegrityVerifier.isFullyVerifiedERC20(address(t20), address(w20)));
        assertTrue(IntegrityVerifier.isFullyVerifiedERC1155(address(t1155), address(w1155)));
    }
}
