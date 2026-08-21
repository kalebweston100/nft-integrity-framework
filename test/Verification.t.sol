// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";
import "../contracts/libraries/IntegrityVerifier.sol";
import "../contracts/interfaces/IHooksERC20.sol";
import "../contracts/interfaces/IHooksERC721.sol";
import "../contracts/interfaces/IHooksERC1155.sol";

/// @dev Impersonates a legitimate token it does not govern, to exercise the
///      Token/Wrapper mutual-reference check.
contract ImpostorWrapper {
    address public token;

    constructor(address stolenToken) {
        token = stolenToken;
    }
}

/// @dev Impersonates a legitimate wrapper it did not deploy, to exercise the
///      Wrapper/Logic mutual-reference check.
contract ImpostorLogic {
    address public wrapper;

    constructor(address stolenWrapper) {
        wrapper = stolenWrapper;
    }
}

contract VerificationTest is Fixtures {
    address internal admin = address(0xA11CE);

    // =========================================================================
    //   Compile-time hash derivation — no published constant, no registry
    // =========================================================================

    /// The core claim: a verifier importing this source derives the canonical hash
    /// itself, at compile time, and it matches every real deployment.
    function test_compileTimeHash_matchesDeployedTokens() public {
        (,, IntegrityERC721 a) = _deployERC721(admin);
        (,, IntegrityERC721 b) = _deployERC721(address(0xD00D));

        bytes32 derived = IntegrityVerifier.canonicalERC721Hash();

        assertEq(derived, address(a).codehash, "derived hash must match a real deployment");
        assertEq(derived, address(b).codehash, "and a second, independently configured one");
    }

    function test_compileTimeHash_allThreeStandards() public {
        (,, IntegrityERC20 t20) = _deployERC20(admin);
        (,, IntegrityERC721 t721) = _deployERC721(admin);
        (,, IntegrityERC1155 t1155) = _deployERC1155(admin);

        assertEq(IntegrityVerifier.canonicalERC20Hash(), address(t20).codehash);
        assertEq(IntegrityVerifier.canonicalERC721Hash(), address(t721).codehash);
        assertEq(IntegrityVerifier.canonicalERC1155Hash(), address(t1155).codehash);
    }

    /// The wrapper gets the identical treatment: one hash verifies every wrapper
    /// deployment, regardless of which logic contract or token it wraps.
    function test_compileTimeHash_matchesDeployedWrappers() public {
        (, HooksWrapperERC721 wrapperA,) = _deployERC721(admin);
        (, HooksWrapperERC721 wrapperB,) = _deployERC721(address(0xD00D));

        bytes32 derived = IntegrityVerifier.canonicalWrapperERC721Hash();

        assertEq(derived, address(wrapperA).codehash, "must match a real wrapper deployment");
        assertEq(derived, address(wrapperB).codehash, "and a second, independently configured one");
    }

    function test_compileTimeHash_allThreeWrapperStandards() public {
        (, HooksWrapperERC20 w20,) = _deployERC20(admin);
        (, HooksWrapperERC721 w721,) = _deployERC721(admin);
        (, HooksWrapperERC1155 w1155,) = _deployERC1155(admin);

        assertEq(IntegrityVerifier.canonicalWrapperERC20Hash(), address(w20).codehash);
        assertEq(IntegrityVerifier.canonicalWrapperERC721Hash(), address(w721).codehash);
        assertEq(IntegrityVerifier.canonicalWrapperERC1155Hash(), address(w1155).codehash);
    }

    /// Token and wrapper hashes must differ — they are different contracts with
    /// different bytecode, not aliases of the same check.
    function test_tokenHash_and_wrapperHash_areDistinct() public pure {
        assertTrue(IntegrityVerifier.canonicalERC721Hash() != IntegrityVerifier.canonicalWrapperERC721Hash());
    }

    /// Tokens deployed by differently-configured logic contracts stay byte-identical,
    /// which is what lets one hash verify every deployment.
    function test_codehashIdentical_acrossIndependentLogicDeployments() public {
        (,, IntegrityERC20 a) = _deployERC20(admin);
        TestHooksERC20 otherLogic = new TestHooksERC20(address(0xD00D), "Other", "OTH", "ipfs://other");
        IntegrityERC20 b = otherLogic.wrapper().token();

        assertTrue(address(a) != address(b), "different deployments");
        assertEq(address(a).codehash, address(b).codehash, "identical runtime bytecode");
    }

    function test_isCanonical_oneCallHelpers() public {
        (,, IntegrityERC20 t20) = _deployERC20(admin);
        (,, IntegrityERC721 t721) = _deployERC721(admin);
        (,, IntegrityERC1155 t1155) = _deployERC1155(admin);

        assertTrue(IntegrityVerifier.isCanonicalERC20(address(t20)));
        assertTrue(IntegrityVerifier.isCanonicalERC721(address(t721)));
        assertTrue(IntegrityVerifier.isCanonicalERC1155(address(t1155)));

        // Cross-standard and non-token addresses must not pass.
        assertFalse(IntegrityVerifier.isCanonicalERC721(address(t20)));
        assertFalse(IntegrityVerifier.isCanonicalERC721(address(this)));
        assertFalse(IntegrityVerifier.isCanonicalERC721(address(0xDEAD)));
    }

    function test_isCanonicalWrapper_oneCallHelpers() public {
        (, HooksWrapperERC20 w20,) = _deployERC20(admin);
        (, HooksWrapperERC721 w721,) = _deployERC721(admin);
        (, HooksWrapperERC1155 w1155,) = _deployERC1155(admin);

        assertTrue(IntegrityVerifier.isCanonicalWrapperERC20(address(w20)));
        assertTrue(IntegrityVerifier.isCanonicalWrapperERC721(address(w721)));
        assertTrue(IntegrityVerifier.isCanonicalWrapperERC1155(address(w1155)));

        // A wrapper must not pass as its own token, and vice versa.
        assertFalse(IntegrityVerifier.isCanonicalWrapperERC721(address(w20)));
        assertFalse(IntegrityVerifier.isCanonicalWrapperERC721(address(0xDEAD)));
    }

    /// EXTCODEHASH is read by the EVM from the target's own deployed bytecode, so
    /// the check cannot be spoofed by the contract under inspection.
    function test_isCanonical_neverCallsIntoTarget() public {
        (,, IntegrityERC721 token) = _deployERC721(admin);
        // No call is made, so no state is touched and a hostile fallback is unreachable.
        assertTrue(IntegrityVerifier.isCanonical(address(token), IntegrityVerifier.canonicalERC721Hash()));
        assertFalse(IntegrityVerifier.isCanonical(address(token), bytes32(uint256(1))));
    }

    // =========================================================================
    //           Mutual-reference (pairing) checks — Token <-> Wrapper
    // =========================================================================

    function test_isConsistentPair_trueForRealPair() public {
        (, HooksWrapperERC721 wrapper, IntegrityERC721 token) = _deployERC721(admin);
        assertTrue(IntegrityVerifier.isConsistentPair(address(token), address(wrapper)));
    }

    /// A fake wrapper can name someone else's real token, but that token will
    /// not name it back — the unspoofable direction closes the spoofable one.
    function test_isConsistentPair_catchesImpostorWrapper() public {
        (,, IntegrityERC721 token) = _deployERC721(admin);
        ImpostorWrapper impostor = new ImpostorWrapper(address(token));

        assertEq(impostor.token(), address(token), "impostor does claim the real token");
        assertFalse(
            IntegrityVerifier.isConsistentPair(address(token), address(impostor)), "but the round trip must fail"
        );
    }

    function test_isConsistentPair_falseForMismatchedRealPairs() public {
        (, HooksWrapperERC721 wrapperA,) = _deployERC721(admin);
        (,, IntegrityERC721 tokenB) = _deployERC721(admin);

        assertFalse(IntegrityVerifier.isConsistentPair(address(tokenB), address(wrapperA)));
    }

    function test_isConsistentPair_falseForNonContracts() public view {
        assertFalse(IntegrityVerifier.isConsistentPair(address(0), address(0)));
        assertFalse(IntegrityVerifier.isConsistentPair(address(0xDEAD), address(0xBEEF)));
    }

    // =========================================================================
    //           Mutual-reference (pairing) checks — Wrapper <-> Logic
    // =========================================================================

    function test_isConsistentLogicPair_trueForRealPair() public {
        (TestHooksERC721 logic, HooksWrapperERC721 wrapper,) = _deployERC721(admin);
        assertTrue(IntegrityVerifier.isConsistentLogicPair(address(wrapper), address(logic)));
    }

    /// Same asymmetry one layer further out: a fake logic contract can claim a
    /// real wrapper, but that wrapper only names whoever actually deployed it.
    function test_isConsistentLogicPair_catchesImpostorLogic() public {
        (, HooksWrapperERC721 wrapper,) = _deployERC721(admin);
        ImpostorLogic impostor = new ImpostorLogic(address(wrapper));

        assertEq(impostor.wrapper(), address(wrapper), "impostor does claim the real wrapper");
        assertFalse(
            IntegrityVerifier.isConsistentLogicPair(address(wrapper), address(impostor)), "but the round trip must fail"
        );
    }

    function test_isConsistentLogicPair_falseForMismatchedRealPairs() public {
        (TestHooksERC721 logicA,,) = _deployERC721(admin);
        (, HooksWrapperERC721 wrapperB,) = _deployERC721(admin);

        assertFalse(IntegrityVerifier.isConsistentLogicPair(address(wrapperB), address(logicA)));
    }

    function test_isConsistentLogicPair_falseForNonContracts() public view {
        assertFalse(IntegrityVerifier.isConsistentLogicPair(address(0), address(0)));
        assertFalse(IntegrityVerifier.isConsistentLogicPair(address(0xDEAD), address(0xBEEF)));
    }

    // =========================================================================
    //                        ERC-165 discovery
    // =========================================================================

    /// Discovery lives on the WRAPPER now — it's the contract the token actually
    /// calls, and the one whose bytecode is verifiable. Logic implements the
    /// same function shapes but has no ERC-165 obligation of its own; nothing
    /// external ever calls it directly.
    function test_erc165_wrappersDeclareConformance() public {
        (, HooksWrapperERC20 w20,) = _deployERC20(admin);
        (, HooksWrapperERC721 w721,) = _deployERC721(admin);
        (, HooksWrapperERC1155 w1155,) = _deployERC1155(admin);

        assertTrue(w20.supportsInterface(type(IHooksERC20).interfaceId));
        assertTrue(w721.supportsInterface(type(IHooksERC721).interfaceId));
        assertTrue(w1155.supportsInterface(type(IHooksERC1155).interfaceId));
    }

    function test_erc165_unknownInterfaceIsFalse() public {
        (, HooksWrapperERC721 w721,) = _deployERC721(admin);
        assertFalse(w721.supportsInterface(0xdeadbeef));
    }
}
