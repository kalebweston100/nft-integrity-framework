// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";
import "../contracts/libraries/IntegrityVerifier.sol";
import "../contracts/interfaces/IHooksERC20.sol";
import "../contracts/interfaces/IHooksERC721.sol";
import "../contracts/interfaces/IHooksERC1155.sol";

/// @dev Impersonates a legitimate token it does not govern, to exercise the
///      mutual-reference check.
contract ImpostorHooks {
    address public token;

    constructor(address stolenToken) {
        token = stolenToken;
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
        (, IntegrityERC721 a) = _deployERC721(admin);
        (, IntegrityERC721 b) = _deployERC721(address(0xD00D));

        bytes32 derived = IntegrityVerifier.canonicalERC721Hash();

        assertEq(derived, address(a).codehash, "derived hash must match a real deployment");
        assertEq(derived, address(b).codehash, "and a second, independently configured one");
    }

    function test_compileTimeHash_allThreeStandards() public {
        (, IntegrityERC20 t20) = _deployERC20(admin);
        (, IntegrityERC721 t721) = _deployERC721(admin);
        (, IntegrityERC1155 t1155) = _deployERC1155(admin);

        assertEq(IntegrityVerifier.canonicalERC20Hash(), address(t20).codehash);
        assertEq(IntegrityVerifier.canonicalERC721Hash(), address(t721).codehash);
        assertEq(IntegrityVerifier.canonicalERC1155Hash(), address(t1155).codehash);
    }

    /// Tokens deployed by differently-configured hooks contracts stay byte-identical,
    /// which is what lets one hash verify every deployment.
    function test_codehashIdentical_acrossIndependentHooksDeployments() public {
        (, IntegrityERC20 a) = _deployERC20(admin);
        TestHooksERC20 otherHooks = new TestHooksERC20(address(0xD00D), "Other", "OTH", "ipfs://other");
        IntegrityERC20 b = otherHooks.token();

        assertTrue(address(a) != address(b), "different deployments");
        assertEq(address(a).codehash, address(b).codehash, "identical runtime bytecode");
    }

    function test_isCanonical_oneCallHelpers() public {
        (, IntegrityERC20 t20) = _deployERC20(admin);
        (, IntegrityERC721 t721) = _deployERC721(admin);
        (, IntegrityERC1155 t1155) = _deployERC1155(admin);

        assertTrue(IntegrityVerifier.isCanonicalERC20(address(t20)));
        assertTrue(IntegrityVerifier.isCanonicalERC721(address(t721)));
        assertTrue(IntegrityVerifier.isCanonicalERC1155(address(t1155)));

        // Cross-standard and non-token addresses must not pass.
        assertFalse(IntegrityVerifier.isCanonicalERC721(address(t20)));
        assertFalse(IntegrityVerifier.isCanonicalERC721(address(this)));
        assertFalse(IntegrityVerifier.isCanonicalERC721(address(0xDEAD)));
    }

    /// EXTCODEHASH is read by the EVM from the target's own deployed bytecode, so
    /// the check cannot be spoofed by the contract under inspection.
    function test_isCanonical_neverCallsIntoTarget() public {
        (, IntegrityERC721 token) = _deployERC721(admin);
        // No call is made, so no state is touched and a hostile fallback is unreachable.
        assertTrue(IntegrityVerifier.isCanonical(address(token), IntegrityVerifier.canonicalERC721Hash()));
        assertFalse(IntegrityVerifier.isCanonical(address(token), bytes32(uint256(1))));
    }

    // =========================================================================
    //                    Mutual-reference (pairing) check
    // =========================================================================

    function test_isConsistentPair_trueForRealPair() public {
        (TestHooksERC721 hooks, IntegrityERC721 token) = _deployERC721(admin);
        assertTrue(IntegrityVerifier.isConsistentPair(address(token), address(hooks)));
    }

    /// A fake hooks contract can name someone else's real token, but that token
    /// will not name it back — the unspoofable direction closes the spoofable one.
    function test_isConsistentPair_catchesImpostorHooks() public {
        (, IntegrityERC721 token) = _deployERC721(admin);
        ImpostorHooks impostor = new ImpostorHooks(address(token));

        assertEq(impostor.token(), address(token), "impostor does claim the real token");
        assertFalse(
            IntegrityVerifier.isConsistentPair(address(token), address(impostor)), "but the round trip must fail"
        );
    }

    function test_isConsistentPair_falseForMismatchedRealPairs() public {
        (TestHooksERC721 hooksA,) = _deployERC721(admin);
        (, IntegrityERC721 tokenB) = _deployERC721(admin);

        assertFalse(IntegrityVerifier.isConsistentPair(address(tokenB), address(hooksA)));
    }

    function test_isConsistentPair_falseForNonContracts() public view {
        assertFalse(IntegrityVerifier.isConsistentPair(address(0), address(0)));
        assertFalse(IntegrityVerifier.isConsistentPair(address(0xDEAD), address(0xBEEF)));
    }

    // =========================================================================
    //                        ERC-165 discovery
    // =========================================================================

    function test_erc165_hooksDeclareConformance() public {
        (TestHooksERC20 h20,) = _deployERC20(admin);
        (TestHooksERC721 h721,) = _deployERC721(admin);
        (TestHooksERC1155 h1155,) = _deployERC1155(admin);

        assertTrue(h20.supportsInterface(type(IHooksERC20).interfaceId));
        assertTrue(h721.supportsInterface(type(IHooksERC721).interfaceId));
        assertTrue(h1155.supportsInterface(type(IHooksERC1155).interfaceId));
    }

    function test_erc165_unknownInterfaceIsFalse() public {
        (TestHooksERC721 h721,) = _deployERC721(admin);
        assertFalse(h721.supportsInterface(0xdeadbeef));
    }
}
