// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./utils/Fixtures.sol";
import "../contracts/libraries/Codehash.sol";

/// @notice Verifies the central claim the new architecture is built on: because
///         IntegrityERC20/721/1155 hold zero `immutable` state (the governing hooks
///         address is plain storage, set once with no setter), two tokens deployed by
///         two completely independent, differently-configured hooks contracts still
///         produce byte-identical runtime bytecode. One published hash per token
///         contract version is enough to verify any deployment of it, forever — see
///         the README's "Verifying a deployment" section.
contract CodehashTest is Fixtures {
    using Codehash for address;

    address internal issuerA = makeAddr("issuerA");
    address internal issuerB = makeAddr("issuerB");

    function test_erc721_codehashIdentical_acrossIndependentHooksDeployments() public {
        (, IntegrityERC721 tokenA) = _deployERC721(issuerA);

        // A second, independently-deployed hooks contract with different constructor
        // args (different admin, name, symbol, URIs) still deploys a token with
        // identical runtime bytecode — only its embedded immutables would differ if
        // it had any, and it has none.
        vm.prank(issuerB);
        TestHooksERC721 hooksB = new TestHooksERC721(
            issuerB, "Totally Different NFT", "DIFF", "ipfs://other-collection", "ipfs://other-base/"
        );
        IntegrityERC721 tokenB = hooksB.token();

        assertEq(address(tokenA).codehash, address(tokenB).codehash);
        assertTrue(Codehash.isCanonical(address(tokenB), address(tokenA).codehash));
    }

    function test_erc20_codehashIdentical_acrossIndependentHooksDeployments() public {
        (, IntegrityERC20 tokenA) = _deployERC20(issuerA);

        vm.prank(issuerB);
        TestHooksERC20 hooksB = new TestHooksERC20(issuerB, "Other Token", "OTH", "ipfs://other-collection");
        IntegrityERC20 tokenB = hooksB.token();

        assertEq(address(tokenA).codehash, address(tokenB).codehash);
    }

    function test_erc1155_codehashIdentical_acrossIndependentHooksDeployments() public {
        (, IntegrityERC1155 tokenA) = _deployERC1155(issuerA);

        vm.prank(issuerB);
        TestHooksERC1155 hooksB = new TestHooksERC1155(issuerB, "ipfs://other/{id}", "ipfs://other-collection");
        IntegrityERC1155 tokenB = hooksB.token();

        assertEq(address(tokenA).codehash, address(tokenB).codehash);
    }

    function test_isCanonical_falseForDifferentBytecode() public {
        (, IntegrityERC721 token) = _deployERC721(issuerA);
        (TestHooksERC721 hooks,) = _deployERC721(issuerB);

        // The token and its own governing hooks contract run different code.
        assertFalse(Codehash.isCanonical(address(hooks), address(token).codehash));
    }

    function test_isCanonical_neverCallsIntoTarget() public {
        // A target with no code at all must simply fail the comparison, not revert —
        // proving the check is a pure EXTCODEHASH read with no external call.
        (, IntegrityERC721 token) = _deployERC721(issuerA);
        assertFalse(Codehash.isCanonical(address(0xDEAD), address(token).codehash));
    }
}
