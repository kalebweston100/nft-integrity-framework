// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../../contracts/token/IntegrityERC20.sol";
import "../../contracts/token/IntegrityERC721.sol";
import "../../contracts/token/IntegrityERC1155.sol";
import "../../contracts/test/TestHooksERC20.sol";
import "../../contracts/test/TestHooksERC721.sol";
import "../../contracts/test/TestHooksERC1155.sol";

/// @notice Shared deployment helpers reused across the test suite. Mirrors the exact
///         deployment flow described in the README: deploying a hooks contract deploys
///         its own token as a side effect of its constructor — no factory involved.
abstract contract Fixtures is Test {
    function _deployERC20(address issuerAdmin) internal returns (TestHooksERC20 hooks, IntegrityERC20 token) {
        hooks = new TestHooksERC20(issuerAdmin, "Test Token", "TST", "ipfs://collection");
        token = hooks.token();
    }

    function _deployERC721(address issuerAdmin) internal returns (TestHooksERC721 hooks, IntegrityERC721 token) {
        hooks = new TestHooksERC721(issuerAdmin, "Test NFT", "TNFT", "ipfs://collection", "ipfs://base/");
        token = hooks.token();
    }

    function _deployERC1155(address issuerAdmin) internal returns (TestHooksERC1155 hooks, IntegrityERC1155 token) {
        hooks = new TestHooksERC1155(issuerAdmin, "ipfs://base/{id}", "ipfs://collection");
        token = hooks.token();
    }
}
