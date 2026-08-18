// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../../contracts/factory/FactoryERC20.sol";
import "../../contracts/factory/FactoryERC721.sol";
import "../../contracts/factory/FactoryERC1155.sol";
import "../../contracts/token/IntegrityERC20.sol";
import "../../contracts/token/IntegrityERC721.sol";
import "../../contracts/token/IntegrityERC1155.sol";
import "../../contracts/test/TestHooksERC20.sol";
import "../../contracts/test/TestHooksERC721.sol";
import "../../contracts/test/TestHooksERC1155.sol";

/// @notice Shared deployment helpers reused across the test suite. Mirrors the exact
///         deployment flow described in the README: deploy hooks with the factory
///         address, deploy the token through the factory, factory wires hooks<->token.
abstract contract Fixtures is Test {
    function _deployERC20(address issuerAdmin)
        internal
        returns (FactoryERC20 factory, TestHooksERC20 hooks, IntegrityERC20 token)
    {
        factory = new FactoryERC20();
        hooks = new TestHooksERC20(address(factory), issuerAdmin);
        address tokenAddr =
            factory.deployTokenERC20(issuerAdmin, address(hooks), "Test Token", "TST", "ipfs://collection");
        token = IntegrityERC20(tokenAddr);
    }

    function _deployERC20NoHooks(address issuerAdmin) internal returns (FactoryERC20 factory, IntegrityERC20 token) {
        factory = new FactoryERC20();
        address tokenAddr = factory.deployTokenERC20(issuerAdmin, address(0), "Test Token", "TST", "ipfs://collection");
        token = IntegrityERC20(tokenAddr);
    }

    function _deployERC721(address issuerAdmin)
        internal
        returns (FactoryERC721 factory, TestHooksERC721 hooks, IntegrityERC721 token)
    {
        factory = new FactoryERC721();
        hooks = new TestHooksERC721(address(factory), issuerAdmin);
        address tokenAddr = factory.deployTokenERC721(
            issuerAdmin, address(hooks), "Test NFT", "TNFT", "ipfs://collection", "ipfs://base/"
        );
        token = IntegrityERC721(tokenAddr);
    }

    function _deployERC721NoHooks(address issuerAdmin) internal returns (FactoryERC721 factory, IntegrityERC721 token) {
        factory = new FactoryERC721();
        address tokenAddr =
            factory.deployTokenERC721(issuerAdmin, address(0), "Test NFT", "TNFT", "ipfs://collection", "ipfs://base/");
        token = IntegrityERC721(tokenAddr);
    }

    function _deployERC1155(address issuerAdmin)
        internal
        returns (FactoryERC1155 factory, TestHooksERC1155 hooks, IntegrityERC1155 token)
    {
        factory = new FactoryERC1155();
        hooks = new TestHooksERC1155(address(factory), issuerAdmin);
        address tokenAddr =
            factory.deployTokenERC1155(issuerAdmin, address(hooks), "ipfs://base/{id}", "ipfs://collection");
        token = IntegrityERC1155(tokenAddr);
    }

    function _deployERC1155NoHooks(address issuerAdmin)
        internal
        returns (FactoryERC1155 factory, IntegrityERC1155 token)
    {
        factory = new FactoryERC1155();
        address tokenAddr = factory.deployTokenERC1155(issuerAdmin, address(0), "ipfs://base/{id}", "ipfs://collection");
        token = IntegrityERC1155(tokenAddr);
    }
}
