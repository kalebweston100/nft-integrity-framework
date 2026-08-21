// SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "forge-std/Test.sol";
import "../../contracts/token/IntegrityERC20.sol";
import "../../contracts/token/IntegrityERC721.sol";
import "../../contracts/token/IntegrityERC1155.sol";
import "../../contracts/hooks/HooksWrapperERC20.sol";
import "../../contracts/hooks/HooksWrapperERC721.sol";
import "../../contracts/hooks/HooksWrapperERC1155.sol";
import "../../contracts/test/TestHooksERC20.sol";
import "../../contracts/test/TestHooksERC721.sol";
import "../../contracts/test/TestHooksERC1155.sol";

/// @notice Shared deployment helpers reused across the test suite. Mirrors the
///         exact chain described in the README: deploying a logic contract
///         deploys a wrapper, which deploys the token — three `new` calls,
///         chained, one transaction. No factory involved.
abstract contract Fixtures is Test {
    function _deployERC20(address issuerAdmin)
        internal
        returns (TestHooksERC20 logic, HooksWrapperERC20 wrapper, IntegrityERC20 token)
    {
        logic = new TestHooksERC20(issuerAdmin, "Test Token", "TST", "ipfs://collection");
        wrapper = logic.wrapper();
        token = wrapper.token();
    }

    function _deployERC721(address issuerAdmin)
        internal
        returns (TestHooksERC721 logic, HooksWrapperERC721 wrapper, IntegrityERC721 token)
    {
        logic = new TestHooksERC721(issuerAdmin, "Test NFT", "TNFT", "ipfs://collection", "ipfs://base/");
        wrapper = logic.wrapper();
        token = wrapper.token();
    }

    function _deployERC1155(address issuerAdmin)
        internal
        returns (TestHooksERC1155 logic, HooksWrapperERC1155 wrapper, IntegrityERC1155 token)
    {
        logic = new TestHooksERC1155(issuerAdmin, "ipfs://base/{id}", "ipfs://collection");
        wrapper = logic.wrapper();
        token = wrapper.token();
    }
}
