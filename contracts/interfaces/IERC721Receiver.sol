//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @notice Interface for contracts that want to support safe ERC-721 token transfers.
interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}
