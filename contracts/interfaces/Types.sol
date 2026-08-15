//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title Types
 * @notice Shared data types for the token framework.
 */

/**
 * @notice Identifies which token standard a framework token implements.
 * @dev Returned by tokenStandard() on every Integrity* token variant.
 *      Allows external contracts, indexers, and UIs to determine the correct
 *      interaction interface without trial-and-error interface detection.
 *
 * ERC20    Standard fungible token (EIP-20). Single balance per address.
 * ERC721   Standard non-fungible token (EIP-721). Unique tokenId ownership.
 * ERC1155  Multi-token standard (EIP-1155). Per-tokenId balances, batch operations.
 */
enum TokenStandard {
    ERC20,
    ERC721,
    ERC1155
}
