//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./Types.sol";

/**
 * @title IIntegrityToken
 * @notice Base interface that ALL tokens in this framework expose, regardless
 *         of token standard (ERC-20, ERC-721, ERC-1155).
 *
 * This interface defines the shared surface: which hooks contract governs the
 * token's behavior (the same contract that deployed it — see IntegrityTokenBase),
 * and how to tell the standard-specific concrete contract apart from an impostor.
 * Standard-specific
 * transfer surfaces use the official OpenZeppelin interfaces:
 *   - IERC20   (openzeppelin/contracts/token/ERC20/IERC20.sol)
 *   - IERC721  (openzeppelin/contracts/token/ERC721/IERC721.sol)
 *   - IERC1155 (openzeppelin/contracts/token/ERC1155/IERC1155.sol)
 *
 * Each Integrity* token contract implements the official ERC standard directly
 * alongside this interface.
 */
interface IIntegrityToken {
    /// @notice Returns whether this contract implements the IIntegrityToken interface.
    function isIntegrityToken() external pure returns (bool);

    /// @notice Returns which token standard (ERC-20, ERC-721, ERC-1155) this token implements.
    /// @dev Allows external contracts, indexers, and UIs to determine the correct
    ///      interaction interface without trial-and-error interface detection.
    function tokenStandard() external pure returns (TokenStandard);

    /// @notice Returns the hooks contract that deployed and governs this token.
    ///         Every token has exactly one — it's the contract that called `new`
    ///         on this token in the first place, so it can never be address(0).
    function hooksContract() external view returns (address);

    /// @notice Returns the collection-level metadata URI (e.g., OpenSea contract metadata).
    function contractURI() external view returns (string memory);
}
