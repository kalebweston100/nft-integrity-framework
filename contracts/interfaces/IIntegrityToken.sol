//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./Types.sol";

/**
 * @title IIntegrityToken
 * @notice Base interface every token in this framework exposes (ERC-20, 721,
 *         1155): which hooks contract governs it (see IntegrityTokenBase) and
 *         how to tell the concrete contract apart from an impostor.
 *         Standard-specific transfer surfaces use the official OpenZeppelin
 *         interfaces (IERC20/IERC721/IERC1155) directly alongside this one.
 */
interface IIntegrityToken {
    /// @notice Whether this contract implements IIntegrityToken.
    function isIntegrityToken() external pure returns (bool);

    /// @notice Which token standard this token implements — lets external
    ///         contracts, indexers, and UIs pick the right interaction
    ///         interface without trial-and-error detection.
    function tokenStandard() external pure returns (TokenStandard);

    /// @notice The hooks contract that deployed and governs this token. Never
    ///         address(0) — it's the contract that called `new` on this token.
    function hooksContract() external view returns (address);

    /// @notice Collection-level metadata URI (e.g. OpenSea contract metadata).
    function contractURI() external view returns (string memory);
}
