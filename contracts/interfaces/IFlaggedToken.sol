//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title IFlaggedToken
 * @notice Shared read-only interface for the on-chain anti-fraud "flags" system
 *         implemented by IntegrityERC721 and IntegrityERC1155.
 *
 * PURPOSE:
 *   Lets a buyer — or a marketplace widget acting on their behalf — verify, with
 *   a single view call and no trust in the seller or any off-chain claim, that a
 *   specific token really carries the traits/certifications it's being sold on.
 *
 * GUARANTEES (enforced by the concrete token contracts, not by this interface):
 *   - A flag's meaning (its label) can never be redefined once set (append-only registry).
 *   - A token's flag bitmap and metadata hash are committed exactly once, atomically
 *     with mint, and are never writable again by anyone — including the issuer.
 *   - Every bit a token carries corresponds to a flag that has a public, permanent label.
 *
 * Marketplaces built on this standard (e.g. OpenSea via Seaport) never call these
 * functions themselves — they trade the token normally via the standard ERC-721/1155
 * transfer surface. verifyToken/verifyMetadata are meant to be called independently
 * by the buyer (or their tooling) before they commit to a purchase.
 */
interface IFlaggedToken {
    /// @notice Emitted once, atomically with mint, when a token's flags/metadata are committed.
    event FlagsCommitted(uint256 indexed tokenId, uint256 flags, bytes32 metadataHash);

    /// @notice Emitted when the issuer permanently defines the label for a flag bit.
    event FlagDefined(uint8 indexed bitIndex, string label);

    /// @notice Returns true if `tokenId` carries the flag at `bitIndex`.
    function hasFlag(uint256 tokenId, uint8 bitIndex) external view returns (bool);

    /// @notice Returns the full flag bitmap committed to `tokenId`.
    function flagsOf(uint256 tokenId) external view returns (uint256);

    /// @notice Returns the metadata commitment hash for `tokenId`.
    function metadataHashOf(uint256 tokenId) external view returns (bytes32);

    /// @notice Returns the permanent, human-readable label for a flag bit
    ///         (empty string if that bit has never been defined).
    function flagLabel(uint8 bitIndex) external view returns (string memory);

    /// @notice Returns the bitmask of every flag bit that has been given a label so far.
    function definedFlags() external view returns (uint256);

    /// @notice One-call anti-scam check for buyers: does `tokenId` carry every flag in
    ///         `requiredFlagsMask`, and (if non-zero) does its committed metadata hash
    ///         match `expectedMetadataHash`?
    /// @param tokenId The token to check.
    /// @param requiredFlagsMask Bitmask of flags the buyer was told this token has.
    ///                          Pass 0 to skip the flag check.
    /// @param expectedMetadataHash keccak256 of the metadata JSON the buyer was shown.
    ///                             Pass bytes32(0) to skip the metadata check.
    /// @return ok True only if every requested check passes.
    /// @return actualFlags The token's real, committed flag bitmap.
    /// @return actualMetadataHash The token's real, committed metadata hash.
    function verifyToken(uint256 tokenId, uint256 requiredFlagsMask, bytes32 expectedMetadataHash)
        external
        view
        returns (bool ok, uint256 actualFlags, bytes32 actualMetadataHash);

    /// @notice Convenience check: does keccak256(metadata) match the committed hash for `tokenId`?
    function verifyMetadata(uint256 tokenId, bytes calldata metadata) external view returns (bool);
}
