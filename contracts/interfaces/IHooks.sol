//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title Hook-initiated mint entry points (token side)
 * @notice These are the ONLY functions through which a hooks contract can write
 *         token state. Everything else in the hooks calling convention is
 *         deny-only: a hook can refuse an action, never cause one.
 *
 * A token that exposes any of these grants its hooks contract real minting
 * authority. That is a deliberate, narrow capability for use cases like
 * "mint on deposit" — but it IS authority, and it must be discoverable rather
 * than buried in documentation. A hooks contract that uses it declares
 * IHookMinter via ERC-165 so an integrator can detect it from the hooks address
 * alone. See IHookMinter below.
 */

/// @notice Hook-initiated minting on IntegrityERC20.
interface IHookMintERC20 {
    function hookMint(address to, uint256 amount) external;
}

/// @notice Hook-initiated minting and per-token URI setting on IntegrityERC721.
interface IHookMintERC721 {
    function hookMint(address to, uint256 tokenId) external;
    function hookSetTokenURI(uint256 tokenId, string calldata newURI) external;
}

/// @notice Hook-initiated minting and per-id URI setting on IntegrityERC1155.
interface IHookMintERC1155 {
    function hookMint(address to, uint256 id, uint256 amount) external;
    function hookSetTokenURI(uint256 id, string calldata newURI) external;
}

/**
 * @title IHookMinter
 * @notice Optional capability marker, declared by a HOOKS contract via ERC-165.
 *
 * The core IHooksERC20/721/1155 interfaces describe a deny-only calling
 * convention: every function in them can block an action but none can cause
 * one. A hooks contract that additionally holds minting authority over its
 * token — i.e. one that calls `hookMint` — MUST also return true from
 * `supportsInterface(type(IHookMinter).interfaceId)`.
 *
 * This turns the framework's single largest trust caveat into a machine-readable
 * bit. An integrator reading a hooks address can distinguish:
 *
 *   supportsInterface(IHooksERC721)  && !supportsInterface(IHookMinter)
 *       → this hooks contract can only restrict; supply is issuer-admin-gated.
 *
 *   supportsInterface(IHooksERC721)  &&  supportsInterface(IHookMinter)
 *       → this hooks contract can mint at will; its logic is part of the
 *         token's supply policy and must be read before trusting supply.
 *
 * NOTE ON WHAT ERC-165 CAN AND CANNOT TELL YOU: declaring an interface is a
 * claim, not a proof. A hostile hooks contract can omit IHookMinter and still
 * mint, or declare conformance it does not honour. This bit is a good-faith
 * disclosure that makes honest integrations legible — it is NOT a security
 * boundary. The only way to know what a hooks contract actually does is to read
 * its code and verify the deployment runs that code (see
 * contracts/libraries/IntegrityVerifier.sol).
 */
interface IHookMinter {
    /// @notice Marker only — never called. Present so the interface has a stable
    ///         ERC-165 id. Implementations return the address of the token whose
    ///         minting authority this hooks contract holds.
    function mintingAuthorityOver() external view returns (address);
}
