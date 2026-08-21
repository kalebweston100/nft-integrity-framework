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
 * "mint on deposit" — but it IS authority, so any hooks author using it should
 * document it prominently rather than relying on a reader to notice the call.
 *
 * There is no ERC-165 marker for this capability. `token` is public on every
 * `Hooks*` base and `hookMint` is gated only on "caller is the governing hooks
 * contract" — so any hooks contract, whether or not it advertises minting, can
 * call it. A declared marker would only ever be a claim an honest author made
 * voluntarily, never something enforceable, so it isn't worth the extra
 * interface: read the hooks contract's source to know whether it mints.
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
