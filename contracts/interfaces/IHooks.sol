//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/// @notice Interface for hooks contracts that support factory initialization and chain-of-trust verification.
interface IInitializableHooks {
    function initializeToken(address _tokenContract) external;
    function factory() external view returns (address);
    function tokenContract() external view returns (address);
}

/// @notice Interface for hooks-initiated minting on IntegrityERC20.
interface IHookMintERC20 {
    function hookMint(address to, uint256 amount) external;
}

/// @notice Interface for hooks-initiated minting and URI setting on IntegrityERC721.
interface IHookMintERC721 {
    function hookMint(address to, uint256 tokenId, uint256 flags, bytes32 metadataHash) external;
    function hookSetTokenURI(uint256 tokenId, string calldata newURI) external;
}

/// @notice Interface for hooks-initiated minting and URI setting on IntegrityERC1155.
interface IHookMintERC1155 {
    function hookMint(address to, uint256 id, uint256 amount, uint256 flags, bytes32 metadataHash) external;
    function hookSetTokenURI(uint256 id, string calldata newURI) external;
}
