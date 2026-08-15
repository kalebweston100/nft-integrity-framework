//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title ITokenFactory
 * @notice Base interface shared by all standard-specific factory interfaces.
 *         Exposes chain-of-trust verification and deploy fee functions common to every factory.
 */
interface ITokenFactory {
    function deployedByFactory(address token) external view returns (bool);
    function deployFee() external view returns (uint256);
}

interface IFactoryERC20 is ITokenFactory {
    function deployTokenERC20(
        address issuerAdmin,
        address hooksAddr,
        string calldata tokenName,
        string calldata tokenSymbol,
        string calldata contractURI
    ) external payable returns (address token);
}

interface IFactoryERC721 is ITokenFactory {
    function deployTokenERC721(
        address issuerAdmin,
        address hooksAddr,
        string calldata tokenName,
        string calldata tokenSymbol,
        string calldata contractURI,
        string calldata baseURI
    ) external payable returns (address token);
}

interface IFactoryERC1155 is ITokenFactory {
    function deployTokenERC1155(
        address issuerAdmin,
        address hooksAddr,
        string calldata baseTokenURI,
        string calldata contractURI
    ) external payable returns (address token);
}
