//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./FactoryBase.sol";
import "../interfaces/ITokenFactory.sol";
import "../token/IntegrityERC1155.sol";

/**
 * @title FactoryERC1155
 * @notice Factory for deploying ERC-1155 framework tokens.
 *
 * DEPLOYMENT FLOW:
 *   1. Developer deploys their hooks contract with factory address — or skips hooks
 *   2. Developer calls factory.deployTokenERC1155(issuerAdmin, hooksAddr, ...)
 *   3. Factory deploys IntegrityERC1155 (the user-facing token) with hooks address
 *   4. Factory initializes hooks (links hooks to token) if hooks are provided
 *   5. Factory finalizes initialization and registers the token
 *
 * The deployed IntegrityERC1155 IS the token users interact with.
 * It holds all token state and calls the hooks contract externally.
 */
contract FactoryERC1155 is FactoryBase, IFactoryERC1155 {
    /// @notice Deploy an ERC-1155 token with optional hooks. Permissionless — anyone
    ///         may deploy, subject only to the configurable deploy fee.
    /// @param issuerAdmin The address that will own and administer the deployed token.
    /// @param hooksAddr Developer's hooks contract (address(0) for no hooks).
    /// @param baseTokenURI The base URI for token metadata.
    /// @return token The deployed token address.
    function deployTokenERC1155(
        address issuerAdmin,
        address hooksAddr,
        string calldata baseTokenURI,
        string calldata contractURI
    ) external payable returns (address token) {
        _checkAndCollectFee();

        // Step 1: Deploy the token (IntegrityERC1155)
        IntegrityERC1155 tokenContract =
            new IntegrityERC1155(address(this), hooksAddr, issuerAdmin, baseTokenURI, contractURI);
        token = address(tokenContract);

        // Step 2: Initialize hooks (link hooks contract to the deployed token)
        _initializeHooks(hooksAddr, token);

        // Step 3: Verify and register
        _verifyAndRegister(token, hooksAddr, issuerAdmin);
    }
}
