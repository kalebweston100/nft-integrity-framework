//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./FactoryBase.sol";
import "../interfaces/ITokenFactory.sol";
import "../token/IntegrityERC721.sol";

/**
 * @title FactoryERC721
 * @notice Factory for deploying ERC-721 framework tokens.
 *
 * DEPLOYMENT FLOW:
 *   1. Developer deploys their hooks contract with factory address — or skips hooks
 *   2. Developer calls factory.deployTokenERC721(issuerAdmin, hooksAddr, ...)
 *   3. Factory deploys IntegrityERC721 (the user-facing token) with hooks address
 *   4. Factory initializes hooks (links hooks to token) if hooks are provided
 *   5. Factory finalizes initialization and registers the token
 *
 * The deployed IntegrityERC721 IS the token users interact with.
 * It holds all token state (including the anti-fraud flags system) and calls
 * the hooks contract externally.
 */
contract FactoryERC721 is FactoryBase, IFactoryERC721 {
    /// @notice Deploy an ERC-721 token with optional hooks. Permissionless — anyone
    ///         may deploy, subject only to the configurable deploy fee.
    /// @param issuerAdmin The address that will own and administer the deployed token.
    /// @param hooksAddr Developer's hooks contract (address(0) for no hooks).
    /// @param tokenName The token's display name.
    /// @param tokenSymbol The token's ticker symbol.
    /// @return token The deployed token address.
    function deployTokenERC721(
        address issuerAdmin,
        address hooksAddr,
        string calldata tokenName,
        string calldata tokenSymbol,
        string calldata contractURI,
        string calldata baseURI
    ) external payable returns (address token) {
        _checkAndCollectFee();

        // Step 1: Deploy the token (IntegrityERC721)
        IntegrityERC721 tokenContract =
            new IntegrityERC721(address(this), hooksAddr, issuerAdmin, tokenName, tokenSymbol, contractURI, baseURI);
        token = address(tokenContract);

        // Step 2: Initialize hooks (link hooks contract to the deployed token)
        _initializeHooks(hooksAddr, token);

        // Step 3: Verify and register
        _verifyAndRegister(token, hooksAddr, issuerAdmin);
    }
}
