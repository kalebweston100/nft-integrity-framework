//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./FactoryBase.sol";
import "../interfaces/ITokenFactory.sol";
import "../token/IntegrityERC20.sol";

/**
 * @title FactoryERC20
 * @notice Factory for deploying ERC-20 framework tokens.
 *
 * DEPLOYMENT FLOW:
 *   1. Developer deploys their hooks contract with factory address — or skips hooks
 *   2. Developer calls factory.deployTokenERC20(issuerAdmin, hooksAddr, ...)
 *   3. Factory deploys IntegrityERC20 (the user-facing token) with hooks address
 *   4. Factory initializes hooks (links hooks to token) if hooks are provided
 *   5. Factory registers the token
 *
 * The deployed IntegrityERC20 IS the token users interact with.
 * It holds all token state and calls the hooks contract externally.
 */
contract FactoryERC20 is FactoryBase, IFactoryERC20 {
    /// @notice Deploy an ERC-20 token with optional hooks. Permissionless — anyone
    ///         may deploy, subject only to the configurable deploy fee.
    /// @param issuerAdmin The address that will own and administer the deployed token.
    /// @param hooksAddr Developer's hooks contract (address(0) for no hooks).
    /// @param tokenName The token's display name.
    /// @param tokenSymbol The token's ticker symbol.
    /// @return token The deployed token address.
    function deployTokenERC20(
        address issuerAdmin,
        address hooksAddr,
        string calldata tokenName,
        string calldata tokenSymbol,
        string calldata contractURI
    ) external payable returns (address token) {
        _checkAndCollectFee();

        // Step 1: Deploy the token (IntegrityERC20)
        IntegrityERC20 tokenContract =
            new IntegrityERC20(address(this), hooksAddr, issuerAdmin, tokenName, tokenSymbol, contractURI);
        token = address(tokenContract);

        // Step 2: Initialize hooks (link hooks contract to the deployed token)
        _initializeHooks(hooksAddr, token);

        // Step 3: Verify and register
        _verifyAndRegister(token, hooksAddr, issuerAdmin);
    }
}
