//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./TokenAdmin.sol";
import "../interfaces/Types.sol";
import "../interfaces/IIntegrityToken.sol";
import "../interfaces/Errors.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title IntegrityTokenBase
 * @notice Abstract base for all framework token contracts. Provides the shared
 *         infrastructure that is identical across ERC-20, ERC-721, and ERC-1155:
 *
 *   - Factory immutable + chain-of-trust getters
 *   - Reentrancy guard
 *   - IIntegrityToken partial implementation (isIntegrityToken)
 *   - issuedAt timestamp
 *   - Collection-level metadata URI
 *
 * INHERITS:
 *   TokenAdmin — issuer admin, pause/unpause
 *
 * SECURITY:
 *   - Factory is immutable — set at deployment, cannot be changed
 *   - Reentrancy guard protects the transfer/mint pipeline
 *   - All state variables are private with internal accessors where needed
 *   - tokenStandard() is left abstract — each concrete token must declare its standard
 */
abstract contract IntegrityTokenBase is IIntegrityToken, TokenAdmin, ReentrancyGuard {
    // =========================================================================
    //                     IMMUTABLE DEPLOYMENT STATE
    // =========================================================================

    /// @notice The factory that deployed this token.
    address private immutable _factory;

    // =========================================================================
    //                     COLLECTION METADATA
    // =========================================================================

    uint256 private _issuedAt;

    /// @notice Collection-level metadata URI (e.g., OpenSea collection metadata).
    string private _contractURI;

    // =========================================================================
    //                          CONSTRUCTOR
    // =========================================================================

    /// @param factoryAddr The deploying factory address.
    /// @param admin The initial issuer admin address.
    /// @param initialContractURI Collection-level metadata URI.
    constructor(address factoryAddr, address admin, string memory initialContractURI) TokenAdmin(admin) {
        if (factoryAddr == address(0)) revert ZeroAddress();

        _factory = factoryAddr;
        _issuedAt = block.timestamp;
        _contractURI = initialContractURI;
    }

    // =========================================================================
    //                     IIntegrityToken IMPLEMENTATION
    // =========================================================================

    function factory() external view override returns (address) {
        return _factory;
    }

    function isIntegrityToken() external pure override returns (bool) {
        return true;
    }

    // tokenStandard() is left abstract — each concrete token must implement it

    // =========================================================================
    //                     COLLECTION METADATA FUNCTIONS
    // =========================================================================

    /// @notice Returns the collection-level metadata URI.
    function contractURI() external view returns (string memory) {
        return _contractURI;
    }

    /// @notice Set the collection-level metadata URI. Only callable by issuer admin.
    function setContractURI(string calldata newContractURI) external onlyIssuerAdmin {
        _contractURI = newContractURI;
        emit ContractURIUpdated(newContractURI);
    }

    event ContractURIUpdated(string newContractURI);

    // =========================================================================
    //                          VIEW FUNCTIONS
    // =========================================================================

    function issuedAt() external view returns (uint256) {
        return _issuedAt;
    }
}
