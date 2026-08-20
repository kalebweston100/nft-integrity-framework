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
 *   - Reentrancy guard
 *   - IIntegrityToken partial implementation (isIntegrityToken)
 *   - issuedAt timestamp
 *   - Collection-level metadata URI
 *
 * INHERITS:
 *   TokenAdmin — issuer admin, pause/unpause
 *
 * SECURITY:
 *   - Reentrancy guard protects the transfer/mint pipeline
 *   - All state variables are private with internal accessors where needed
 *   - tokenStandard() is left abstract — each concrete token must declare its standard
 *
 * NOTE ON THE HOOKS ADDRESS: each concrete token (IntegrityERC20/721/1155) stores its
 * own governing hooks-contract address as a plain (non-immutable, non-constant)
 * storage slot, set exactly once in its own constructor from `msg.sender` — the token
 * only ever comes into existence via `new` from inside a hooks contract's own
 * constructor, so `msg.sender` there is always that hooks contract, never spoofable.
 * There is deliberately no setter anywhere in the token's source. Keeping this out of
 * `immutable` matters: EXTCODEHASH never includes storage, only code, so a plain
 * storage slot (unlike an immutable, which gets baked into runtime bytecode as a
 * literal) keeps every canonical deployment of a given token contract byte-identical
 * regardless of which hooks contract deployed it — see Codehash.sol.
 */
abstract contract IntegrityTokenBase is IIntegrityToken, TokenAdmin, ReentrancyGuard {
    // =========================================================================
    //                     COLLECTION METADATA
    // =========================================================================

    uint256 private _issuedAt;

    /// @notice Collection-level metadata URI (e.g., OpenSea collection metadata).
    string private _contractURI;

    // =========================================================================
    //                          CONSTRUCTOR
    // =========================================================================

    /// @param admin The initial issuer admin address.
    /// @param initialContractURI Collection-level metadata URI.
    constructor(address admin, string memory initialContractURI) TokenAdmin(admin) {
        _issuedAt = block.timestamp;
        _contractURI = initialContractURI;
    }

    // =========================================================================
    //                     IIntegrityToken IMPLEMENTATION
    // =========================================================================

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
