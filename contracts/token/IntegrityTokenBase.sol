//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "./TokenAdmin.sol";
import "../interfaces/Types.sol";
import "../interfaces/IIntegrityToken.sol";
import "../interfaces/Errors.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title IntegrityTokenBase
 * @notice Abstract base shared by all three token standards: reentrancy
 *         guard, the IIntegrityToken partial implementation
 *         (isIntegrityToken), and collection-level metadata URI. Inherits
 *         TokenAdmin (issuer admin, pause/unpause). `tokenStandard()` is left
 *         abstract for each concrete token to declare.
 *
 * NOTE ON THE HOOKS ADDRESS: each concrete token stores its governing hooks
 * contract as a plain (non-immutable) storage slot, set once in its own
 * constructor from `msg.sender` — the token only ever comes into existence
 * via `new` from inside that hooks contract's constructor, so this is
 * unspoofable, with deliberately no setter. Keeping it out of `immutable`
 * matters: EXTCODEHASH covers only code, not storage, so every canonical
 * deployment stays byte-identical regardless of which hooks contract deployed
 * it — see IntegrityVerifier.sol.
 */
abstract contract IntegrityTokenBase is IIntegrityToken, TokenAdmin, ReentrancyGuard {
    // =========================================================================
    //                     COLLECTION METADATA
    // =========================================================================

    /// @notice Collection-level metadata URI (e.g., OpenSea collection metadata).
    string private _contractURI;

    // =========================================================================
    //                          CONSTRUCTOR
    // =========================================================================

    /// @param admin The initial issuer admin address.
    /// @param initialContractURI Collection-level metadata URI.
    constructor(address admin, string memory initialContractURI) TokenAdmin(admin) {
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
}
