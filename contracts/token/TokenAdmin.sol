//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Errors.sol";

/**
 * @title TokenAdmin
 * @notice Administrative controls shared by all three token standards: issuer
 *         admin, pause/unpause, admin transfer. Fully standalone (no parent);
 *         storage is merged in at IntegrityTokenBase. `_isPaused()` is
 *         non-virtual so issuers can't fake the pause state.
 */
abstract contract TokenAdmin {
    // =========================================================================
    //                        ADMINISTRATIVE EVENTS
    // =========================================================================

    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event IssuerAdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    // =========================================================================
    //                          STATE VARIABLES
    // =========================================================================

    /// @notice The token issuer's admin address.
    address private _issuerAdmin;

    /// @notice Whether the token is currently paused.
    bool private _paused;

    /// @notice The issuer admin supplied to the constructor, recorded once and
    ///         never changed — `transferIssuerAdmin` moves `_issuerAdmin` but
    ///         never this. Plain storage, no setter.
    /// @dev    Exists so a verifier can reconstruct the token's original
    ///         constructor arguments and recompute its CREATE2 address; without
    ///         it, an admin transfer would make the deployment unverifiable.
    ///         See IntegrityVerifier.isProvenanceVerified*.
    address private _deployAdmin;

    // =========================================================================
    //                             MODIFIERS
    // =========================================================================

    modifier onlyIssuerAdmin() {
        if (msg.sender != _issuerAdmin) revert NotIssuerAdmin();
        _;
    }

    modifier whenNotPaused() {
        if (_paused) revert TokenPaused();
        _;
    }

    // =========================================================================
    //                            CONSTRUCTOR
    // =========================================================================

    /// @param admin The initial issuer admin address (typically msg.sender from child).
    constructor(address admin) {
        _issuerAdmin = admin;
        _deployAdmin = admin;
    }

    // =========================================================================
    //                        PAUSE / UNPAUSE
    // =========================================================================

    /// @notice Pauses all token transfers. Only the issuer admin can call this.
    function pause() external onlyIssuerAdmin {
        if (_paused) revert AlreadyPaused();
        _paused = true;
        emit Paused(msg.sender);
    }

    /// @notice Unpauses token transfers. Only the issuer admin can call this.
    function unpause() external onlyIssuerAdmin {
        if (!_paused) revert NotPaused();
        _paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Returns whether the token is currently paused.
    /// @dev Non-virtual — issuers cannot override the pause check.
    function _isPaused() internal view returns (bool) {
        return _paused;
    }

    /// @notice Public view for pause state.
    function paused() external view returns (bool) {
        return _paused;
    }

    function transferIssuerAdmin(address newAdmin) external onlyIssuerAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        emit IssuerAdminTransferred(_issuerAdmin, newAdmin);
        _issuerAdmin = newAdmin;
    }

    /// @notice Returns the current issuer admin address.
    function issuerAdmin() external view returns (address) {
        return _issuerAdmin;
    }

    /// @notice The issuer admin recorded at deployment. Never changes, even
    ///         after `transferIssuerAdmin`. Needed to recompute this token's
    ///         CREATE2 address — see IntegrityVerifier.isProvenanceVerified*.
    function deployAdmin() external view returns (address) {
        return _deployAdmin;
    }

    /// @dev Internal accessor for child contracts that need the admin address.
    function _getIssuerAdmin() internal view returns (address) {
        return _issuerAdmin;
    }
}
