//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Errors.sol";

/**
 * @title TokenAdmin
 * @notice Administrative controls for framework tokens: issuer admin,
 *         pause/unpause, and admin transfer.
 *
 * SECURITY MODEL:
 *   - issuerAdmin is set at construction (deployer) and can be transferred.
 *   - Pause state is stored here with public pause()/unpause() gated by onlyIssuerAdmin.
 *   - _isPaused() is non-virtual — issuers cannot fake the pause state.
 *
 * INHERITANCE NOTE:
 *   This contract is fully standalone (no parent contract). All three token standard
 *   variants (ERC-20, ERC-721, ERC-1155) share this admin layer. Storage is merged
 *   at the IntegrityTokenBase level.
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

    /// @dev Internal accessor for child contracts that need the admin address.
    function _getIssuerAdmin() internal view returns (address) {
        return _issuerAdmin;
    }
}
