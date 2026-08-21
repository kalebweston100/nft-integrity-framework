//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title HooksAdmin
 * @notice Shared issuer-admin access control for hooks LOGIC contracts —
 *         `HooksLogicERC20/721/1155` each inherit this instead of redeclaring
 *         the same admin bookkeeping three times. Mirrors TokenAdmin.sol on
 *         the token side.
 *
 * Not inherited by `HooksWrapper*` — those are canonical, un-inherited
 * forwarders with no custom behavior to gate. Also deliberately holds no
 * `wrapper`/`onlyWrapper`: `wrapper` is typed per standard and Solidity has no
 * generics, so each `HooksLogicERC*` keeps its own typed `wrapper`,
 * `onlyWrapper`, and constructor (which deploys that standard's wrapper).
 */
abstract contract HooksAdmin {
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    address public issuerAdmin;

    modifier onlyIssuerAdmin() {
        require(msg.sender == issuerAdmin, "Hooks: Not issuer admin");
        _;
    }

    constructor(address _issuerAdmin) {
        require(_issuerAdmin != address(0), "Hooks: Zero admin address");
        issuerAdmin = _issuerAdmin;
    }

    function transferAdmin(address newAdmin) external onlyIssuerAdmin {
        require(newAdmin != address(0), "Hooks: Zero address");
        address oldAdmin = issuerAdmin;
        issuerAdmin = newAdmin;
        emit AdminTransferred(oldAdmin, newAdmin);
    }
}
