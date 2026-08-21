//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title HooksAdmin
 * @notice Shared issuer-admin access control for hooks contracts. Every concrete
 *         `Hooks*` base (HooksERC20/721/1155) inherits this rather than
 *         redeclaring the same admin bookkeeping three times.
 *
 * Deliberately does NOT hold `token` or `onlyToken` — those are typed per
 * standard (IntegrityERC20 vs 721 vs 1155) and Solidity has no generics, so a
 * shared base can't declare a single correctly-typed `token` field for all
 * three. Each `Hooks*` contract keeps its own `token` and `onlyToken`, and its
 * own constructor (which deploys that standard's token via `new`).
 *
 * Mirrors TokenAdmin.sol on the token side, which does the same admin-layer
 * extraction for IntegrityERC20/721/1155.
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
