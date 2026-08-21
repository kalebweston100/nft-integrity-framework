//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

/**
 * @title HooksAdmin
 * @notice Shared issuer-admin access control for hooks LOGIC contracts. Every
 *         `HooksLogicERC20/721/1155` base (the abstract contract a developer's
 *         custom hooks logic inherits) inherits this rather than redeclaring the
 *         same admin bookkeeping three times.
 *
 * Deliberately not inherited by the `HooksWrapper*` contracts — those are
 * canonical, un-inherited, parameterless-admin forwarders with no custom
 * behavior of their own to gate. Admin-gated custom functions belong on the
 * author's logic contract, which is what this base serves.
 *
 * Deliberately does NOT hold `wrapper` or `onlyWrapper` — `wrapper` is typed per
 * standard (HooksWrapperERC20 vs 721 vs 1155) and Solidity has no generics, so a
 * shared base can't declare a single correctly-typed field for all three. Each
 * `HooksLogicERC*` contract keeps its own `wrapper` and `onlyWrapper`, and its
 * own constructor (which deploys that standard's wrapper via `new`).
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
