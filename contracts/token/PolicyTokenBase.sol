//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";
import "../interfaces/Errors.sol";
import "../interfaces/IPolicyGoverned.sol";
import "../engine/PolicyEngine.sol";
import "../engine/PolicyTypes.sol";

/**
 * @title PolicyTokenBase
 * @notice Storage and admin bookkeeping shared by every token in the canonical
 *         set. Deploys the engine; holds nothing that can block a transfer.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY A SHARED BASE IS SAFE HERE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Ordinarily "inherit this to make your token policy-governed" would destroy
 * the guarantee — an author's subclass can add a `require` anywhere, and the
 * rule array stops being exhaustive. That is why this contract is NOT an
 * extension point and must never be documented as one.
 *
 * The reason it is nonetheless harmless is that the restriction ENFORCES
 * ITSELF, with no marker interface and no honour system:
 *
 *     Verification matches a token's runtime codehash against a fixed,
 *     published set. A contract that inherits this base but is not a member
 *     of that set compiles to different bytecode, so it matches nothing and
 *     is reported as unknown — exactly as an arbitrary ERC-20 would be.
 *
 * So the base can be shared freely for code organisation. What is published is
 * the SET OF HASHES, never the base.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHAT IS DELIBERATELY *NOT* HERE
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * The transfer path. Each token writes its own out flat, even though the three
 * are structurally similar, because that function is where the entire claim
 * lives — every reachable `revert` in it must be either a standard-conformance
 * requirement or the policy verdict. A reader auditing that property should be
 * able to do it in one file, top to bottom, without resolving an inheritance
 * chain. Duplication is the cheaper cost.
 *
 * Also absent, and never to be added: pause, freeze, blocklist, or any other
 * discretionary lever. See PolicyERC20's NatSpec for the full argument.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * ZERO IMMUTABLES — LOAD-BEARING
 * ─────────────────────────────────────────────────────────────────────────────
 *
 * Every field is plain storage written once in the constructor. POLICY_SALT is
 * `constant`, which inlines into bytecode; `immutable` would stop
 * type(C).runtimeCode compiling for every token below and take the whole
 * canonical set with it. The constraint enforces itself — see
 * contracts/verification/CanonicalCode.sol.
 */
abstract contract PolicyTokenBase is IPolicyGoverned {
    // =========================================================================
    //                              ERRORS / EVENTS
    // =========================================================================

    /// @notice The policy denied this transfer, and named the rule that did.
    error PolicyDenied(string reason);

    event IssuerAdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    // =========================================================================
    //                                CONSTANTS
    // =========================================================================

    /// @dev One salt for the whole set. Distinct tokens still get distinct
    ///      engine addresses: a CREATE2 address commits to the deployer and the
    ///      init code, both of which differ per token.
    bytes32 private constant POLICY_SALT = keccak256("PolicyToken.policy.v1");

    // =========================================================================
    //                        STATE — ALL PLAIN STORAGE
    // =========================================================================

    /// @notice The canonical engine holding this token's complete transfer
    ///         policy. Deployed by this contract's constructor. No setter.
    PolicyEngine internal _policy;

    address private _issuerAdmin;

    /// @notice The admin passed to the constructor, recorded once and never
    ///         changed, so a CREATE2 address stays recomputable after a
    ///         handover. See CanonicalCode.isProvenanceVerified.
    address private _deployAdmin;

    // =========================================================================
    //                                MODIFIERS
    // =========================================================================

    modifier onlyIssuerAdmin() {
        if (msg.sender != _issuerAdmin) revert NotIssuerAdmin();
        _;
    }

    // =========================================================================
    //                               CONSTRUCTOR
    // =========================================================================

    /// @notice One transaction deploys the token and its policy together, so
    ///         there is no initializer and no window in which the token exists
    ///         with no policy attached.
    /// @dev The engine needs its notifier (this token) and this token needs the
    ///      engine's address — a cycle at the VALUE level but not at the TYPE
    ///      level, which is all the compiler cares about. PolicyEngine imports
    ///      only PolicyTypes and never names a token, so the dependency graph
    ///      stays acyclic and type(PolicyEngine).creationCode resolves here.
    constructor(address admin, uint256 swapDelay, Rule[] memory initialRules) {
        if (admin == address(0)) revert ZeroAddress();

        _issuerAdmin = admin;
        _deployAdmin = admin;

        _policy = new PolicyEngine{salt: POLICY_SALT}(admin, address(this), swapDelay, initialRules);
    }

    // =========================================================================
    //                        THE INTEGRATOR SURFACE
    // =========================================================================

    /// @inheritdoc IPolicyGoverned
    /// @dev Check the engine's codehash against
    ///      keccak256(type(PolicyEngine).runtimeCode) before trusting what it
    ///      returns. Because this token's code is canonical, this getter and
    ///      the caller in the transfer path read the same setter-less slot.
    function policy() external view returns (address) {
        return address(_policy);
    }

    // =========================================================================
    //                                  ADMIN
    // =========================================================================

    function issuerAdmin() external view returns (address) {
        return _issuerAdmin;
    }

    /// @notice The admin recorded at deployment. Never changes, even after a
    ///         handover.
    function deployAdmin() external view returns (address) {
        return _deployAdmin;
    }

    /// @dev Moves the token's admin only. The engine holds its own admin, set
    ///      to the same address at construction; transferring one does not move
    ///      the other, and a verifier reports both.
    function transferIssuerAdmin(address newAdmin) external onlyIssuerAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        emit IssuerAdminTransferred(_issuerAdmin, newAdmin);
        _issuerAdmin = newAdmin;
    }
}
