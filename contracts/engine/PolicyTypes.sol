//SPDX-License-Identifier: MIT
pragma solidity ^0.8.34;

import "../interfaces/Types.sol";

/**
 * @title PolicyTypes
 * @notice The data a declarative transfer policy is written in.
 *
 * @dev Policy is DATA, not code. A rule is a struct in storage, not a function
 *      in bytecode — which is what lets one canonical PolicyEngine serve every
 *      issuer while remaining byte-identical, and therefore hash-verifiable.
 */

/**
 * @notice The complete vocabulary of conditions a policy can express.
 *
 * @dev Deliberately finite. A fixed vocabulary is what makes a policy
 *      ENUMERABLE — an integrator can read the rules and render them in a UI,
 *      and because the engine's code is canonical, no condition outside this
 *      list can exist. An open-ended expression language would be code again,
 *      and would give back exactly the property this design exists to provide.
 *
 * Allowlist     Both parties must be listed in `ref`. Skips the zero address,
 *               so mint and burn are not blocked by it.
 * Blocklist     Neither party may be listed in `ref`.
 * Frozen        Neither party may be individually frozen in `ref`.
 * LockupUntil   No transfer settles before `value` (unix timestamp).
 * MaxTransfer   A single transfer may not exceed `value`.
 * MaxBalance    Recipient balance after the transfer may not exceed `value`.
 * MaxBalanceBps Same, as `value` basis points of total supply.
 * MinHoldTime   Sender must have held for `value` seconds since last receipt.
 * HolderCap     Distinct holder count may not exceed `value`.
 * ExternalGate  Defers to arbitrary code at `ref`. THE ESCAPE HATCH — see
 *               PolicyEngine.hasExternalGate().
 */
enum RuleKind {
    Allowlist,
    Blocklist,
    Frozen,
    LockupUntil,
    MaxTransfer,
    MaxBalance,
    MaxBalanceBps,
    MinHoldTime,
    HolderCap,
    ExternalGate
}

/**
 * @notice One condition. Rules are ANDed: every rule must pass.
 *
 * @dev No OR and no nesting, on purpose — see RuleKind. Fields are left
 *      unpacked for legibility; a production version would pack `kind`,
 *      `scoped` and a narrowed `value` into fewer slots.
 *
 * @param kind    Which condition this is.
 * @param value   Numeric parameter — timestamp, cap, bps, or seconds.
 * @param ref     Registry or gate address, for kinds that consult one.
 * @param scoped  ERC-1155 only: restrict this rule to a single token id.
 * @param scopeId The id it is restricted to when `scoped` is true. Ignored
 *                otherwise, since id 0 is itself a valid ERC-1155 id.
 */
struct Rule {
    RuleKind kind;
    uint256 value;
    address ref;
    bool scoped;
    uint256 scopeId;
}

/**
 * @notice Everything a rule may consult about a pending transfer.
 *
 * @dev The token PUSHES this; the policy never calls back to fetch it. That is
 *      what lets balance-dependent rules exist without breaking the framework's
 *      one-directional invariant (Token -> Wrapper -> Policy, never the
 *      reverse).
 *
 *      One struct covers all three standards. ERC-20 leaves `id` at 0; ERC-721
 *      sets `amount` to 1; ERC-1155 uses both. `totalSupply` is per-id for
 *      ERC-1155.
 *
 *      Balances are the values BEFORE the transfer settles.
 */
struct TransferContext {
    TokenStandard standard;
    address from;
    address to;
    uint256 id;
    uint256 amount;
    uint256 fromBalance;
    uint256 toBalance;
    uint256 totalSupply;
    uint256 holderCount;
}

/// @notice Membership oracle for Allowlist / Blocklist / Frozen rules.
interface IPolicyRegistry {
    function isListed(address account) external view returns (bool);
}

/// @notice The ExternalGate escape hatch. Arbitrary, unverifiable policy.
interface IPolicyGate {
    function check(TransferContext calldata ctx) external view returns (bool ok, string memory reason);
}
