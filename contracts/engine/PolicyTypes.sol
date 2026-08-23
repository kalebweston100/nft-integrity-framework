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
 *
 *      Three groups live here:
 *        THE QUESTION      ActionContext — what is being attempted
 *        THE VOCABULARY    Action, RuleKind, Rule — what conditions can exist
 *        THE ESCAPE HATCH  IPolicyRegistry, IPolicyGate — where a rule delegates
 */

/**
 * @notice The entry points a policy can govern.
 *
 * @dev Fixed by the ERC-20/721/1155 ABIs, which is what keeps the policy a
 *      PRODUCT OF TWO FINITE DIMENSIONS (action x kind) rather than an
 *      open-ended program. Every cell is still a flat AND-list of predicates.
 *
 * Transfer     transfer, transferFrom, safeTransferFrom, safeBatchTransferFrom.
 *              One action, not several: the transfer is identical and only the
 *              initiator differs, which `ActionContext.actor` carries. Batch
 *              variants are this action applied once per item.
 * Approve      approve. Only an INCREASE is gated; see PolicyEngine.
 * SetOperator  setApprovalForAll. Deliberately distinct from Approve — a
 *              blanket operator grant is categorically broader than an
 *              allowance, and separating them is what lets an operator
 *              allowlist be expressed as an enumerated rule with a notice
 *              period rather than as a silent filter. Only a GRANT is gated.
 * Mint         mint, mintBatch.
 * Burn         burn, burnBatch. Always the caller's own balance.
 */
enum Action {
    Transfer,
    Approve,
    SetOperator,
    Mint,
    Burn
}

/**
 * @notice The complete vocabulary of conditions a policy can express.
 *
 * @dev Deliberately finite. A fixed vocabulary is what makes a policy
 *      ENUMERABLE — an integrator can read the rules and render them in a UI,
 *      and because the engine's code is canonical, no condition outside this
 *      list can exist. An open-ended expression language would be code again,
 *      and would give back exactly the property this design exists to provide.
 *
 *      Not every kind is meaningful for every action, and several would
 *      SILENTLY MISBEHAVE rather than merely be useless — see
 *      PolicyEngine.allowedKinds, which rejects those pairings in canonical
 *      code.
 *
 * Allowlist     Both parties must be listed in `ref`. Skips the zero address,
 *               so mint and burn are not blocked by it.
 * Blocklist     Neither party may be listed in `ref`.
 * Frozen        Neither party may be individually frozen in `ref`.
 * LockupUntil   Nothing settles before `value` (unix timestamp).
 * MaxTransfer   A single action may not exceed `value`.
 * MaxBalance    Recipient balance after the action may not exceed `value`.
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
 * @notice One condition on one action. Rules are ANDed: every rule that applies
 *         to the action being attempted must pass.
 *
 * @dev A TAGGED UNION flattened into a struct, because Solidity has no sum
 *      types. `kind` is the discriminant and selects which of the remaining
 *      fields carry meaning; the rest MUST be zero. That is normative, not
 *      stylistic — canonical encoding is what makes two engines holding the
 *      same logical policy return byte-identical `rules()`.
 *
 *      FIELD SCHEMA, by kind:
 *
 *        kind            value                      ref
 *        ------------------------------------------------------------
 *        Allowlist       0                          registry, non-zero
 *        Blocklist       0                          registry, non-zero
 *        Frozen          0                          registry, non-zero
 *        LockupUntil     unix seconds               0
 *        MaxTransfer     token units                0
 *        MaxBalance      token units                0
 *        MaxBalanceBps   basis points, <= 10000     0
 *        MinHoldTime     seconds                    0
 *        HolderCap       address count              0
 *        ExternalGate    0                          gate, non-zero
 *
 *      `scoped`/`scopeId` are an Option<uint256> — two fields because 0 is a
 *      valid ERC-1155 id, so no sentinel is available. Meaningful only for
 *      ERC-1155; MUST be false for ERC-20 and ERC-721.
 *
 *      No OR and no nesting, on purpose. Fields are left unpacked for
 *      legibility; `action`, `kind` and `scoped` share one slot regardless.
 *
 * @param action  Which entry point this rule governs.
 * @param kind    Which condition this is.
 * @param value   Numeric parameter — timestamp, cap, bps, or seconds.
 * @param ref     Registry or gate address, for kinds that consult one.
 * @param scoped  ERC-1155 only: restrict this rule to a single token id.
 * @param scopeId The id it is restricted to when `scoped` is true.
 */
struct Rule {
    Action action;
    RuleKind kind;
    uint256 value;
    address ref;
    bool scoped;
    uint256 scopeId;
}

/**
 * @notice Everything a rule may consult about a pending action.
 *
 * @dev The token PUSHES this; the policy never calls back to fetch it. That is
 *      what lets balance-dependent rules exist without any reverse call path.
 *
 *      `from` and `to` are ALWAYS the endpoints of value flow, with the zero
 *      address standing in where there is none. That is what lets the identity
 *      rules work unchanged across all five actions.
 *
 *        action       actor       from     to         amount        id
 *        --------------------------------------------------------------------
 *        Transfer     msg.sender  holder   recipient  value         token id
 *        Approve      owner       owner    spender    new allowance token id (721)
 *        SetOperator  owner       owner    operator   1 (grant)     0
 *        Mint         admin       0        recipient  value         token id
 *        Burn         holder      holder   0          value         token id
 *
 *      One struct covers all three standards. ERC-20 leaves `id` at 0; ERC-721
 *      sets `amount` to 1 for transfers; ERC-1155 uses both. `totalSupply` and
 *      `holderCount` are per-id for ERC-1155.
 *
 *      Balances are the values BEFORE the action settles.
 */
struct ActionContext {
    Action action;
    TokenStandard standard;
    address actor;
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
    function check(ActionContext calldata ctx) external view returns (bool ok, string memory reason);
}
