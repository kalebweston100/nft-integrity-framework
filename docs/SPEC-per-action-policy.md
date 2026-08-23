# Spec: per-action policy

> **STATUS: SPECIFICATION ONLY. NOT IMPLEMENTED.**
> Nothing in `contracts/` does this yet. The shipped engine holds one flat rule
> array evaluated on transfers only. This document describes the next data
> model and exists so the design is settled before code is written; it is not a
> description of the repository.

---

## 1. What this changes

Today the policy governs **one action**: transfer. Mint and burn are carved out
with an argument — the issuer already controls supply, so gating them adds
nothing a holder can rely on.

The argument is defensible and it is still a carve-out, which is where claims go
to die: the `burn(address,uint256)` confiscation hole lived inside exactly this
exemption for two sessions. The carve-out is also what forces the current claim
to be scoped ("...can block a **transfer**") rather than total.

This spec removes the exemption by making the policy a function of **(action,
rule)** rather than of rule alone.

    Today:     rules  →  can this transfer proceed?
    Proposed:  rules  →  can this ACTION proceed?

The claim becomes total over the ABI:

> For every entry point in this token, beyond the standard's own requirements,
> the complete set of conditions under which it can fail is enumerated in
> `rules()`. No other condition exists, and none can be added without
> `swapDelay` seconds of public notice.

**This is generalisation that deletes a special case, not a feature that adds
surface.** That is the test it must keep passing. If it starts requiring
per-action exceptions, it has failed and should be cut.

### 1.1 Why this composes when the general version does not

A stored *program* would collapse the guarantee: AND-composition of boolean
predicates is comprehensible because each element independently implies the
conclusion, while sequential composition of state transitions is not, because
meaning depends on order and intermediate state.

This design stays on the right side of that line. It is a **product of two
finite dimensions** — a fixed action set from the ERC standards, and the
existing fixed rule vocabulary. Every cell is still an AND-list of predicates,
and every entry is still independently meaningful on its own.

---

## 2. `Action`

```solidity
enum Action {
    Transfer,     // transfer, transferFrom, safeTransferFrom, safeBatchTransferFrom
    Approve,      // approve
    SetOperator,  // setApprovalForAll
    Mint,         // mint, mintBatch
    Burn          // burn, burnBatch
}
```

Five actions, fixed by the ERC-20/721/1155 ABIs.

**`transfer` and `transferFrom` are the same action.** The transfer is
identical; only the initiator differs, and that is carried by `actor`. Writing
a rule twice to cover both would be a footgun.

**Batch variants are the same action**, applied per item — consistent with the
already-shipped rule that a batch is exactly N sequential singles.

**`Approve` and `SetOperator` are deliberately distinct.** Granting a blanket
operator is a categorically broader authorisation than approving an amount, and
an issuer may reasonably permit one and not the other. Keeping them separate is
also what lets an operator-allowlist be expressed honestly, as an enumerated
rule with a notice period, rather than as the kind of silent operator filter
this design exists to make impossible.

---

## 3. `ActionContext`

`TransferContext` becomes `ActionContext` with two added fields:

```solidity
struct ActionContext {
    Action        action;      // NEW
    TokenStandard standard;
    address       actor;       // NEW — always msg.sender
    address       from;
    address       to;
    uint256       id;
    uint256       amount;
    uint256       fromBalance;
    uint256       toBalance;
    uint256       totalSupply;
    uint256       holderCount;
}
```

`from` and `to` are **always the endpoints of value flow**, with the zero
address standing in where there is none. That keeps every identity rule
(`Allowlist`, `Blocklist`, `Frozen`) working unchanged across all five actions.

| Action | actor | from | to | amount | id |
|---|---|---|---|---|---|
| `Transfer` | `msg.sender` | holder | recipient | value | token id |
| `Approve` | owner | owner | spender | allowance | token id (721) |
| `SetOperator` | owner | owner | operator | `1` grant / `0` revoke | `0` |
| `Mint` | admin | `address(0)` | recipient | value | token id |
| `Burn` | holder | holder | `address(0)` | value | token id |

`fromBalance` and `toBalance` are always the real balances of `from` and `to`
before the action settles. `totalSupply` and `holderCount` remain per-id for
ERC-1155.

---

## 4. `Rule` gains an action

```solidity
struct Rule {
    Action   action;   // NEW — which entry point this rule governs
    RuleKind kind;
    uint256  value;
    address  ref;
    bool     scoped;
    uint256  scopeId;
}
```

**One flat array, not a mapping.** Considered and rejected:
`mapping(Action => Rule[])` with per-action proposals. A flat array keeps
`rules()` returning the entire policy as one value, keeps a single timelock and
a single `pendingAt` for a reader to track, lets a policy change span several
actions atomically, and leaves the whole policy hashable as one object — which
matters for the address-commitment design in `DESIGN-NOTES` §6.

Evaluation filters on `action` exactly as it already filters on
`scoped`/`scopeId`:

```solidity
for (uint256 i; i < n; ++i) {
    Rule storage r = _rules[i];
    if (r.action != ctx.action) continue;
    if (r.scoped && r.scopeId != ctx.id) continue;
    ...
}
```

---

## 5. `allowedKinds` — legality in canonical code

Not every kind is meaningful for every action, and — more importantly — several
do not merely become useless, they **silently misbehave**:

- `HolderCap` on `Burn` reads `toBalance == 0` with `to == address(0)`, so it
  fires on every burn and denies it for the wrong reason.
- `MaxBalance` on `Burn` compares against the zero address's balance, silently
  behaving as a `MaxTransfer`.
- `MinHoldTime` on `Mint` reads `lastReceived[address(0)]`, which is never set.

A rule that quietly means something other than its name is worse than one that
is rejected, so legality is **enforced, in the engine, as part of the verified
bytecode**:

```solidity
/// @notice Which rule kinds may ever apply to `a`. `pure`, so this is part of
///         the canonical code and a reader need not trust an off-chain table.
function allowedKinds(Action a) public pure returns (uint256 bitmask);
```

`_validate` rejects any rule whose `kind` bit is unset for its `action`.

### 5.1 The normative matrix

`✓` permitted, `·` rejected at propose time.

| Kind | Transfer | Approve | SetOperator | Mint | Burn |
|---|:--:|:--:|:--:|:--:|:--:|
| `Allowlist` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `Blocklist` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `Frozen` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `LockupUntil` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `MaxTransfer` | ✓ | ✓ | · | ✓ | ✓ |
| `MaxBalance` | ✓ | · | · | ✓ | · |
| `MaxBalanceBps` | ✓ | · | · | ✓ | · |
| `MinHoldTime` | ✓ | ✓ | ✓ | · | ✓ |
| `HolderCap` | ✓ | · | · | ✓ | · |
| `ExternalGate` | ✓ | ✓ | ✓ | ✓ | ✓ |

Identity rules and the escape hatch apply everywhere. Quantity rules apply only
where a quantity is meaningful. `MaxTransfer` on `Approve` is an allowance cap;
`MinHoldTime` on `Approve` or `SetOperator` is an anti-sniping rule — both
unusual but coherent, so both are permitted.

### 5.2 The claim this unlocks

Because `allowedKinds` is `pure` and lives in canonical bytecode, a reader can
state a bound on **future** policy, not just current policy:

> `Mint` on this token can only ever be gated by an identity rule, a lockup, a
> transfer cap, a balance cap, a holder cap, or an external gate. Nothing else
> can ever apply to it — regardless of what the admin proposes, and regardless
> of notice.

This is strictly stronger than the timelock. The timelock says *no new kind
without notice*; this says *these kinds can never apply here at all*. It also
sharpens the unconditional case from "no rules right now" to "no rules right
now, and here is the finite envelope of everything that could ever be added."

---

## 6. Normative field schema

Independent readers must render the same policy identically, so field meaning
per kind is normative, and **unused fields MUST be zero**. Canonical encoding
also means two engines with the same logical policy produce byte-identical
storage and identical `rules()` output — required if a policy hash is ever to be
committed to in a CREATE2 salt.

| Kind | `value` | `ref` | `scoped` / `scopeId` |
|---|---|---|---|
| `Allowlist` | MUST be `0` | registry, non-zero | optional |
| `Blocklist` | MUST be `0` | registry, non-zero | optional |
| `Frozen` | MUST be `0` | registry, non-zero | optional |
| `LockupUntil` | unix seconds | MUST be `0` | optional |
| `MaxTransfer` | token units, per-id for 1155 | MUST be `0` | optional |
| `MaxBalance` | token units | MUST be `0` | optional |
| `MaxBalanceBps` | basis points, `<= 10000` | MUST be `0` | optional |
| `MinHoldTime` | seconds | MUST be `0` | optional |
| `HolderCap` | address count | MUST be `0` | optional |
| `ExternalGate` | MUST be `0` | gate, non-zero | optional |

`scoped` is meaningful only for ERC-1155 and MUST be `false` for ERC-20 and
ERC-721, where `scopeId` has no interpretation. `_validate` enforces every row.

---

## 7. Engine surface

```solidity
function rules() external view returns (Rule[] memory);              // whole policy
function rulesFor(Action a) external view returns (Rule[] memory);   // one row
function activeActions() external view returns (uint256 bitmap);     // gated actions
function allowedKinds(Action a) external pure returns (uint256);     // the envelope
function evaluate(ActionContext calldata) external view returns (bool, string memory);
```

Timelock functions are unchanged in shape — `proposeRules(Rule[])`,
`commitRules()`, `cancelRules()`, `pendingRules()` — because a proposal replaces
the entire policy across all actions atomically. One timelock, one `pendingAt`.

`activeActions` is a cached bitmap refreshed in `_refreshCaches` alongside
`tracksHoldTime`, letting `evaluate` return early with no array scan for an
ungated action.

---

## 8. Token surface

Each gated entry point builds a context and consults the engine:

```solidity
function approve(address spender, uint256 amount) external returns (bool) {
    _gate(_ctx(Action.Approve, msg.sender, msg.sender, spender, 0, amount));
    _allowances[msg.sender][spender] = amount;
    emit Approval(msg.sender, spender, amount);
    return true;
}
```

`_gate` remains the **only** discretionary revert in every function, and the
existing rule stands verbatim: adding any other revert falsifies the claim while
leaving every test green.

`canTransfer` generalises to `canPerform(ActionContext)`, giving integrators a
preflight for every action rather than only transfers.

### 8.1 Gas, honestly

`Transfer` already calls the engine, so it is unchanged. The four other actions
gain one STATICCALL each:

- ~700 call overhead plus one cold SLOAD (~2,100) for the bitmap on first touch,
  ~800 warm thereafter
- `evaluate` returns immediately when the action's bit is unset, so an ungated
  action never scans the array

On `approve` (~46k with its SSTORE) that is under 5%. There is no way to drive
it to zero without the token caching engine state, which would put policy state
back in the token and break the single-source property — not worth it.

---

## 9. Verification

`PolicyVerification.Report` gains:

```solidity
uint256 activeActions;       // bitmap of gated actions
uint256[5] allowedKindsBy;   // the permanent envelope, per action
```

`isUnconditional` keeps its current form and quietly becomes a **stronger**
claim: `rules.length == 0` now means no rules on *any* action, not merely on
transfers. `pendingAt == 0` remains part of it.

Add `isUnconditionalFor(report, action)` for readers that want per-row answers —
a token that gates minting but nothing else should be renderable as
"transfers unconditional, minting restricted."

---

## 10. Migration

The shipped policy is exactly this model with every rule pinned to
`Action.Transfer`. Migration is mechanical:

1. Add `Action` to `PolicyTypes`; add `action` to `Rule`; rename
   `TransferContext` to `ActionContext` and add `action` / `actor`.
2. Add `allowedKinds` and extend `_validate`.
3. Add `activeActions` to `_refreshCaches`; early-return in `evaluate`.
4. Add gates to `approve` / `setApprovalForAll` / `mint` / `burn` in all three
   tokens.
5. Delete the mint/burn carve-out paragraphs from every NatSpec block and from
   the README; they are the thing being removed.
6. Extend the selector-absence tests to assert the gate is present on every
   action, and add a fuzz case per action to `UnconditionalPolicy.t.sol`.

Every existing test should survive step 1–3 unchanged apart from the struct
rename, which is the signal that the generalisation is behaving.

---

## 11. What this does not change

- **The closed set.** Whatever address receives the transaction decides whether
  it reverts, so only known bytecode can carry the claim. Unchanged and
  unfixable.
- **The theorem.** You can prove an action went through the policy; never that
  it went only through the policy.
- **Codehash scope.** Still future-tense only; still no provenance.
- **The reader.** Still does not exist, and this data model is the reason to
  build it after this lands rather than before — the shape it renders changes
  here.

## 12. Open questions

- Should `Approve` distinguish increase from decrease? Reducing an allowance is
  strictly de-risking and arguably should never be blockable. Leaning yes,
  as an evaluation-time exemption rather than a sixth action.
- Does `SetOperator` revocation need the same exemption? Same argument, more
  strongly — a policy that can prevent you revoking an operator is a trap.
- Should `Burn` be gateable at all? A policy that can stop you destroying your
  own tokens has no holder-protective reading. Possibly `allowedKinds(Burn)`
  should be identity rules only.
