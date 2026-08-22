# Spec: declarative policy, and collapsing verification to one address

Status: **design, not implemented.** Supersedes [DESIGN-NOTES](DESIGN-NOTES.md)
sections 3.1, 3.2 and 4.1, which this resolves.

---

## 1. What changes and why

Two limitations have been recorded as the deepest in the design:

- **3.1** — verification covers the plumbing but never the policy, because
  `logic` is bespoke code per issuer and so can never have a universal hash.
- **3.2** — `logic` is fixed at deployment, which fights the compliance and RWA
  use cases this shape of extension most suits.

Both dissolve under one move: **policy becomes data, not code.**

A single canonical `PolicyERC20` — zero immutables, byte-identical for every
issuer — holds an array of rules in *storage* and evaluates them. The trick is
the one the token already uses: fix the code, vary the storage. Applied one
layer out, `logic` becomes universally hash-verifiable, and policy changes
become rule-array edits that a timelock inside canonical bytecode can govern.

The claim this buys, which nothing in the ecosystem currently offers:

> Here is the complete, enumerable set of conditions under which this token can
> block a transfer. The code is canonical, so no other condition exists. It
> cannot change without `N` days of public notice.

Provable **absence of arbitrary code** in a transfer path is the product.

A second, independent goal: collapse the integrator's check from four calls to
one. Today an integrator must verify the token, the wrapper, the pairing, and
then read bespoke logic by hand. Nobody does that at scale. The target is
`IntegrityVerifier.verifyERC20(token)` returning a single struct.

---

## 2. Architecture

### 2.1 The wrapper becomes the root and deploys both children

> **Corrected after phase 1.** An earlier draft kept the three-layer cascade
> and simply swapped the bespoke logic contract for a canonical policy at the
> root: Policy → Wrapper → Token. That does not compile. The policy would need
> `type(HooksWrapperERC20).creationCode` to deploy the wrapper, while the
> wrapper would need `keccak256(type(PolicyERC20).runtimeCode)` to enforce it —
> a cycle, and exactly the class of failure phase 1 exists to prevent. The
> ordering below is the version that actually satisfies the DAG.

```
             CURRENT                                PROPOSED

  Logic (bespoke, unverifiable)          Wrapper  (deployed by the issuer)
             │ new                          ├── new{salt} ──▶ Policy (canonical)
             ▼                              └── new{salt} ──▶ Token
          Wrapper
             │ new
             ▼
           Token
```

The cascade flattens from a chain into a fan. The wrapper is deployed directly
by the issuer and creates both children, so the issuer's single transaction
becomes:

```solidity
new HooksWrapperDeclarativeERC20(admin, rules, delay, name, symbol, contractURI);
```

They write no Solidity — they choose rules from a vocabulary.

Both `new`s are CREATE2, so each child's address commits to its init code and
`isProvenanceVerified*` extends to the policy exactly as it already does to the
token.

### 2.1.1 Two wrapper variants, and the hash tells you which

The bespoke `HooksLogicERC*` path is retained (section 6), but one wrapper
cannot both *be deployed by* a logic contract and *deploy* a policy. So there
are two canonical wrappers:

| Wrapper | `logic` comes from | Guarantee |
|---|---|---|
| `HooksWrapperERC20` | `msg.sender` — arbitrary developer code | Deny-only calling convention |
| `HooksWrapperDeclarativeERC20` | `new{salt}` — canonical policy | The above, plus enumerable policy |

This is a feature rather than duplication: **the wrapper's codehash alone tells
an integrator which regime applies**, before they inspect anything else. One
`EXTCODEHASH` distinguishes "arbitrary policy code" from "enumerable rules."

### 2.2 The dependency DAG must stay acyclic

`type(C).runtimeCode` and `type(C).creationCode` cannot participate in a cycle;
the compiler rejects it. Under the corrected ordering both children are leaves:

```
PolicyERC20        imports IHooksERC20 only          ─┐
IntegrityERC20     imports IHooksERC20 only          ─┤ leaves
                                                      │
HooksWrapperDeclarativeERC20                          │
    needs type(PolicyERC20).creationCode      ────────┘
    needs type(IntegrityERC20).creationCode
```

**This is what phase 1 bought.** `IntegrityERC20` previously stored
`HooksWrapperERC20 private _hooks` and imported the concrete contract, so
token and wrapper referenced each other. Storing `IHooksERC20` made the token a
leaf. Verified: `forge inspect IntegrityERC20 metadata` no longer resolves
`HooksWrapperERC20.sol` at all.

### 2.2 The dependency DAG must stay acyclic

`type(C).runtimeCode` and `type(C).creationCode` cannot participate in a cycle;
the compiler rejects it. The required ordering:

```
PolicyERC20      — depends on nothing upward
    ▲ creationCode (to deploy it)     ▼ runtimeCode hash (to enforce it)
HooksWrapperERC20 — holds CANONICAL_POLICY_HASH
    ▲ creationCode
IntegrityERC20    — must NOT name HooksWrapperERC20 concretely
```

**This forces one change to the token:** `IntegrityERC20` currently stores
`HooksWrapperERC20 private _hooks` and imports the concrete contract
(`IntegrityERC20.sol:7,52,75`). It must store `IHooksERC20 private _hooks`
instead. The call sites are unchanged — the interface already declares every
hook the token invokes. This is a pure decoupling with no behavioural effect,
and it is what keeps the graph acyclic.

### 2.3 Canonical by construction, not by check

An earlier draft had the wrapper hold `CANONICAL_POLICY_HASH` and verify
`logic.codehash` before each forward, at ~100 gas per transfer. Under the
corrected ordering that is unnecessary: **the wrapper deploys the policy
itself**, with `new`, from creation code embedded in its own bytecode. There is
no setter and no path by which `logic` could be anything else.

So the guarantee costs zero gas and is stronger — not "the wrapper checks that
its policy is canonical," but "the wrapper is incapable of having a
non-canonical policy." Same recurring move as everywhere else in the project:
make it structurally impossible rather than checked.

What an integrator verifies is correspondingly simpler — that the policy really
was deployed by this wrapper, via `isProvenanceVerifiedPolicy(policy, wrapper)`,
which is the CREATE2 derivation already built for the token.

### 2.4 Why construction-time checks are impossible

A contract mid-construction has no deployed code, so `address(x).codehash` is
empty for anything upstream in a chained cascade. The wrapper cannot verify the
policy that is currently constructing it. All codehash enforcement must be
lazy — at call time, as above. Recorded because it is easy to attempt and
guaranteed to fail.

---

## 3. `PolicyERC20`

### 3.1 Rule vocabulary

```solidity
enum RuleKind {
    Allowlist,      // ref = registry; both parties must be verified
    Blocklist,      // ref = registry; neither party may be listed
    LockupUntil,    // a = unix timestamp before which no transfer settles
    MaxBalance,     // a = absolute cap on recipient balance after transfer
    MaxBalanceBps,  // a = cap on recipient balance as bps of totalSupply
    MaxTransfer,    // a = cap on a single transfer amount
    MinHoldTime,    // a = seconds a recipient must hold before resending
    HolderCap,      // a = max distinct holders
    Frozen,         // ref = registry of individually frozen addresses
    ExternalGate    // ref = arbitrary contract — THE ESCAPE HATCH
}

struct Rule {
    RuleKind kind;
    uint256  a;
    uint256  b;
    address  ref;
}
```

Deliberately a flat struct rather than an expression tree. Rules are ANDed: all
must pass. No OR, no nesting. Expressiveness is traded for the ability to render
the policy as a readable list, which is the entire point — a policy an
integrator cannot display in a UI is worth much less than one they can.

### 3.2 `ExternalGate` is the honest escape hatch

A fixed vocabulary cannot express everything. `ExternalGate` delegates to an
arbitrary contract, and the policy exposes:

```solidity
function hasExternalGate() external view returns (bool);
```

Verification then reports *"this policy contains an unverified external call"*
rather than silently over-claiming. This is strictly better than today, because
the presence of arbitrary code becomes **visible and verifiable** instead of
assumed. Provable absence is the feature; provable presence is the fallback.

### 3.3 Balance context — the hook signature must change

`MaxBalance`, `MaxBalanceBps`, and `HolderCap` all need balances, and the
policy **must not call the token** — the one-directional invariant is the
framework's core guarantee and is not negotiable.

Resolution: the token *pushes* the context it already has, rather than the
policy *pulling* it.

```solidity
struct TransferContext {
    address from;
    address to;
    uint256 amount;
    uint256 fromBalance;   // before the transfer
    uint256 toBalance;     // before the transfer
    uint256 totalSupply;
    uint256 holderCount;   // maintained by the token
}

function validateTransfer(TransferContext calldata ctx)
    external view returns (bool valid, string memory reason);
```

This is a **breaking change to `IHooksERC20`/`721`/`1155`** and touches every
wrapper and token. It preserves one-directionality exactly: calls still flow
Token → Wrapper → Policy and nothing calls back.

`holderCount` requires the token to track distinct holders — increment when a
recipient crosses 0 → positive, decrement when a sender hits zero. Adds two
`SSTORE`s on transfers that change holder status. If that cost is judged too
high, drop `HolderCap` from v1 rather than weakening the invariant.

### 3.4 Stateful rules

`MinHoldTime` needs `_lastReceived[address]`. `validateTransfer` is `view`
(STATICCALL-enforced), so it can only read. The write happens in
`_onAfterTransfer`, which the existing hook surface already provides. No new
call path.

### 3.5 Storage

```solidity
Rule[]  private _rules;
Rule[]  private _pendingRules;
uint256 private _pendingAt;      // 0 = nothing pending
uint256 private _swapDelay;      // set once in constructor, no setter
mapping(address => uint256) private _lastReceived;
```

All plain storage, **zero immutables** — the constraint that makes
`type(PolicyERC20).runtimeCode` compile, and which now enforces itself at a
third layer.

`_swapDelay` in storage rather than as a `constant` is a deliberate departure
from DESIGN-NOTES 4.1. A `constant` would make each delay a different contract
with a different hash — good for risk segmentation, bad for having *one*
canonical policy hash, which this design needs more. The delay is instead read
and displayed by integrators. Trade-off recorded rather than hidden.

---

## 4. Timelocked rule changes

```solidity
function proposeRules(Rule[] calldata newRules) external onlyIssuerAdmin;
function commitRules() external onlyIssuerAdmin;
function cancelRules() external onlyIssuerAdmin;

event RulesProposed(Rule[] rules, uint256 effectiveAt);
event RulesCommitted(Rule[] rules);
event RulesCancelled();
```

`commitRules` requires `_pendingAt != 0 && block.timestamp >= _pendingAt`.
Because the code is canonical, the timelock covers **every possible policy
change** — there is no `setLogic` escape, because there is no swappable logic
any more. Section 3.2 of DESIGN-NOTES is fully resolved rather than mitigated.

Holders get a public, indexable notice window in which to exit.

**Known residual:** a fabricated constructor could write `_pendingAt` in the
past and commit once immediately (constructors remain outside codehash
coverage — DESIGN-NOTES 1.1). CREATE2 provenance on the policy closes it where
the policy was itself deployed by a contract; where the issuer deploys it
directly from an EOA it cannot be, since EOA deployment uses CREATE and commits
to no init code. Document the limit; do not paper over it.

---

## 5. Verifier API

The integrator-facing goal is one call:

```solidity
struct Verification {
    bool    tokenCanonical;      // codehash — future behaviour
    bool    tokenProvenance;     // CREATE2  — history
    bool    wrapperCanonical;
    bool    policyCanonical;
    bool    hasExternalGate;     // policy contains unverified code
    uint256 swapDelay;
    Rule[]  rules;               // the complete, exhaustive policy
}

function verifyERC20(address token) internal view returns (Verification memory);
```

It walks the chain itself: `token.hooksContract()` → wrapper, `wrapper.logic()`
→ policy, checking codehashes before making any call to an address it has not
yet established as canonical. Ordering is load-bearing — `EXTCODEHASH` never
calls the target, so a hostile address is rejected before its code runs.

Existing functions stay for callers who want the pieces.

---

## 6. Migration plan

Six phases, each independently testable and committable. Phases 1–2 are
prerequisites with no user-visible payoff; the value lands in 3–4.

| # | Change | Gate |
|---|---|---|
| 1 | ✅ Token stores `IHooksERC20` instead of the concrete wrapper | done — `0d78bcb`, 76 green, cycle verified broken |
| 2 | `TransferContext` replaces positional hook args across all three standards | full suite green; hook authors see one mechanical signature change |
| 3 | `PolicyERC20` — vocabulary, evaluator, `_onAfterTransfer` state | new unit suite per rule kind, including deny and allow paths |
| 4 | `HooksWrapperDeclarativeERC20` deploys policy + token via CREATE2 | policy is canonical by construction; provenance holds for both children |
| 5 | `verifyERC20/721/1155` + `Verification` struct | extend `CodehashLimits.t.sol`: impostor policy fails, real chain passes |
| 6 | 721 and 1155 policy contracts | parity suite |

Do **not** delete `HooksLogicERC20/721/1155`. The declarative policy is an
additional, verifiable option — not a replacement. Issuers needing arbitrary
logic keep the escape hatch of writing their own, and verification honestly
reports the weaker result for them.

### Ordering risk

Phase 2 is the largest mechanical diff and touches every contract and test.
Phase 1 is small and unblocks it. Neither delivers value alone, so resist
shipping 3 before 1–2 are green — the DAG will not permit it and the failure
mode is a compiler error that is easy to misdiagnose as a `runtimeCode`
restriction.

---

## 7. What this proves, and what it still doesn't

**Adds:** the policy governing a token is canonical, complete, enumerable, and
timelocked — verifiable by a stranger with one call, no registry, and no
trusted party. Combined with the existing token and wrapper checks, the full
chain is covered for the first time.

**Still doesn't prove:** that the rules are *good*. A canonical policy can
enumerate rules that deny every transfer. What changes is that the rules are
now *visible in advance* rather than hidden in bespoke bytecode — the buyer can
read them and decide. That is the honest claim, and it is a large improvement
over "trust that this compliance contract does what its author says."

**Also unresolved:** an `ExternalGate` rule reduces the guarantee to
today's level for that rule. Reported, never hidden.

**Also unresolved:** implementation-independence (DESIGN-NOTES 3.4). A
third-party OpenZeppelin token wired through this wrapper still gets the
canonical, enumerable policy — most of the value — but not the token-side
guarantees. That remains the separate, larger piece of work.
