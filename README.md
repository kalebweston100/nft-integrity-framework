# Policy Tokens

**A token's transfer policy should be readable data, not opaque code.**

Every token that can restrict transfers today answers the question *"can this
contract block me, and when?"* the same way: read the source, reason about every
path through it, and hope nobody upgrades it. That is a program-analysis
problem — undecidable in general, and in practice a human auditor per token per
version.

These tokens answer it with an array read.

```solidity
Rule[] memory rules = PolicyEngine(token.policy()).rules();
// [] — nothing can block a transfer of this token.
```

And because the code that evaluates those rules is fixed and published, the
array is not merely *a* list of conditions. It is **all** of them.

---

## The claim

> For **every entry point** in one of these tokens — transfer, approve,
> setApprovalForAll, mint, burn — beyond the standard's own requirements, the
> only conditions under which it can fail are the rules enumerated by
> `policy().rules()`. No other condition exists, and none can be added without
> `swapDelay` seconds of public, on-chain notice.

There is no carve-out. Each rule names the action it governs, so a policy is a
table rather than a list, and `mint` is answerable on exactly the same terms as
`transfer`. That matters more than the extra coverage suggests: a carve-out is
where a claim goes to die, and the `burn(address,uint256)` confiscation hole
this design once had lived inside precisely such an exemption.

The strongest case is the empty one. A token whose rule array is empty is
**unconditional**: nothing it can do will ever block your transfer.

That sounds like a default. It is not. "This token has no hidden restriction" is
a claim about a *negative*, and negatives over arbitrary code cannot be
established by observation — every transfer that succeeds is still consistent
with a branch that has not been taken yet. Today the only honest way to check it
is to read the source, reason over every path, and do it again after the next
upgrade. `Pausable` is one line. An operator filter is a modifier. Behind a
proxy, either can appear tomorrow.

A canonical codehash moves the question from runtime to compile time, where it
is decidable. One call settles it:

```solidity
PolicyVerification.Report memory r = PolicyVerification.verify(token);
if (PolicyVerification.isUnconditional(r)) {
    // Machine-checkable proof of absence.
}
```

An unconditional token is also an entirely ordinary one — it behaves exactly
like a plain ERC-721 and is fully marketplace-compatible. The guarantee costs
its issuer nothing.

---

## Architecture

Two contracts, one deployment transaction, no proxies and no factory.

```
Issuer ──▶ PolicyERC20 ──new{salt}──▶ PolicyEngine
           (canonical)               (canonical)
```

The token deploys its own engine in its constructor via CREATE2, from creation
code embedded in its own bytecode. There is no setter, no initializer, and
therefore no window in which the token exists without a policy. The engine
cannot be swapped, because nothing can swap it.

Both contracts hold **zero immutables**, which is what makes
`type(C).runtimeCode` compile and a compile-time hash derivable. That constraint
enforces itself: add a single `immutable` and the verifier stops building.

**Policy varies in storage; code never does.** An engine holding a 90-day lockup
and an engine holding an allowlist plus a transfer cap have *identical*
codehashes. That is the whole trick — it is what lets one published hash cover
every issuer on every chain.

---

## The canonical set

Verification matches a token against a fixed, finite set of hashes:

| Contract | Runtime size |
|---|---|
| `PolicyERC20` | 4,945 B |
| `PolicyERC721` | 7,858 B |
| `PolicyERC1155` | 7,742 B |
| `PolicyEngine` | 7,803 B |

A wallet ships four constants and can then verify any token any issuer deploys,
on any chain, forever, per version.

**The set being closed is the source of the guarantee, not a limitation to be
engineered away.** Whatever address a user transacts with decides whether the
call reverts, so only known bytecode can carry the claim — which means "only
these rules can block you" and "works with any token" are contradictory, not
merely hard. There is deliberately no conformance interface a third-party token
can implement to be treated as a member. A token outside the set is reported as
`unknown`, exactly as any other ERC-20 would be.

---

## The rule vocabulary

Ten kinds, deliberately finite. A fixed vocabulary is what makes a policy
renderable in a UI; an open-ended expression language would be code again, and
would give back exactly the property this design exists to provide.

| Kind | Condition |
|---|---|
| `Allowlist` | Both parties must be listed in `ref` |
| `Blocklist` | Neither party may be listed in `ref` |
| `Frozen` | Neither party may be individually frozen in `ref` |
| `LockupUntil` | No transfer settles before `value` |
| `MaxTransfer` | A single transfer may not exceed `value` |
| `MaxBalance` | Recipient balance after the transfer may not exceed `value` |
| `MaxBalanceBps` | Same, as basis points of total supply |
| `MinHoldTime` | Sender must have held for `value` seconds |
| `HolderCap` | Distinct holder count may not exceed `value` |
| `ExternalGate` | Defers to arbitrary code — the honest escape hatch |

Rules are ANDed, flat, with no nesting: expressiveness traded for
renderability. Each rule also names one **action** — `Transfer`, `Approve`,
`SetOperator`, `Mint` or `Burn` — so the policy is a product of two finite
dimensions rather than an open-ended program. For ERC-1155 a rule may also be
`scoped` to a single token id.

### The permanent envelope

Not every kind is meaningful for every action, and several would *silently
misbehave* rather than merely be useless — `HolderCap` on `Burn` sees
`to == address(0)`, so it would fire on every burn for a reason unrelated to
holder counts. Legality is therefore enforced inside the engine, by a `pure`
function that is part of its canonical bytecode:

```solidity
function allowedKinds(Action a) public pure returns (uint256 bitmask);
```

Because it is canonical, a reader gets something the timelock cannot give them:

> The timelock says no new **kind** can appear without notice.
> This says these kinds can **never** apply to this action at all — regardless
> of notice, for the life of the contract.

So the unconditional case sharpens from *"no rules right now"* to *"no rules
right now, and here is the finite envelope of everything that could ever be
added."*

| Kind | Transfer | Approve | SetOperator | Mint | Burn |
|---|:--:|:--:|:--:|:--:|:--:|
| `Allowlist` / `Blocklist` / `Frozen` | ● | ● | ● | ● | ● |
| `LockupUntil` | ● | ● | ● | ● | ● |
| `MaxTransfer` | ● | ● | | ● | ● |
| `MaxBalance` / `MaxBalanceBps` | ● | | | ● | |
| `MinHoldTime` | ● | ● | ● | | ● |
| `HolderCap` | ● | | | ● | |
| `ExternalGate` | ● | ● | ● | ● | ● |

`ExternalGate` voids the strong claim by design, and
`isFullyEnumerable()` returns false whenever one is present. `externalRefs()`
reports every address a policy consults of *any* kind, because an
`Allowlist` backed by a hostile upgradeable registry is not a gate but is still
unverified code.

---

## What these tokens deliberately do not have

Each of these is a decision, not an omission.

**No `pause()`.** A pause is a discretionary revert in the transfer path held by
the issuer — precisely the unenumerable, un-noticed blocking power this design
exists to eliminate. The capability is not lost, only made honest: halting
transfers is a `LockupUntil` rule, and therefore takes the timelock like any
other change. An issuer cannot silently freeze a market.

**No admin burn.** `burn` destroys the caller's own balance and nothing else. An
admin able to burn from an arbitrary holder holds a *confiscation* lever, which
is strictly stronger than the freeze already refused: blocking a transfer stops
you moving a token, burning takes it outright. For ERC-721 not even an approved
operator may burn — approving a marketplace to sell an NFT must never be
approval to destroy it.

**No policy over de-risking.** Reducing an allowance and revoking an operator
are structurally exempt: only *increases* and *grants* consult the policy. A
rule able to stop you withdrawing an approval could pin you to it, which is a
trap rather than a restriction.

**No proxies, anywhere, ever.** A canonical proxy in front of a mutable
implementation verifies clean and means nothing.

**No inheritance as an extension point.** `PolicyTokenBase` exists for code
organisation. It is not an adoption path, and the restriction enforces itself: a
contract inheriting it that is not a member of the set compiles to different
bytecode and matches nothing.

---

## Compatibility: marketplaces yes, DeFi no

A token that can revert on transfer is a "weird ERC-20" to every integrator.
That is true of any transfer-restricted token — USDC's blacklist, ERC-1404,
ERC-3643 — and the cost scales with how restrictive the policy is. An
unconditional token pays nothing; a heavily-ruled one pays a lot. Where it lands
is asymmetric, and the asymmetry is deliberate:

**NFT marketplaces work.** In Seaport, `from` and `to` are the seller and buyer
while the conduit never holds a balance, so rules evaluate against real
counterparties and the plumbing needs no special-casing. The worst case is a
reverted fill — and `canTransfer()` exists so a marketplace can pre-check and
render *"blocked by a 30-day lockup"* instead of burning the buyer's gas.

**ERC-20 DeFi does not.** An AMM pool *is* a holder. An allowlist excluding the
Uniswap pool breaks LP; `MaxBalance` strangles a pool as it accumulates; lending
protocols will not list assets whose liquidation can revert. This is not a bug
to engineer around — it is what the rule *means*.

The comparison class is what matters. A token that wants an enumerable transfer
policy already has transfer restrictions today; the incumbent is ERC-3643 with a
bespoke, opaque compliance module. Against that baseline this is strictly *more*
compatible, because an integrator can read the rules instead of auditing a
program.

---

## Discovery and verification

Any integrator can find a policy without knowing anything else about a token:

```solidity
if (IERC165(token).supportsInterface(type(IPolicyGoverned).interfaceId)) {
    address engine = IPolicyGoverned(token).policy();
}
```

Discovery is cheap and universal; **it is not the guarantee**. Anything can
implement the interface and return an address. What makes the answer
trustworthy is the codehash:

```solidity
PolicyVerification.Report memory r = PolicyVerification.verify(token);

r.tokenCanonical   // runs a member of the canonical set
r.policyCanonical  // engine runs canonical PolicyEngine code
r.standard         // which member matched
r.rules            // the complete, exhaustive policy, every action
r.activeActions    // which entry points are gated at all
r.allowedKindsBy   // per action, what could EVER gate it
r.hasExternalGate  // arbitrary code is consulted
r.externalRefs     // every address the policy consults
r.swapDelay        // notice required before a rule change
r.pendingAt        // a change is already queued
```

`isUnconditionalFor(report, action)` answers the same question per entry point,
so a collection that caps supply per wallet but never restricts secondary
trading renders as *"transfers unconditional, minting restricted"* rather than
collapsing to a single red badge.

`verify()` is safe against untrusted input: `EXTCODEHASH` never invokes the
target, and every codehash is established *before* any call is made to that
address.

### What the timelock actually covers

> The timelock covers **which conditions exist**, not **who they apply to**.

Four of the ten rule kinds consult a registry whose membership the timelock does
not govern, so an issuer can freeze an address instantly by editing a registry.
That is not fully fixable — sanctions compliance *requires* immediate blocking —
and documenting it is better than pretending. What the timelock does guarantee
is that no new *kind* of condition can appear: a token with no `Frozen` rule
today cannot acquire the power to freeze you without public notice.

### What a codehash cannot carry

> Guarantees about **future** behaviour can ride on a codehash.
> Guarantees about **history** cannot.

`EXTCODEHASH` covers runtime code only. The constructor that wrote a contract's
initial storage lives in creation code and is never hashed, so an attacker can
fabricate any state and still present byte-identical runtime code copied off a
real deployment — demonstrated in `test/CodehashLimits.t.sol`.

This costs the headline claim nothing, because the claim is entirely
future-tense: the impostor genuinely runs canonical code, so from that moment on
only the enumerated policy can block a transfer of it. What no codehash can
establish is how its balances arose. CREATE2 provenance would close that gap and
`CanonicalCode.sol` carries the primitive, but `PolicyVerification` deliberately
does not use it — no claim made here needs it.

---

## Repository

```
contracts/
  token/         PolicyTokenBase, PolicyERC20, PolicyERC721, PolicyERC1155
  engine/        PolicyEngine, PolicyTypes  — the rule vocabulary
  verification/  CanonicalCode (standalone, zero imports), PolicyVerification
  interfaces/    IPolicyGoverned (discovery), Types, Errors, receivers
docs/
  DESIGN-NOTES.md  rationale, prior art, honest limitations
```

`CanonicalCode.sol` imports nothing and is vendorable into any project that
wants codehash and CREATE2 provenance checking, independent of everything else
here.

## Development

Foundry.

```bash
forge build
forge test          # 142 tests
forge fmt --check
```

## Status

Pre-audit. Not deployed. Version 1 — a proof of concept and a starting point,
not a final feature set.

Known rough edges: `Rule` is unpacked for legibility and could be packed;
`evaluate()` is a linear scan, so gas grows with rule count; and the ERC-1155
batch path consults the policy once per item, which is the honest price of a
batch meaning exactly the same thing as the transfers it bundles. Gating the
four non-transfer entry points costs each one a STATICCALL; an action no rule
governs short-circuits on a single warm SLOAD inside the engine.

The clearest next step is an off-chain reader — paste a token address, render
its policy — since the value of enumerability is only realised once something
reads it.

## License

MIT
