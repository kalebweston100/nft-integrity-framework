# Design notes

What this proves, what it doesn't, and why each decision went the way it did.
The README states the claims; this file argues for them and records the costs.

---

## 1. The idea, scoped precisely

A transfer policy expressed as **data in storage** rather than **code in
bytecode**, evaluated by a contract whose bytecode is fixed and published.

Fix the code, vary the storage. That is the entire mechanism, and it is the same
trick applied twice: the tokens stay byte-identical across issuers because their
configuration lives in storage, and the engine stays byte-identical across
policies for exactly the same reason. An engine holding a 90-day lockup and an
engine holding an allowlist plus a transfer cap compile to the same runtime
bytes and hash identically.

### 1.1 What the canonical hash is actually for

This has been walked back three times and the final position is narrow:

> The canonical hash is not what makes a policy trustworthy to **read**.
> It is what makes `rules()` **exhaustive** — no condition exists outside the
> array.

Verification is *not* the product, and the earlier framing that leaned on it was
wrong. "This bytecode matches this source" is what Sourcify and Etherscan
already provide, free, for every contract; a consumer that is already off-chain
can fetch `eth_getCode` from any RPC. Nothing here improves on that, and
claiming otherwise would be dishonest.

What survives is a much smaller point, and it is enough:

An Etherscan-verified bespoke ERC-3643 compliance module still cannot answer
*"can this block my transfer, and when?"* without reasoning over every
control-flow path — a program-analysis problem, undecidable in general, in
practice a human auditor per token per version. Policy-as-data replaces that
with an array read. **No explorer touches this.** Exhaustiveness comes from the
finite rule vocabulary plus a known evaluator, not from the hash's provenance.

Two smaller advantages of the on-chain hash are worth keeping as footnotes, not
as a thesis: explorer verification is opt-in per deployment, so a canonical
engine matches even when an issuer never verifies on a chain nobody indexes; and
Etherscan is a company with an API key.

### 1.2 The theorem everything else follows from

> **The contract the user transacts with must have a verifiable codehash.**

Whatever address receives the transaction decides whether it reverts. If you
cannot verify that bytecode, the author can `require` anything, anywhere. And
this cannot be recovered at runtime, because of an asymmetry:

> You can prove a transfer **went through** the policy.
> You can never prove it went **only** through the policy.

Consultation is a positive, observable fact. "Nothing else blocked" is a
negative claim over arbitrary code, and no observation establishes it — the
engine returning `true` followed by the token reverting for its own reasons is
indistinguishable, from the engine's side, from success.

**Therefore "only these rules can block" and "works with any token" are
contradictory, not merely hard.** The closed canonical set is not a limitation
awaiting an adoption story; it is what the strong claim costs.

### 1.3 Why the unconditional case is the headline

The theorem above says a negative claim cannot be established *at runtime, for
arbitrary code*. A canonical codehash does not beat it — it **relocates** the
question to compile time, for a closed set. The empty policy is the purest
instance of that move: the entire value is the proven absence.

Nothing else in the ecosystem can state "this token has no transfer
restrictions" as a checkable fact. And it costs the issuer nothing: with no
rules the token is an ordinary, fully marketplace-compatible ERC-721.

`isUnconditional()` folds in `pendingAt == 0` deliberately. A token with no
rules but a live proposal is unconditional today and locked next week; a green
badge on it would be exactly the failure this design exists to prevent.

---

## 2. Prior art, honestly

| Prior art | Relationship |
|---|---|
| **ERC-1404** | Restriction logic lives *inside* the token. No separate deployment; nothing stops the same function from mutating balances. The separation here is a strict improvement, but 1404's `detectTransferRestriction` is the direct ancestor of `canTransfer()`. |
| **ERC-3643 (T-REX)** | The closest serious comparison. Modular compliance, but routed through a trusted `Compliance` contract, and — importantly — **updatable arbitrary code**. Has institutional RWA adoption and a standards body. Beats this on adoption and on policy expressiveness; loses on enumerability, which is the entire point of contention. |
| **ERC-902** | Standardises external transfer validators. Stagnant. |
| **ERC-7943 (uRWA)** | Newer, minimal RWA interface. Occupies adjacent design space. |
| **Uniswap v4 hooks** | The dominant non-EIP prior art for `CALL`-based, separately-deployed extension points. Related, but hooks are arbitrary code by design — the opposite trade. |
| **Diamond facets / Safe modules** | Wire extensions in via `DELEGATECALL`, so the extension runs in the host's storage. The pattern this is a reaction to. |

The novel part is not the separation and not the hashing. It is **replacing an
arbitrary predicate with a finite, enumerable vocabulary**, and accepting a
closed token set as the price of the claim that buys.

---

## 3. Structural limitations

These follow from the design, not from incomplete implementation.

### 3.1 The canonical set cannot include OpenZeppelin

An issuer cannot bring their own ERC-721. This is unfixable — see §1.2 — and it
is the single largest adoption cost. The reframing that makes it workable is
that the curated set must cover **the features people will not give up**, which
is a finishable target with a clear definition of done.

The distinction for deciding what may join the set: `permit` adds an
**authorization** path, not a **blocking condition**, so it costs the claim
nothing and belongs. `Pausable` hooks and role-gated transfer guards add
discretionary reverts, and are exactly what the policy replaces.

### 3.2 The timelock does not cover registry membership

Four of ten rule kinds consult a registry whose contents the timelock does not
govern. "The policy cannot change without notice" is therefore **false** in the
common case. The precise honest claim:

> The timelock covers which conditions exist, not who they apply to.

Not fully fixable: sanctions compliance *requires* immediate blocking, so a
notice period on membership would make the rules unusable for the market that
most wants them. `externalRefs()` reports every consulted address of any rule
kind, so an integrator can at least see the whole dependency surface rather than
only the `ExternalGate` ones.

### 3.3 A codehash cannot speak to history

Demonstrated in `test/CodehashLimits.t.sol`: init code and runtime code are
independent byte strings, so an impostor can fabricate arbitrary storage and
return canonical runtime bytes copied off a real deployment. It passes the full
report.

This is *not* a hole in the headline claim, and the test suite says so
explicitly. Every claim the report makes is future-tense and holds for the
impostor too — it genuinely runs canonical code. What no codehash can establish
is how the balances arose. CREATE2 provenance closes precisely that gap;
`CanonicalCode.sol` carries the primitive and `PolicyVerification` deliberately
does not call it, because no claim made here is about history.

One residual detail worth knowing: an impostor pointing at somebody else's
engine is *inert*, because `recordTransfer` is notifier-gated and the transfer
path calls it unconditionally. The cheap forgery fails closed; a working one has
to stand up its own engine and therefore its own honest, readable policy.

### 3.4 On-chain consumers are hypothetical

`PolicyVerification` is a library nothing on-chain currently calls. The
realistic consumer is off-chain — a wallet, a marketplace, an explorer — and
none exists yet. Until one does, enumerability is a property nobody is reading.
This is the gap most worth closing next, and it is a UI problem rather than a
contract problem.

### 3.5 Gas

`evaluate()` is a linear scan, so cost grows with rule count. The ERC-1155 batch
path consults the policy once per item rather than once per call — the honest
price of a batch meaning exactly what the transfers it bundles mean. `Rule` is
unpacked for legibility and could pack `kind`, `scoped` and a narrowed `value`
into fewer slots.

---

## 4. Decisions worth not re-litigating

Each of these was argued and settled; several reverse an earlier position.

**Inheriting the engine into tokens: fatal.** It destroys the thesis three ways
— no canonical hash (every issuer's token compiles differently, back to
bespoke), no exhaustiveness (the author adds a `require` in their own path), and
storage collision. Inheritance and canonical-hash verification are mutually
exclusive *at the leaf*. A shared abstract base among the members of the set is
fine, because a non-member that inherits it simply matches no published hash.

**A tier-2 "bring your own token" adapter: not the adoption path.** It silently
weakens the claim to "the policy is enumerable" without "nothing else blocks",
which is the half that matters. It must never be documented as an extension
point.

**The wrapper/logic layers: deleted.** They existed to be canonical while an
author's `logic` contract was bespoke. A closed set has no bespoke logic, so the
premise dissolved and the chain collapsed from four contracts to two. Worse than
redundant, they were contradictory: a hooks-based deployment falsifies the
headline claim, so shipping both published an extension point implicitly.

**A STATICCALL pull model: obsolete.** Proposed to reach third-party tokens;
the closed set removes the reason. The one insight worth keeping is that
`evaluate` being `view` means the whole subcall frame is already
STATICCALL-enforced to arbitrary depth — so "nothing can write back" was never
the pull model's contribution.

**`initialize`-once instead of constructor binding: rejected.** Once the token
is canonical, a one-shot setter buys nothing the constructor doesn't, and costs
a window in which the token exists with no policy. If the token is *not*
canonical the `initialized` guard proves nothing anyway — it only works when you
already have what makes it unnecessary.

**No proxies, ever.** A canonical proxy in front of a mutable implementation
verifies clean and means nothing. Not present today; the point is to keep it
out.

**Generalising beyond ERC tokens: a trap.** Enumerability depends on a narrow
decision surface. A universal "any action on any contract" policy degrades back
into code. ERC-4337 validators are the one adjacent domain worth a second
instance later.

---

## 5. Two bugs that recur, recorded so they stop recurring

**Balance inflation on self-transfer.** Caching both balances before writing
means, when `from == to`, the credit overwrites the debit and the transfer mints
from nothing. Found in `IntegrityERC721` during a review, then written again in
`PolicyERC20._moveBalance` and caught by a new test. It looks like an
optimisation, which is why it keeps getting written. Every `_move*` function now
opens with an early return and a comment saying why.

**Auditing for blocking levers but not confiscation ones.** The selector-absence
test originally asserted `pause`, `freeze` and `blacklist` were absent while
`burn(address,uint256)` sat in the contract — an admin able to zero any holder's
balance. Blocking stops you moving a token; burning takes it. A design that
rejects `pause()` on principle cannot accept admin burn, and the test now covers
both categories.

---

## 6. Where this goes

**Shipped: per-action policy.** `docs/SPEC-per-action-policy.md`, now
implemented. The policy is a function of (action, rule) rather than rule alone,
which deleted the mint/burn carve-out — the exemption the `burn` confiscation
hole lived inside — and turned the claim from "only these rules can block your
transfer" into a total statement over the ABI.

It stayed decidable because it is a product of two finite dimensions rather
than an escalation to stored programs. It also added a claim the timelock
cannot make: `allowedKinds` is `pure` and therefore canonical, so a reader
learns the permanent envelope of what could *ever* gate an action, not merely
what gates it today.

**Then: an off-chain reader.** Paste a token address, render its policy. The
value of enumerability is only realised once something reads it, and this is a
UI problem rather than a contract problem — see §3.4.

**Specified but deliberately shelved: address-as-commitment.** A token is
currently EOA-deployed via plain `CREATE`, so nothing about its origin is
checkable. Deploying it through a canonical factory with
`salt = keccak256(abi.encode(config))` would make the address commit to the
launch configuration, giving the one class of claim this design cannot currently
make — history. Recompute the address from the token's self-reported config and
compare; any lie moves the address.

Two details make it cleaner than it first appears. Constructor arguments are
part of init code, so the address already commits to them — and if the token
takes *no* constructor arguments and calls back to the factory for its
parameters (the Uniswap V3 pool pattern), `initCodeHash` collapses to a single
constant per contract type. More importantly, `type(C).creationCode` compiles
for contracts holding immutables while `type(C).runtimeCode` does not, so
switching the verification primitive from runtime hash to CREATE2 address
**dissolves the zero-immutable constraint as a side effect** — configuration
could move from storage into immutables.

Shelved rather than rejected: it costs an anchor (a factory address, though one
derivable from source via the standard deterministic deployer) and it buys a
second claim while nothing yet reads the first. Full history verification also
needs the launch config from the factory's deployment log, so it is inherently
an off-chain, log-indexing operation.

**Rejected: a canonical template executing stored programs.** Considered and
argued down. A contract that reads operations from storage and executes them is
an interpreter, and verifying the interpreter proves only that it faithfully
runs an unbounded program — the enumerability collapses, because sequential
composition of state transitions is not comprehensible from its parts the way
AND-composition of predicates is. It is also, structurally, an upgradeable proxy
with worse gas, which the no-proxies rule already forbids. The salvageable
fragment is enumerating *capabilities* rather than implementation, which the
per-action spec above partly subsumes.

**After that: standardise the vocabulary, not the implementation.** If `RuleKind`
and `Rule` became an ERC, a wallet would write one reader and every conforming
token would benefit regardless of whose engine they deployed — a primitive
others build on rather than a framework others adopt. That reframes what needs
scrutiny: the ten rule kinds in `PolicyTypes.sol` are the part that must survive
contact with real issuers, and they deserve far more adversarial review than
they have had.

**Not next:** more rule kinds, more token variants, or anything that widens the
surface before something reads the surface that exists.
