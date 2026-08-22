# Design notes: what this framework proves, what it doesn't, and where it goes

Companion to the [README](../README.md). The README documents *how* the
framework works; this file records *why* it is shaped this way, what the
central idea is actually worth once scoped honestly, the structural
limitations that follow from the design, and the roadmap that addresses them.

Written against the state of `refactor/focus-pipeline` (67 tests, pre-audit).

---

## 1. The central idea, scoped precisely

The framework's one novel contribution is in
[`IntegrityVerifier.sol`](../contracts/libraries/IntegrityVerifier.sol):
deriving a contract's expected runtime codehash **at compile time**, from
imported source, via `keccak256(type(IntegrityERC721).runtimeCode)` — which
compiles only because `IntegrityERC721` and `HooksWrapperERC721` hold zero
`immutable` state.

It is worth being exact about which part of that is new, because two parts of
it are not.

**Not new: comparing `EXTCODEHASH` against a known-good value.** This is
routine. EIP-1167 clone detection, CREATE2 address derivation, and Uniswap
V2's `init_code_hash` all do it.

**Not new: the trust reduction.** The README's "no published hash to trust"
overstates the case. A verifier still has to trust that the source it imported
is the genuine framework source. Importing `IntegrityVerifier.sol` from a repo
and reading a published hash constant from that same repo bottom out in the
same supply-chain trust. The anchor is relocated, not eliminated.

**Actually new, and the part worth keeping: the hash cannot drift from the
source.** A published constant can go stale — Uniswap V2's hardcoded
`init_code_hash` is a well-known footgun precisely because forks changed the
source and forgot to update the constant, and integrators silently computed
wrong pair addresses. Here that failure mode is structurally impossible: the
hash is *derived from* the source it describes, in the same compilation.

**Also new, and the best design decision in the repo: the invariant is
self-enforcing.** Add a single `immutable` to any verified token or wrapper and
`IntegrityVerifier.sol` stops compiling, with the compiler naming the reason:

```
Error (9274): "runtimeCode" is not available for contracts containing
              immutable variables.
```

The property cannot decay into a convention that nobody checks. CI catches it
on the commit that breaks it, not in an audit six months later. This is the
same move the framework makes elsewhere — `CALL` never `DELEGATECALL`,
non-`virtual` entry points — applied to the verification layer: replace a
guarantee that depends on reviewer discipline with one the compiler enforces.

That is the contribution. It is a technique, not a new trust model, and it is
worth roughly what a good technique is worth.

### 1.1 The boundary of a codehash, and how it is closed

A runtime codehash constrains **future behaviour** and nothing else. It cannot
speak to how current state arose, because the constructor that wrote the
initial storage lives in the **creation** code, which `EXTCODEHASH` never
covers.

Init code and runtime code are independent byte strings — `CREATE` stores
whatever the init code `RETURN`s. So an attacker can write an arbitrary
constructor that fabricates storage, then return canonical runtime bytes copied
off any real deployment (public by design, `EXTCODECOPY`-able on chain). The
result passes `isCanonicalERC721()` *honestly*: it really does run canonical
code. `test/CodehashLimits.t.sol` demonstrates this — a contract reporting a
`totalSupply` no mint ever created, a `hooksContract()` that never deployed it,
and a byte-identical codehash.

The rule this yields, and the one to design against:

> Guarantees about **future behaviour** can ride on a codehash.
> Guarantees about **history** cannot, and need CREATE2 provenance as well.

Run the original claims through that filter and they sort cleanly. Locked entry
points, `CALL`-not-`DELEGATECALL`, the STATICCALL-enforced `view` on
`validateTransfer`, and the section 4.1 timelock are all future-tense — they
survive on a codehash alone. "The wrapper reference is unspoofable" and "supply
is confined to `onlyIssuerAdmin`" are past-tense, and both failed, for the same
single reason.

**The closure.** A CREATE2 address is a commitment to the init code:

```
address = keccak256(0xff ++ deployer ++ salt ++ keccak256(initCode))[12:]
```

Each wrapper now deploys its token with `new IntegrityERC721{salt: TOKEN_SALT}`,
and `isProvenanceVerifiedERC721(token, wrapper)` recomputes that address from
`type(IntegrityERC721).creationCode` plus the constructor arguments read back
off the token. The arguments are self-certifying — any lie changes the init-code
hash, hence the address, hence the result. A match proves the canonical
constructor actually ran, which restores the past-tense claims in full.

Three things worth recording about this:

- **No new anchor.** The CREATE2 deployer is the wrapper, already an input to
  the check. No factory, registry, or singleton is reintroduced, so the
  anchor-free property of section 1 is preserved.
- **`constant`, not `immutable`.** `TOKEN_SALT` is a `constant`, which inlines
  into bytecode and does not break `type(C).runtimeCode`. The self-enforcing
  zero-immutable constraint is untouched.
- **A transferable admin needed a permanent record.** `transferIssuerAdmin`
  moves `issuerAdmin`, so the current value is not the constructor argument.
  `TokenAdmin._deployAdmin` records the deploy-time admin in its own setter-less
  slot; without it, an admin handover would silently make a deployment
  unverifiable.

**Provenance is strictly more powerful than the codehash check.**
`type(C).creationCode` is available even for contracts holding immutables —
only `runtimeCode` is restricted — so this technique extends to tokens the
zero-immutable discipline currently rules out. The two are complementary rather
than redundant: the codehash is cheap and needs no arguments but speaks only to
the future; the CREATE2 derivation needs the arguments and proves the history.

---

## 2. Prior art, honestly

| Prior art | Relationship |
|---|---|
| **ERC-1404** | Restriction logic lives *inside* the token. No separate deployment; nothing stops the same function from mutating balances. This framework's separation is a strict improvement. |
| **ERC-3643 (T-REX)** | The closest serious comparison. Modular compliance, but routed through a trusted `Compliance` contract, and — importantly — **updatable**. Has institutional RWA adoption and a standards body. Beats this framework on adoption and on policy mutability; loses on the calling-convention guarantee. |
| **ERC-902** | Standardises external transfer validators. Stagnant. |
| **ERC-7943 (uRWA)** | Newer, minimal RWA interface. Occupies adjacent design space. |
| **Uniswap v4 hooks** | The dominant non-EIP prior art for `CALL`-based, separately-deployed extension points. The extension model here is a stricter point on that same spectrum, not a new axis. |
| **Diamond facets / Safe modules** | Wire extensions in via `DELEGATECALL`, so the extension runs in the host's storage. This is the pattern the framework is a reaction to — but note these are wallet and upgradability products, a different category from transfer-restriction hooks. |

The extension model — deny-only, separately deployed, `CALL`-invoked — is a
sound point on an existing spectrum. The verification technique is the part
without close prior art.

---

## 3. Structural limitations

These follow from the design rather than from incomplete implementation. They
are the honest cost of the guarantees above.

### 3.0 Resolved: the constructor was outside the verified perimeter

Recorded here because the repository shipped with it. A canonical runtime
codehash said nothing about the constructor that wrote the initial state, so
fabricated supply and a fabricated wrapper reference both passed verification.
Closed by the CREATE2 provenance check in section 1.1; the failing case is kept
as an executable test in `test/CodehashLimits.t.sol` rather than deleted,
because it documents where the boundary sits.

### 3.1 The verified perimeter excludes everything that carries risk

The token and the wrapper get a universal hash — and they contain no policy.
`logic`, which contains *all* the policy, is deliberately not coverable by any
universal hash: it carries per-developer state and immutables by design.

So verification proves the plumbing and never the behaviour. A canonical token
behind a canonical wrapper can still deny every transfer, or allow exactly the
ones a hostile issuer wants. This is stated in the README, but its weight
deserves emphasis: the headline feature verifies the part of the system that
was never where the risk lived.

### 3.2 Immutable `logic` fights the primary use case

`HooksWrapperERC721` captures `logic = msg.sender` in its constructor with no
setter. Policy is therefore fixed for the life of the deployment.

The natural market for deny-only transfer hooks is compliance and RWA — a
domain where rules change constantly: new sanctioned jurisdictions, revised
accreditation thresholds, changed holding periods. ERC-3643 supports updatable
compliance for exactly this reason. Under the current design, a rule change
means redeploying the entire stack and migrating holders, or having the logic
contract hold its own updatable pointer to a sub-policy — at which point the
mutable, unverified component holds all the risk and the wrapper hash covers
none of it.

This is the sharpest tension in the design. Section 4.1 proposes a resolution
that strengthens the verification claim rather than trading it away.

### 3.3 On-chain consumers are, so far, hypothetical

`IntegrityVerifier` is an `internal` library intended to compile into a
consumer such as a marketplace. Two frictions:

- Established marketplaces (Seaport, Blur) will not add per-framework codehash
  checks. There is no incentive.
- Any integrator must compile with byte-identical settings — solc `0.8.34`
  exactly, `viaIR = true`, optimizer 200 runs, `cancun`, `cbor_metadata =
  false`. That is real coordination cost for a check whose off-chain
  equivalent (Sourcify, Etherscan verification) already exists and is free.

Worth noting that the **pairing checks** (`isConsistentPair`,
`isConsistentLogicPair`) carry none of this friction — they need no hash and no
compiler-settings agreement, work against any deployment, and are cheap. They
are currently undersold relative to the bytecode-hash story and are probably
the more adoptable primitive of the two.

### 3.4 Adoption currently requires abandoning the existing token stack

Conformance means inheriting `HooksLogicERC20/721/1155` and taking
`IntegrityERC20/721/1155` with it. An issuer therefore gives up OpenZeppelin,
ERC721A's batch-mint gas profile, `permit`/EIP-712, enumerable extensions,
per-token royalty, and role-based admin (there is a single `issuerAdmin`), with
no upgrade path.

That is a very high switching cost for a guarantee about the hooks layer. It is
what makes this a framework rather than a standard, and it is the single
largest barrier to anyone using it. See section 4.2.

### 3.5 Minor: unbounded revert-reason returndata

The token copies an untrusted `string memory reason` out of the logic contract
on every gated call — e.g.
[`IntegrityERC721.sol`](../contracts/token/IntegrityERC721.sol) in
`_transferPipeline721` — with no bound on returndata size. A hostile logic
contract could grief gas by returning a very large string. The griefing is
self-inflicted (the issuer chooses the logic contract), so this is a nit rather
than a finding, but a returndata bound would be cheap and is worth adding.

---

## 4. Where this goes

Two changes, in this order. The first is the interesting one.

### 4.1 Timelocked logic swaps, enforced in canonical bytecode

The obvious fix for 3.2 — add `setLogic()` — would delete most of the value of
section 1. Today, "this wrapper is canonical" implies "the policy behind it is
the policy that was there at deployment." With a plain setter, a canonical
wrapper proves almost nothing: an issuer verifies clean, and swaps in hostile
policy afterwards.

The version that is not a trade-off: **make `setLogic` two-phase, with the
delay as a compile-time constant in the wrapper.** Propose, emit an event, wait
`LOGIC_SWAP_DELAY`, commit. Because the wrapper remains canonical, un-inherited
and immutable-free, its codehash then carries a strictly stronger claim:

> Verifying this wrapper's codehash proves that the policy governing this token
> cannot change without `N` days of public, on-chain notice.

No registry, no admin key, and no off-chain promise can offer that, and a
stranger can check it with one `EXTCODEHASH`. It is the same move the framework
already makes twice: convert a property that would normally be a documented
convention into one that is enforced by bytecode.

Implementation sketch:

- `pendingLogic` / `pendingLogicAt` as plain storage, no immutables (the
  section 1 constraint continues to hold, and continues to enforce itself).
- `proposeLogic(address)` and `commitLogic()`, both `onlyLogic` or
  `onlyIssuerAdmin` — the authorisation model needs a decision, since today the
  wrapper has no admin of its own.
- `LogicProposed(address indexed newLogic, uint256 effectiveAt)` so the notice
  is indexable off-chain without polling.
- `LOGIC_SWAP_DELAY` as a `constant` — note that `constant` is inlined into
  bytecode and, unlike `immutable`, does **not** break `type(C).runtimeCode`.
  A different delay is a genuinely different wrapper with a different hash,
  which is the correct semantics: an integrator choosing to accept a 1-day
  wrapper and a 30-day wrapper is making two different risk decisions and
  should have to opt into each explicitly.
- Tests: the existing `Verification.t.sol` pattern extends directly — assert
  the codehash is unchanged across deployments that have swapped logic, and
  that a swap cannot commit early.

### 4.2 Implementation independence

The concrete gate for 3.4, already named in the README's "What's not there
yet." The target: a canonical `HooksWrapperERC721` that can govern an
OpenZeppelin, ERC721A, or Solady token rather than requiring `IntegrityERC721`.

This is a larger refactor than anything on this branch, because the current
guarantees lean on properties of the bundled token — non-`virtual` entry
points, the setter-less `msg.sender`-derived wrapper reference,
`onlyIssuerAdmin` mint and burn. A third-party token provides none of them, so
the honest version of this work is to determine *which* guarantees survive the
separation and document the reduced claim, rather than to assert the full claim
over tokens that cannot support it.

The gate remains a conformance test suite that passes against someone else's
ERC-721 wired through the wrapper pattern. Until that exists, this is a
framework, not a standard.

### 4.3 Smaller items

- Invariant and fuzz tests: `sum(balances) == totalSupply`, no-op
  self-transfers, pause gating on every entry point. The current 67-test suite
  is broad but example-based.
- Bound revert-reason returndata (3.5).
- Surface the pairing checks (3.3) more prominently — they are the primitive
  most likely to be adopted.
- Packaging: a documented `forge install` flow and versioned releases.
- Security disclosure policy; external audit.

---

## 5. Summary

The framework's contribution is a verification technique — compile-time hash
derivation made possible and kept honest by a self-enforcing zero-immutable
constraint — demonstrated inside a strictly one-directional, deny-only token
pipeline. The technique is sound, tested, and the property it guarantees cannot
silently rot.

Its limits are equally clear. Verification covers the plumbing rather than the
policy; fixed `logic` sits badly with the compliance use case that most wants
this shape of extension; and requiring the bundled token puts the switching
cost above what the guarantee currently justifies.

Section 4.1 is the change that makes the central idea prove something a
competing design cannot, and section 4.2 is the change that makes the framework
installable at all. In that order.
