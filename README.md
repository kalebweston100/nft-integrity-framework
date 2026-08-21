# Integrity Token Framework

A Solidity framework for ERC-20 / ERC-721 / ERC-1155 tokens with a locked,
non-bypassable transfer pipeline and a strictly one-directional external hooks
layer that lets a developer bolt on custom policy without ever gaining the
ability to override core guarantees — or to write back to the token at all.

There is no factory: a developer deploys their own hooks logic contract, and
that single deployment cascades — via chained constructors, one transaction —
into the wrapper and the token that govern it.

Anyone can then confirm that a given token address, AND the wrapper governing
it, run the real, unmodified implementation, with **no published hash, no
registry, and no admin key to trust** — the expected bytecode hash is derived
at compile time by whoever is doing the checking. See "Verifying a deployment"
below; it's the most interesting idea in this repository.

> **Status: pre-audit.** The contracts are implemented, tested (70 tests, CI on
> every push), and internally consistent, but there has been no external
> security review. Do not deploy real value on top of this yet.

## Why

Most "compliance hook" or "extension point" patterns for tokens give the
extension full access to token storage, which means a badly written or
malicious hook can bypass the very rules it was meant to enforce. This
framework inverts that: the token contract owns all state and the transfer
pipeline; the hooks layer is a separate deployment that the token calls
externally and which can only **deny** — it has no path to mutate balances or
ownership, and no path to call the token at all. Calls flow in exactly one
direction, always: Token → Wrapper → Logic. Nothing downstream ever calls back.

The common way projects add third-party extensibility to a token — Diamond
facets, Safe-style modules — wires the extension in via `delegatecall`, so the
extension runs inside the *host's own* storage context. That's a large share of
why module-related exploits happen: a buggy or malicious module doesn't just get
to say yes/no, it gets to touch everything. This framework makes non-authority a
property of the calling convention itself — plain external `CALL`, never
`DELEGATECALL` — rather than something enforced by review discipline.

Prior art worth comparing against: **ERC-1404** puts restriction logic inside the
token contract, so there's no separate deployment and nothing stopping the token
author from having that same function quietly mutate balances on the side.
**ERC-3643**'s compliance modules are closer, but are typically routed through
one trusted `Compliance` contract. **ERC-902** standardises external transfer
validators but is stagnant. **Uniswap v4 hooks** are the dominant non-EIP prior
art for `CALL`-based, separately-deployed extension points. What this framework
adds on top is the verification story below.

## Architecture

Three contracts, one deployment, calls flowing one way only:

```
Logic (developer-deployed, inherits HooksLogicERC20/721/1155)
   │  - constructor deploys the Wrapper via `new`
   │  - custom deny/notify policy lives here, and ONLY here
   │  - issuerAdmin, admin-gated custom functions
   │  - has NO reference to the token's type at all — imports only
   │    HooksAdmin and its own HooksWrapper*, nothing from contracts/token/
   │
   │ `new`, synchronously, inside Logic's constructor
   ▼
Wrapper (HooksWrapperERC20/721/1155 — canonical, never inherited)
   │  - constructor deploys the Token via `new`; captures `logic` from
   │    msg.sender (unspoofable)
   │  - zero custom behavior: every call is forwarded to `logic`, unmodified,
   │    via plain external CALL — never DELEGATECALL
   │  - `token` and `logic` are plain storage, no setter, NOT immutable — see
   │    "Verifying a deployment"
   │
   │ `new`, synchronously, inside the Wrapper's constructor
   ▼
Token (IntegrityERC20 / IntegrityERC721 / IntegrityERC1155)
   - owns all balance/ownership storage
   - transfer/mint/burn entry points are non-virtual (locked)
   - reads its governing wrapper address from msg.sender at construction
     (unspoofable) and stores it in a plain, setter-less slot, deliberately
     NOT immutable
   ▲
   │ external CALL, at fixed points in the pipeline
   └─ Wrapper: beforeX (notify) / validateX (deny gate) → can block;
      afterX → wrapped in try/catch by the token, so a bug anywhere in the
      Wrapper → Logic chain can't brick the token
```

Deploying `MyLogic` is the one transaction a developer runs; three chained
`new` calls — Logic → Wrapper → Token — bring the whole governed token into
existence with no separate initialization step and no window where any piece
exists but isn't wired.

**Nothing ever calls back.** `token.hooksContract()` always returns a real,
non-zero wrapper address — the token only exists because that address called
`new` on it — and the wrapper and logic contracts have no entry point through
which they could write token state even if they wanted to. There is no
hook-initiated mint, nothing. Mint and burn are exclusively
`onlyIssuerAdmin`-gated on the token, unconditionally.

## Core concepts

- **Locked pipeline.** `transferFrom`, `mint`, `burn`, etc. are not `virtual` on
  the concrete token contracts. There is no inheritance path for a hooks author
  (or the issuer) to change what "transfer" means.
- **Deny-only, and one-directional, with no exceptions.** `validate*` and
  `before*` hooks can refuse an action; nothing on the hooks side has any path
  to write token storage, ever. Earlier drafts of this framework carried a
  narrow hook-initiated mint capability; it's gone. Mint and burn are
  exclusively issuer-admin-gated, full stop.
- **Strict superset of the base standard.** A conforming token stays a fully
  conforming ERC-20/721/1155: zero-value transfers succeed, batch operations
  emit exactly one `TransferBatch`, and no hook can make the token deviate from
  the standard except by reverting the whole call.
- **Permissionless, single-transaction deployment.** Anyone can deploy their own
  logic contract and become the issuer admin of their own token — the wrapper
  and the token come into existence as a side effect of the same transaction.

### Extension points

Every hook has an internal `virtual` counterpart on `HooksLogicERC20/721/1155`
— the abstract base a developer inherits. Override the `_on*` function, never
the external one — the external functions carry `onlyWrapper` and are
non-virtual so an override cannot remove that check.

| Kind | Functions | Behaviour |
|---|---|---|
| Deny gates | `_onValidateTransfer`, `_onBeforeMint`, `_onBeforeBurn` | Fail-closed. Return `(false, reason)` to block. |
| Notifications | `_onBeforeTransfer`, `_onAfterTransfer`, `_onAfterMint`, `_onAfterBurn` | Fail-open. `after*` is try/catch-wrapped by the token around the entire Wrapper → Logic call chain — a bug anywhere downstream can't brick the token. |

Deny a transfer through `_onValidateTransfer`, not by reverting in
`_onBeforeTransfer` — `beforeTransfer` is a settle-only notification.

`HooksWrapperERC20/721/1155` are the canonical, un-inherited contracts a
developer never touches directly — see "Verifying a deployment."

## Verifying a deployment

Solidity exposes a contract's runtime bytecode at compile time as
`type(C).runtimeCode` — but **only for contracts with no immutable variables**.
A contract with immutables has no single runtime bytecode, because the values are
patched into the code at construction. The compiler rejects the expression
outright:

```
Error (9274): "runtimeCode" is not available for contracts containing
              immutable variables.
```

`IntegrityERC20`/`721`/`1155` hold **zero** immutable state — each stores its
governing wrapper address in a plain storage slot, written once in the
constructor from `msg.sender` (unspoofable), with no setter anywhere.
`HooksWrapperERC20`/`721`/`1155` apply the identical trick one layer out:
`token` and `logic` are ALSO plain storage, set once from the constructor with
no setter. `EXTCODEHASH` never covers storage, only code, so every canonical
deployment of a given token OR wrapper version is byte-identical forever,
regardless of which contract deployed it.

That combination is what makes verification anchor-free, for both layers. A
verifier that imports this source derives both expected hashes itself:

```solidity
import "contracts/libraries/IntegrityVerifier.sol";

contract MyMarketplace {
    bytes32 private immutable _canonical721;
    bytes32 private immutable _canonicalWrapper721;

    constructor() {
        // Derived at compile time. Nothing published, nothing looked up.
        _canonical721 = IntegrityVerifier.canonicalERC721Hash();
        _canonicalWrapper721 = IntegrityVerifier.canonicalWrapperERC721Hash();
    }

    function isFullyCanonical(address token, address wrapper) external view returns (bool) {
        return IntegrityVerifier.isCanonical(token, _canonical721)
            && IntegrityVerifier.isCanonical(wrapper, _canonicalWrapper721);
    }
}
```

Two properties worth calling out:

**The check never calls into the target.** `EXTCODEHASH` is read directly by the
EVM from the target's deployed bytecode, so a malicious contract can't misreport
it the way it could if you called an `isCanonical()`-style function defined *on*
the contract you're verifying — that contract could simply hardcode it to return
true. This is also why the property can never be expressed as an interface the
target implements: an interface is a thing you call, and the whole point is not
to take the target's word for anything.

**The constraint enforces itself.** If anyone ever adds an `immutable` to a
token or wrapper contract, `IntegrityVerifier.sol` stops compiling. The
invariant can't silently decay into a convention nobody checks — the same move
the framework makes with `CALL`-not-`DELEGATECALL`, applied to the verification
layer, at both hops.

`IntegrityVerifier` is an `internal` library, so it has no deployed address of
its own — it compiles into whatever contract uses it. Routing the check through
an intermediary would only add an address to trust.

### Pairing checks

Two mutual-reference checks, the identical pattern applied at each hop of the
chain:

- `IntegrityVerifier.isConsistentPair(token, wrapper)` — `token → wrapper` is
  **unspoofable** (written once, from `msg.sender`, no setter); `wrapper →
  token` is **author-controlled** (any contract can declare a `token` address
  pointing at someone else's legitimate token).
- `IntegrityVerifier.isConsistentLogicPair(wrapper, logic)` — same asymmetry,
  one layer further out: `wrapper → logic` is unspoofable, `logic → wrapper` is
  author-controlled.

Checking the round trip closes the spoofable direction using the unspoofable
one: a fake wrapper can claim to govern a real token, but that token won't name
it back; a fake logic contract can claim a real wrapper, but that wrapper only
names whoever actually deployed it. Requires no hash and no compiler-settings
agreement, so both are worth running even where bytecode comparison is
impractical.

### What this proves, and what it doesn't

**Verifying the token alone proves:** the token runs exactly the pipeline in
this repository — locked entry points, `CALL`-only invocation of its wrapper,
setter-less wrapper reference — and that mint/burn can only ever be triggered
by the issuer admin. There is no hook-initiated write path anywhere in this
framework, so a canonical token's supply is provably confined to
`onlyIssuerAdmin`, regardless of what governs it.

**Verifying the wrapper adds:** proof that the address governing the token
actually honours the deny-only calling convention — that it forwards every
call to `logic` via plain external `CALL`, that the deny gates are exactly the
ones documented, and that `validateTransfer`'s `view` guarantee is
compiler-enforced at both hops (Wrapper → Logic is a `STATICCALL` because both
sides declare the function `view`).

**Neither proves the token is safe to buy.** `logic` — the actual custom
policy a developer wrote — is deliberately *not* covered by any universal hash;
it carries per-developer state and immutables by design, so there was never
going to be one hash for "a logic contract" the way there is for the token and
the wrapper. A canonical token behind a canonical wrapper can still have every
transfer denied by hostile logic. Verifying a *specific* logic implementation
with `isCanonical` is still meaningful; it just answers a narrower question
("does this address run exactly the code its author published for this logic
contract") than the ecosystem-wide one the token/wrapper hashes give you.

Verification also still bottoms out in reading source. What's eliminated is every
*additional* anchor: no registry, no factory, no admin key, no published hash
artifact — for either the token or the wrapper. The hash travels with the
source, not with a person.

### Required compiler settings

Bytecode is only comparable across independent compilations if the build is
reproducible. A verifier must compile with the same settings as the deployment
it's checking. This repo's canonical settings live in `foundry.toml`:

- solc `0.8.34`, pinned exactly — not a floating `^0.8.34`.
- optimizer on, `200` runs; `evmVersion = "cancun"`; `viaIR = true`. The sources
  compile without `viaIR`, but it stays pinned because turning it off changes
  the bytecode and therefore every canonical hash.
- `bytecode_hash = "none"` and `cbor_metadata = false`, which drop the CBOR
  metadata trailer. Without this, two people compiling identical source get
  different hashes purely from a trailer derived from absolute file paths.

A settings mismatch fails **closed** — a legitimate deployment is rejected
rather than a malicious one accepted — but it's a real operational hazard, so
pin the profile rather than relying on defaults.

Note that `codehash` is `0` for EOAs and nonexistent accounts, and
`keccak256("")` for an existing account with no code. Derive expected values from
the `canonical*Hash()` helpers rather than pasting literals.

## What's implemented

| Concern | ERC-20 | ERC-721 | ERC-1155 |
|---|---|---|---|
| Logic → Wrapper → Token, one-directional, zero-immutable at both layers | ✅ | ✅ | ✅ |
| Locked transfer/mint/burn pipeline | ✅ | ✅ | ✅ |
| Full overridable hook surface (deny gates + notifications) | ✅ | ✅ | ✅ |
| `IHooksERC*` conformance + ERC-165 discovery (on the wrapper) | ✅ | ✅ | ✅ |
| Compile-time canonical hash + pairing checks (Token↔Wrapper, Wrapper↔Logic) | ✅ | ✅ | ✅ |
| Pause / issuer admin transfer | ✅ | ✅ | ✅ |
| ERC-2981 royalty info | — | ✅ | ✅ |
| Example logic contracts (`contracts/test/`) | ✅ | ✅ | ✅ |

Also present: a shared `Errors.sol` (custom errors, no revert strings on hot
paths), `Types.sol` (`TokenStandard` enum), and `HooksAdmin.sol` (the
`issuerAdmin` / `transferAdmin` bookkeeping shared by all three
`HooksLogicERC*` bases).

## Development

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

```sh
git submodule update --init --recursive   # OpenZeppelin Contracts + forge-std
forge build                               # uses the pinned profile in foundry.toml
forge test                                # 70 tests
forge fmt --check                         # verify formatting matches CI
```

CI (`.github/workflows/ci.yml`) runs `forge build --sizes`, `forge test`,
`forge fmt --check`, and a Slither pass on every push and pull request.

## What's not there yet

- **Implementation-independence.** Right now nothing can conform without
  inheriting `HooksLogicERC20`/`721`/`1155` and taking `IntegrityERC*` with it.
  That makes this a framework, not a standard. The concrete gate is a
  conformance test suite that passes against someone else's ERC-721
  (OpenZeppelin, ERC721A, Solady) wired through this wrapper pattern.
- **Invariant / fuzz tests.** `sum(balances) == totalSupply`, no-op
  self-transfers, and pause gating on every entry point. The unit suite is broad
  but example-based.
- **Packaging** for consumption by other projects: a documented `forge install`
  flow for integrators and versioned releases.
- **A security disclosure policy and a professional audit.** This repo is
  pre-audit.

## License

MIT — see `LICENSE`, with per-file SPDX headers throughout.
