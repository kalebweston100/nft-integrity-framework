# Integrity Token Framework

A Solidity framework for ERC-20 / ERC-721 / ERC-1155 tokens with a locked,
non-bypassable transfer pipeline and an external "hooks" contract that lets a
developer bolt on custom policy without ever gaining the ability to override
core guarantees.

There is no factory: a developer deploys their own hooks contract, and that
contract's constructor deploys its token directly, as the return value of
`new` — one deployment, one transaction, no intermediary.

Anyone can then confirm that a given token address runs the real, unmodified
implementation, with **no published hash, no registry, and no admin key to
trust** — the expected bytecode hash is derived at compile time by whoever is
doing the checking. See "Verifying a deployment" below; it's the most
interesting idea in this repository.

> **Status: pre-audit.** The contracts are implemented, tested (69 tests, CI on
> every push), and internally consistent, but there has been no external
> security review. Do not deploy real value on top of this yet.

## Why

Most "compliance hook" or "extension point" patterns for tokens give the
extension full access to token storage, which means a badly written or
malicious hook can bypass the very rules it was meant to enforce. This
framework inverts that: the token contract owns all state and the transfer
pipeline; the hooks contract is a separate deployment that the token calls
externally and which can only **deny** — it has no path to mutate balances or
ownership.

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

```
Hooks (developer-deployed, inherits HooksERC20/721/1155)
   │  - constructor deploys the token via `new` and stores the returned
   │    address as `token` (immutable on the hooks side — hooks contracts
   │    carry per-developer state anyway)
   │  - issuerAdmin, custom deny/notify logic
   │
   │ `new`, synchronously, inside the hooks constructor — no separate
   │ initialization step, no window where hooks exists but isn't wired
   ▼
Token (IntegrityERC20 / IntegrityERC721 / IntegrityERC1155)
   - owns all balance/ownership storage
   - transfer/mint/burn entry points are non-virtual (locked)
   - reads its governing hooks address from msg.sender at construction
     (the deploying contract — unspoofable) and stores it in a plain,
     setter-less slot, deliberately NOT immutable — see "Verifying a
     deployment" for why that matters
   ▲
   │ external CALL, at fixed points in the pipeline
   └─ Hooks: beforeX (notify) / validateX (deny gate) → can block;
      afterX → wrapped in try/catch by the token, so a hook bug can't
      brick the token
```

`token.hooksContract()` always returns a real, non-zero address — the token only
exists because that address called `new` on it. There's no registry to consult:
the token's own storage says who governs it.

## Core concepts

- **Locked pipeline.** `transferFrom`, `mint`, `burn`, etc. are not `virtual` on
  the concrete token contracts. There is no inheritance path for a hooks author
  (or the issuer) to change what "transfer" means.
- **Hooks are deny-only.** `validate*` and `before*` hooks can refuse an action;
  they never receive a path to write token storage. The one exception is
  hook-initiated minting, which is deliberately split out as a declared
  capability — see below.
- **Strict superset of the base standard.** A conforming token stays a fully
  conforming ERC-20/721/1155: zero-value transfers succeed, batch operations
  emit exactly one `TransferBatch`, and no hook can make the token deviate from
  the standard except by reverting the whole call.
- **Permissionless, single-transaction deployment.** Anyone can deploy their own
  hooks contract and become the issuer admin of their own token — the token comes
  into existence as a side effect of the same transaction.

### Extension points

Every hook has an internal `virtual` counterpart. Override the `_on*` function,
never the external one — the external functions carry `onlyToken` and are
non-virtual so an override cannot remove that check.

| Kind | Functions | Behaviour |
|---|---|---|
| Deny gates | `_onValidateTransfer`, `_onBeforeMint`, `_onBeforeBurn`, `_onBeforeSet*URI` | Fail-closed. Return `(false, reason)` to block. |
| Notifications | `_onBeforeTransfer`, `_onAfterTransfer`, `_onAfterMint`, `_onAfterBurn`, `_onAfterSet*URI` | Fail-open. `after*` is try/catch-wrapped by the token. |

Deny a transfer through `_onValidateTransfer`, not by reverting in
`_onBeforeTransfer` — `beforeTransfer` is a settle-only notification.

### Minting authority

`hookMint` is the only path by which a hooks contract can write token state,
available via `_mintFromHooks` on every `Hooks*` base. It exists for cases like
mint-on-deposit, and it *is* real authority over supply — but there is
deliberately no ERC-165 marker for it. `token` is `public` and the token's
`hookMint` gates only on "caller is the governing hooks contract", so any hooks
contract can call it whether or not it advertises doing so; a declared
capability bit would only ever be a claim an honest author made voluntarily,
never something enforceable. Knowing whether a given hooks contract mints means
reading its source — the same requirement as knowing anything else about what
a hooks contract does.

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

`IntegrityERC20`/`721`/`1155` therefore hold **zero** immutable state. Each
stores its governing hooks address in a plain storage slot, written once in the
constructor from `msg.sender` (the deploying hooks contract — unspoofable), with
no setter anywhere. `EXTCODEHASH` never covers storage, only code, so every
canonical deployment of a given token version is byte-identical forever,
regardless of which hooks contract deployed it.

That combination is what makes verification anchor-free. A verifier that imports
this source derives the expected hash itself:

```solidity
import "contracts/libraries/IntegrityVerifier.sol";

contract MyMarketplace {
    bytes32 private immutable _canonical721;

    constructor() {
        // Derived at compile time. Nothing published, nothing looked up.
        _canonical721 = IntegrityVerifier.canonicalERC721Hash();
    }

    function isGenuine(address token) external view returns (bool) {
        return IntegrityVerifier.isCanonical(token, _canonical721);
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

**The constraint enforces itself.** If anyone ever adds an `immutable` to a token
contract, `IntegrityVerifier.sol` stops compiling. The invariant can't silently
decay into a convention nobody checks — the same move the framework makes with
`CALL`-not-`DELEGATECALL`, applied to the verification layer.

`IntegrityVerifier` is an `internal` library, so it has no deployed address of
its own — it compiles into whatever contract uses it. Routing the check through
an intermediary would only add an address to trust.

### Pairing check

`IntegrityVerifier.isConsistentPair(token, hooks)` confirms the two reference
each other. The directions are not equally trustworthy, which is the point:

- `token → hooks` is **unspoofable** — written once, in the token's own
  constructor, from `msg.sender`, with no setter.
- `hooks → token` is **author-controlled** — any contract can declare a `token`
  address pointing at someone else's legitimate token.

Checking the round trip closes the spoofable direction using the unspoofable one:
a fake hooks contract can claim to govern a real token, but that token won't name
it back. Requires no hash and no compiler-settings agreement, so it's worth
running even where bytecode comparison is impractical.

### What this proves, and what it doesn't

**Proves:** the token runs exactly the pipeline in this repository — locked entry
points, `CALL`-only hooks, setter-less hooks reference.

**Does not prove the token is safe to buy.** The hooks contract holds the
arbitrary logic and is deliberately *not* covered by any universal hash — hooks
contracts carry per-developer state and immutables by design. A canonical token
governed by hostile hooks can still deny every transfer, or mint without limit if
its hooks contract holds minting authority. Verifying a *specific* hooks
implementation with `isCanonical` is still meaningful; it just answers a narrower
question ("does this address run exactly the code its author published for this
hooks contract") than the ecosystem-wide one a token's hash gives you.

Verification also still bottoms out in reading source. What's eliminated is every
*additional* anchor: no registry, no factory, no admin key, no published hash
artifact. The hash travels with the source, not with a person.

### Required compiler settings

Bytecode is only comparable across independent compilations if the build is
reproducible. A verifier must compile with the same settings as the deployment
it's checking. This repo's canonical settings live in `foundry.toml`:

- solc `0.8.34`, pinned exactly — not a floating `^0.8.34`.
- optimizer on, `200` runs; `evmVersion = "cancun"`; `viaIR = true`. The sources
  now compile without `viaIR`, but it stays pinned because turning it off
  changes the bytecode and therefore every canonical hash.
- `bytecode_hash = "none"` and `cbor_metadata = false`, which drop the CBOR
  metadata trailer. Without this, two people compiling identical source get
  different hashes purely from a trailer derived from absolute file paths.

A settings mismatch fails **closed** — a legitimate token is rejected rather than
a malicious one accepted — but it's a real operational hazard, so pin the profile
rather than relying on defaults.

Note that `codehash` is `0` for EOAs and nonexistent accounts, and
`keccak256("")` for an existing account with no code. Derive expected values from
the `canonical*Hash()` helpers rather than pasting literals.

## What's implemented

| Concern | ERC-20 | ERC-721 | ERC-1155 |
|---|---|---|---|
| Hooks-deploys-its-own-token, zero-immutable bytecode | ✅ | ✅ | ✅ |
| Locked transfer/mint/burn pipeline | ✅ | ✅ | ✅ |
| Full overridable hook surface (deny gates + notifications) | ✅ | ✅ | ✅ |
| `IHooksERC*` conformance + ERC-165 discovery | ✅ | ✅ | ✅ |
| Compile-time canonical hash + pairing check | ✅ | ✅ | ✅ |
| Pause / issuer admin transfer | ✅ | ✅ | ✅ |
| ERC-2981 royalty info | — | ✅ | ✅ |
| Example hooks contracts (`contracts/test/`) | ✅ | ✅ | ✅ |

Also present: a shared `Errors.sol` (custom errors, no revert strings on hot
paths), `Types.sol` (`TokenStandard` enum), `IHooks.sol` (the token-side
`hookMint` entry points), and `HooksAdmin.sol` (the `issuerAdmin` /
`transferAdmin` bookkeeping shared by all three `Hooks*` bases).

## Development

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

```sh
git submodule update --init --recursive   # OpenZeppelin Contracts + forge-std
forge build                               # uses the pinned profile in foundry.toml
forge test                                # 69 tests
forge fmt --check                         # verify formatting matches CI
```

CI (`.github/workflows/ci.yml`) runs `forge build --sizes`, `forge test`,
`forge fmt --check`, and a Slither pass on every push and pull request.

## What's not there yet

- **Implementation-independence.** Right now nothing can conform without
  inheriting `HooksERC20`/`721`/`1155` and taking `IntegrityERC*` with it. That
  makes this a framework, not a standard. The concrete gate is a conformance test
  suite that passes against someone else's ERC-721 (OpenZeppelin, ERC721A,
  Solady) wired to a hooks contract.
- **Invariant / fuzz tests.** `sum(balances) == totalSupply`, no-op
  self-transfers, and pause gating on every entry point. The unit suite is broad
  but example-based.
- **Packaging** for consumption by other projects: a documented `forge install`
  flow for integrators and versioned releases.
- **A security disclosure policy and a professional audit.** This repo is
  pre-audit.

## License

MIT — see `LICENSE`, with per-file SPDX headers throughout.
