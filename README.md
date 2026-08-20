# Integrity Token Framework

A Solidity framework for deploying ERC-20 / ERC-721 / ERC-1155 tokens with a
locked, non-bypassable transfer pipeline and an external "hooks" contract
that lets a developer bolt on custom logic without ever gaining the ability
to override core guarantees. There is no factory: a developer deploys their
own hooks contract, and that contract's constructor deploys its token
directly, as the return value of `new` — one deployment, one transaction, no
intermediary.

NFTs (ERC-721 / ERC-1155) additionally carry an on-chain **flags** system:
an append-only registry of trait/certification labels, committed to each
token exactly once at mint, that a buyer can verify trustlessly before
purchase — no reliance on marketplace metadata or seller claims.

> **Status: early / pre-audit.** The contracts below are implemented and
> internally consistent, but there is no test suite, no CI, and no security
> review yet. Do not deploy real value on top of this until that changes.

## Distribution model

This project is a source library, like OpenZeppelin Contracts — not a
hosted service. There is no canonical deployment maintained by anyone, no
admin key held by the framework's authors, and no on-chain registry to keep
up. Each developer compiles the contracts and deploys their **own** hooks
contract (inheriting `HooksERC20`/`721`/`1155` or the `*Base` variants),
which deploys and owns its own token outright. What travels with a release
is the source and the token contracts' canonical bytecode hash, so anyone
can independently confirm a given token deployment is genuine — see
"Verifying a deployment" below.

## Why

Most "compliance hook" or "extension point" patterns for tokens give the
extension full access to token storage, which means a badly written or
malicious hook can bypass the very rules it was meant to enforce. This
framework inverts that: the token contract owns all state and the transfer
pipeline; the hooks contract is a separate deployment that the token calls
externally and can only **add** restrictions (return `false` from a
`validate*` call) — it has no path to mutate balances, ownership, or the
flags registry directly.

## Architecture

```
Hooks (developer-deployed, inherits HooksERC20/721/1155)
   │  - constructor deploys the token directly via `new` and stores the
   │    returned address as `token` (immutable on the hooks side — hooks
   │    contracts carry per-developer state anyway, so there was never
   │    going to be one universal hash for them)
   │  - issuerAdmin, custom validate/before/after logic
   │
   │ `new`, synchronously, inside the hooks constructor — no separate
   │ initialization step, no window where hooks exists but isn't wired
   ▼
Token (IntegrityERC20 / IntegrityERC721 / IntegrityERC1155)
   - owns all balance/ownership/flags storage
   - transfer/mint/burn entry points are non-virtual (locked)
   - reads its governing hooks address from msg.sender at construction
     time (the deploying contract — unspoofable) and stores it in a plain,
     setter-less slot, deliberately NOT immutable — see "Verifying a
     deployment" for why that matters
   ▲
   │ external call, at fixed points in the pipeline
   └─ Hooks: beforeX / validateX → can block (require true / non-empty
      reason); afterX → wrapped in try/catch by the token, so a hook bug
      can't brick the token
```

**Trust surface:** `token.hooksContract()` always returns a real,
non-zero address — the token only ever exists because that address called
`new` on it. There's no separate registry to consult: the token's own
storage already tells you who governs it, and `Codehash.isCanonical(...)`
(see below) tells you whether the token itself is running unmodified code,
independent of which hooks contract deployed it.

## Core concepts

- **Locked pipeline.** `transferFrom`, `mint`, `burn`, etc. are not
  `virtual` on the concrete token contracts. There is no inheritance path
  for a hooks author (or the issuer) to change what "transfer" means.
- **Hooks are advisory-restrictive, not authoritative.** `before*`/`validate*`
  hooks can only deny; they never receive a path to write token storage.
  The one exception is hook-initiated minting (`hookMint`), which is a
  deliberate, narrow, `onlyHooksContract`-gated entry point for use cases
  like "mint on deposit" — even then, the hook still can't touch flags or
  balances outside what `hookMint`/`hookSetTokenURI` expose.
- **Flags (ERC-721/1155 only).** The issuer calls `defineFlag(bitIndex, label)`
  once per bit — the label is permanent (`FlagAlreadyDefined` on reuse). At
  mint, a flag bitmap and a `keccak256` metadata hash are committed
  atomically and are never writable again by anyone, issuer included.
  `verifyToken(tokenId, requiredFlagsMask, expectedMetadataHash)` gives a
  buyer a single view call to check both before purchasing.
- **Permissionless, single-transaction deployment.** Anyone can deploy their
  own hooks contract (`new MyHooks(issuerAdmin, ...)`) and become the issuer
  admin of their own token — the token comes into existence as a side effect
  of that same transaction, no separate deploy call, no factory instance to
  stand up first. Nothing here is shared across developers — see
  "Distribution model" above.
- **Optional `HooksFactory` convenience base.** A developer building a
  product on top of this framework (e.g. "mint NFTs on deposit") often wants
  their own contract to charge a platform-level fee for deploying hooks+token
  pairs on behalf of users. `contracts/hooks/HooksFactory.sol` is an abstract
  base for exactly that: two-step ownership and a platform fee accumulator —
  a concrete platform contract just does `address(new MyHooks(...))` in its
  own payable function, since deploying the hooks contract already deploys
  the token. It's purely additive — nothing in the core framework depends on
  it, and skipping it changes nothing about the guarantees above.

## A minimal, standalone hook standard (draft)

Everything above describes this repo's opinionated framework: an issuer admin,
on-chain flags, hooks contracts that deploy their own token. But the one
architectural property that actually differentiates the hooks design —
*a hooks contract is called externally (`CALL`, never `DELEGATECALL`), lives in
its own storage, and can only deny — never authorize or mutate host state* — is
currently just an implementation detail of `contracts/interfaces/IHooks.sol`.
Nothing about that property is specific to this framework's admin model or
flags system, and nothing forces another project's ERC-20/721/1155 to adopt
any of those to get the same guarantee.

`contracts/standard/` pulls that property out into its own draft interfaces —
`IHooksERC20`, `IHooksERC721`, `IHooksERC1155` — decoupled from the flags
system and this repo's specific token implementation entirely. The goal is a
spec small enough that *any* token contract can adopt it by adding one hooks
address and a handful of external calls at the right pipeline points, without
adopting this repo's token or deployment model at all.

**Why this is worth pulling out, instead of just being "how this repo happens
to work":** the common way projects add third-party extensibility to a token —
Diamond facets, Safe-style modules — wires the extension in via `delegatecall`,
so the extension runs inside the *host's own* storage context. That's a large
share of why module-related exploits happen: a buggy or malicious module
doesn't just get to say yes/no, it gets to touch everything. `IHooksERC*`
instead makes non-authority a property of the calling convention itself, not
something enforced by review discipline. The closest prior art, ERC-1404
("Simple Restricted Token"), gets partway there but puts the restriction logic
inside the token contract itself — there's no separate deployment and nothing
stopping the token author from having that same function quietly mutate
balances on the side. ERC-3643's compliance modules are closer but are
typically routed through one trusted `Compliance` contract, not a spec that
pins down `CALL`-only invocation or requires ERC-165 discovery of conformance.

**Normative rules the draft interfaces assume of a conforming host** (see the
NatSpec at the top of `IHooksERC20.sol` for the full text):

1. The host **MUST** invoke the hooks contract via a plain external `CALL` —
   never `DELEGATECALL`. This is what makes storage isolation a guarantee
   rather than a convention.
2. `before*` / `validate*` **MUST** be called unprotected — a revert or a
   `(false, reason)` return **MUST** block the action (fail-closed: hooks can
   authoritatively deny).
3. `after*` **MUST** be called inside a try/catch by the host — a bug or
   revert here **MUST NOT** be able to brick the host (fail-open: after-hooks
   are informational only and cannot deny after the fact).
4. A conforming hooks contract **MUST** return `true` from
   `supportsInterface(type(IHooksERC*).interfaceId)` (ERC-165), so a host,
   indexer, or marketplace can confirm conformance from the hooks address
   alone before wiring it up or trusting it.

**What's deliberately out of scope** of the base interfaces: multi-hook
composition, on-chain trait/certification registries (this repo's own
`IFlaggedToken`), royalty distribution, and any deployment machinery.
Composability in particular falls out for free rather than needing to be
designed in — since a hooks contract is just "any contract implementing the
interface," a router that fans one call out to several independent, mutually
untrusted sub-hooks is itself just another `IHooksERC*` implementation, the
same way an ERC-4626 vault can wrap other vaults.

`contracts/standard/HooksERC20Template.sol` / `HooksERC721Template.sol` /
`HooksERC1155Template.sol` are minimal reference implementations — copy one,
override the `_on*` internal hooks, done. They intentionally do **not** depend
on this repo's own opinionated `HooksERC*` (which deploys its token
directly via `new` — see "Architecture" below); the templates instead solve
the hooks-needs-the-token's-address-but-deployment-order-is-ambiguous problem
with a plain one-time `owner`-gated `initialize(token)` call, since the base
interfaces don't mandate any particular deployment story.

**Status:** this is a draft proposal living alongside the framework for
illustration and feedback, not yet an EIP and not yet wired into
`IntegrityERC20`/`721`/`1155`'s actual pipeline — those still use the
framework-specific `contracts/interfaces/IHooks.sol` (which additionally
carries hook-mint plumbing that's out of scope for a minimal standard).
Treat `contracts/standard/` as a concrete starting point for an EIP
write-up, not as production code.

## What's implemented

| Concern | ERC-20 | ERC-721 | ERC-1155 |
|---|---|---|---|
| Hooks-deploys-its-own-token, zero-immutable token bytecode | ✅ | ✅ | ✅ |
| Locked transfer/mint/burn pipeline | ✅ | ✅ | ✅ |
| Hooks base + before/after/validate | ✅ | ✅ | ✅ |
| On-chain flags / `verifyToken` | — (N/A, fungible) | ✅ | ✅ |
| Pause / issuer admin transfer | ✅ | ✅ | ✅ |
| ERC-2981 royalty info | — | ✅ | not yet |
| Example hooks contracts (`contracts/test/`) | ✅ | ✅ | ✅ |

Also present: a shared `Errors.sol` (custom errors, no revert strings on
the hot paths), a `Types.sol` (`TokenStandard` enum), a `Codehash.sol`
library (see below), and `IHooks.sol` interfaces (`IHookMintERC20/721/1155`)
that let external tooling drive hook-initiated minting without knowing the
concrete standard ahead of time.

## Verifying a deployment

Anyone — a buyer, a marketplace, another contract — can independently
confirm that a given token address is running the real, unmodified
`IntegrityERC20`/`721`/`1155` implementation and not a maliciously patched
fork, with a single on-chain check and no off-chain lookup or trusted third
party required. `contracts/libraries/Codehash.sol`:

```solidity
library Codehash {
    function isCanonical(address target, bytes32 expectedCodeHash) internal view returns (bool) {
        return target.codehash == expectedCodeHash;
    }
}
```

Safe to call against a token (or anything else) you don't yet trust: the
check never calls into `target` — EXTCODEHASH is read directly by the EVM
from the target's actual deployed bytecode, so a malicious contract can't
misreport it the way it could if you called an `isCanonical()`-style
function defined on the contract you're trying to verify (that contract
could simply hardcode such a function to return true). This is also why
`Codehash` is an `internal` library function rather than something deployed
once and called into: it compiles directly into whatever contract uses it,
so there's no deployed address of its own to trust in the first place —
import it directly into a marketplace contract, an indexer, or any verifier.

**Why this works cleanly for tokens specifically, without a factory to
anchor trust in:** `IntegrityERC20`/`721`/`1155` hold zero `immutable`
state. The hooks address that governs each token is a plain (non-immutable,
non-constant) storage slot, set exactly once in the constructor from
`msg.sender` (the deploying contract — unspoofable, since a hooks
contract's own constructor is what calls `new` on the token), with no
setter anywhere in the token's source. EXTCODEHASH never includes storage,
only code, so this keeps every canonical deployment of a given token
contract version byte-identical forever, regardless of which hooks contract
deployed it or what address that hooks contract has. One published hash per
token contract version verifies every deployment of it, by anyone,
anywhere — `test/Codehash.t.sol` demonstrates this directly: two tokens
deployed by two independently-configured hooks contracts produce identical
`codehash`.

Hooks contracts are the opposite by design, and deliberately not covered by
a single hash: they carry real, per-developer custom logic (that's the
entire point of a hooks contract) and typically their own immutables (e.g.
`issuerAdmin`), so there was never going to be one universal hash for "a
hooks contract" the way there is for a token. `Codehash.isCanonical` still
works against a *specific* hooks implementation if its author publishes a
hash for it — that's just a narrower claim ("this address runs exactly the
code its author published for this hooks contract") than the ecosystem-wide
one a token's hash gives you.

### Required compiler settings

Runtime bytecode is only comparable across independent compilations if the
build is reproducible. Solidity appends a CBOR-encoded metadata hash to the
end of runtime bytecode by default (derived from things like absolute file
paths on the machine that compiled it) — two people compiling identical
source with default settings get *different* code hashes purely from that
trailer, with no logic difference at all. To get a hash that's actually
comparable across machines:

- Pin the exact compiler version you're comparing against — e.g. `0.8.34`,
  not a floating `^0.8.34` build that could resolve to a different patch.
- Pin the optimizer settings (enabled/disabled, `runs`), `evmVersion`, and
  `viaIR`, and publish them alongside any hash you cite — they change the
  bytecode. This repo's canonical settings live in `foundry.toml`: solc
  `0.8.34`, optimizer on with `200` runs, `evmVersion = "cancun"`, and
  `viaIR = true` (required — `IntegrityERC1155.mintBatch` has enough local
  variables to hit solc's "stack too deep" limit without it).
- Set `settings.metadata.bytecodeHash = "none"`. In Foundry:
  `bytecode_hash = "none"` under `[profile.default]` in `foundry.toml`. In
  Hardhat: `metadata: { bytecodeHash: "none" }` under the compiler
  settings. This drops the non-reproducible metadata trailer entirely.

No hash is published in this repo yet — there is no maintained list to
consult. Whoever cuts a release computes it themselves from the pinned
settings above (e.g. `forge inspect IntegrityERC721 deployedBytecode | keccak256`,
or deploy a token locally and read its `.codehash`) and publishes it
alongside that release's tag, one hash per token contract (ERC-20/721/1155
each need their own). The hash travels with the source, not with a person.

## Development

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

```sh
forge install          # fetch OpenZeppelin Contracts + forge-std into lib/
forge build             # compile (via-ir is required — see above)
forge test               # run the test suite
forge fmt --check    # verify formatting matches CI
```

CI (`.github/workflows/ci.yml`) runs `forge build`, `forge test`,
`forge fmt --check`, and a Slither static-analysis pass on every push and
pull request.

## What's not there yet

Packaging for consumption by other projects (a documented `forge install`
flow for integrators, versioned releases with published bytecode hashes),
integrator docs beyond this README, a security disclosure policy, and a
professional audit — this repo is still **pre-audit** (see the status note
above). See the project's working notes for the current priority order.

## License

MIT (per-file SPDX headers already in place); a root `LICENSE` file is
still needed.