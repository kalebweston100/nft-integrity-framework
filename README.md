# Integrity Token Framework

A Solidity framework for deploying ERC-20 / ERC-721 / ERC-1155 tokens with a
locked, non-bypassable transfer pipeline, a permissionless factory, and an
optional external "hooks" contract that lets a developer bolt on custom
logic without ever gaining the ability to override core guarantees.

NFTs (ERC-721 / ERC-1155) additionally carry an on-chain **flags** system:
an append-only registry of trait/certification labels, committed to each
token exactly once at mint, that a buyer can verify trustlessly before
purchase — no reliance on marketplace metadata or seller claims.

> **Status: early / pre-audit.** The contracts below are implemented and
> internally consistent, but there is no test suite, no CI, and no security
> review yet. Do not deploy real value on top of this until that changes.

## Distribution model

This project is a source library, like OpenZeppelin Contracts — not a
hosted service. There is no canonical factory deployment maintained by
anyone, no admin key held by the framework's authors, and no on-chain
registry of "trusted" factories to keep up. Each developer compiles the
contracts and deploys their **own** `FactoryERC20` / `FactoryERC721` /
`FactoryERC1155` instance, and owns that instance outright (its `owner`,
its fee, its withdrawals). What travels with a release is the source and
its canonical bytecode hash, so anyone can independently confirm a given
deployment is genuine — see "Verifying a deployment" below.

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
Factory (permissionless deploy, fee collection)
   │
   │ deploys via `new`
   ▼
Token (IntegrityERC20 / IntegrityERC721 / IntegrityERC1155)
   │  - owns all balance/ownership/flags storage
   │  - transfer/mint/burn entry points are non-virtual (locked)
   │  - factory address and hooks address are immutable
   │
   │ external call, at fixed points in the pipeline
   ▼
Hooks (developer-deployed, inherits HooksERC20/721/1155)
   - beforeX / validateX  → can block (require true / non-empty reason)
   - afterX               → wrapped in try/catch by the token; a hook bug
                             can't brick the token
```

**Chain of trust:** `factory.deployedByFactory(token)` →
`token.factory() == factory` → `token.hooksContract() == hooksAddr` →
`hooks.factory() == factory` && `hooks.tokenContract() == token`. Any
contract (a marketplace, an indexer) can call `factory.verifyChainOfTrust(token)`
and get a single boolean instead of re-deriving this by hand.

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
- **Pull-model royalties (opt-in via `HooksERC*` instead of `HooksERC*Base`).**
  An accumulator-per-unit design (`RoyaltyBase`) settles each holder's
  earned share into `pendingRoyalties` at transfer/mint/burn time; holders
  call `claimRoyalties()` themselves. ERC-721 counts 1 unit/token; ERC-1155
  runs a separate accumulator per `tokenId` (optional — enabled per-deployment
  via the hooks constructor); ERC-20 weights by balance.
- **Permissionless, fee-gated deployment.** Anyone can call
  `factory.deployToken*()` on a given factory instance and become the
  issuer admin of their own token; that factory instance's own deployer
  (its `owner`) can set a per-deploy ETH fee (0 by default) and withdraw
  fees accumulated by *their* factory. Nothing here is shared across
  developers — see "Distribution model" above.
- **Optional `HooksFactory` convenience base.** A developer building a
  product on top of this framework (e.g. "mint NFTs on deposit") often wants
  their own contract to deploy the hooks contract *and* call the token
  factory in one transaction, then take a platform-level fee on top of the
  framework's own deploy fee. `contracts/hooks/HooksFactory.sol` is an
  abstract base for exactly that: two-step ownership, a platform fee
  accumulator, and `_deployERC20Pair`/`_deployERC721Pair`/`_deployERC1155Pair`
  helpers that forward the underlying token factory's deploy fee
  automatically. It's purely additive — nothing in the core framework
  depends on it, and skipping it changes nothing about the chain-of-trust
  guarantees above.

## What's implemented

| Concern | ERC-20 | ERC-721 | ERC-1155 |
|---|---|---|---|
| Factory + chain-of-trust | ✅ | ✅ | ✅ |
| Locked transfer/mint/burn pipeline | ✅ | ✅ | ✅ |
| Hooks base + before/after/validate | ✅ | ✅ | ✅ |
| Pull-model royalty accumulator | ✅ | ✅ | ✅ |
| On-chain flags / `verifyToken` | — (N/A, fungible) | ✅ | ✅ |
| Pause / issuer admin transfer | ✅ | ✅ | ✅ |
| ERC-2981 royalty info | — | ✅ | not yet |
| Example hooks contracts (`contracts/test/`) | ✅ | ✅ | ✅ |

Also present: a shared `Errors.sol` (custom errors, no revert strings on
the hot paths), a `Types.sol` (`TokenStandard` enum), and `IHooks.sol` /
`ITokenFactory.sol` interfaces that let external tooling detect and drive
any framework token without knowing the concrete standard ahead of time.

## Verifying a deployment

Because every developer deploys their own factory from the same source,
anyone — a buyer, a marketplace, another contract — can independently
confirm a given factory address is running the real, unmodified
implementation and not a maliciously patched fork. `FactoryBase` exposes
this on-chain, no off-chain lookup or trusted third party required:

- **`isCanonicalCodeHash(address target, bytes32 expectedCodeHash)`** —
  compares `target.codehash` (EXTCODEHASH, read directly by the EVM)
  against a hash you supply. Safe to call against a factory you don't yet
  trust: the check never calls into `target`, so a malicious contract can't
  misreport its own bytecode hash the way it could if you called an
  `isCanonical()`-style function defined on the contract you're trying to
  verify.
- **`runtimeCodeHash()`** — convenience getter for a factory's own hash.
  Only meaningful as a self-report from a factory you already trust; it is
  *not* how you should establish that trust in the first place.

This works because `FactoryBase` and its concrete subclasses
(`FactoryERC20`/`721`/`1155`) hold no `immutable` state — every canonical
deployment produces byte-identical runtime bytecode regardless of who
deploys it or what `owner` ends up being. (Deployed *tokens* do embed
`immutable`s — factory address, hooks address — so their bytecode
legitimately differs per deployment. That's fine: a token only ever comes
into existence via `new` from inside the factory's own bytecode, so a
verified-canonical factory transitively guarantees every token it deployed
is running the canonical token implementation too. Tokens don't need to be
verified separately.)

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
settings above (e.g. `forge inspect FactoryERC721 deployedBytecode | keccak256`,
or deploy locally and call `runtimeCodeHash()`) and publishes it alongside
that release's tag. The hash travels with the source, not with a person.

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