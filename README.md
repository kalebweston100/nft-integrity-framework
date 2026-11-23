# Integrity Token Framework

[![CI](https://github.com/kalebweston100/nft-integrity-framework/actions/workflows/ci.yml/badge.svg)](https://github.com/kalebweston100/nft-integrity-framework/actions/workflows/ci.yml)

ERC-20 / ERC-721 / ERC-1155 tokens whose transfer pipeline cannot be changed
by the code that customizes them. Developers add logic through a separate
**hooks contract** that the token calls with plain `CALL`, never
`DELEGATECALL`, so a hook can veto a transfer but can never touch balances,
ownership, or flags. NFTs also carry **flags**: certification bits and a
metadata hash committed once at mint, which a buyer can check with one view
call before purchase.

> **Status: pre-audit.** Implemented and covered by unit, fuzz, and invariant
> tests in CI, with Slither in the pipeline. No security review yet. Do not
> put real value on it.

## At a glance

- **Locked pipeline.** `transfer`, `mint`, `burn` are non-virtual on concrete
  token contracts. Nobody, including the issuer, can redefine what a transfer is.
- **Hooks can only restrict.** `before*` / `validate*` hooks can deny an
  action; `after*` hooks run in `try/catch`, so a buggy hook cannot brick the token.
- **Immutable NFT flags.** `defineFlag(bit, label)` is append-only; flags and
  metadata hash are written once at mint and never again.
  `verifyToken(id, requiredFlags, expectedMetadataHash)` checks both.
- **One deployment, no factory.** A hooks contract's constructor deploys its
  own token with `new`. No registry, no initializer, no window where the two
  exist unwired.
- **One codehash per token version.** Tokens hold no `immutable` state, so
  every deployment of a token version has identical runtime bytecode and can
  be checked against one published hash. See [what that does and does not
  prove](#threat-model-and-limits).

## Why

The usual ways to make a token extensible (Diamond facets, Safe-style modules)
run extension code via `delegatecall` inside the host's storage. A buggy or
malicious module does not just say yes or no; it can write anything. This
framework makes non-authority a property of the calling convention: the token
owns all state and calls hooks externally at fixed points.

Prior art gets partway there. ERC-1404 puts restriction logic inside the token
itself, with nothing stopping that function from also mutating balances.
ERC-3643 compliance modules are closer but usually route through one trusted
`Compliance` contract and do not pin down `CALL`-only invocation or ERC-165
discovery of conformance.

## Architecture

```
Hooks contract (developer-deployed, inherits HooksERC20 / 721 / 1155)
   │  issuerAdmin, custom before / validate / after logic
   │
   │  `new IntegrityERC*(...)` inside the hooks constructor
   ▼
Token (IntegrityERC20 / IntegrityERC721 / IntegrityERC1155)
   │  owns all balances, ownership, flags; pipeline is non-virtual
   │  stores its hooks address (msg.sender at construction) in a
   │  setter-less storage slot, not an immutable, so bytecode is identical
   │  across deployments
   │
   └─► external CALL at fixed points:
         pause → before → validate → state change → after (try/catch)
```

Each hooks base implements a small ERC-165-discoverable interface
(`IHooksERC20` / `IHooksERC721` / `IHooksERC1155`), so a marketplace or indexer
can confirm a hooks address follows this calling convention without reading
source. The one write path a hook has is deliberate and narrow:
`hookMint` / `hookSetTokenURI`, callable only by the token's own hooks contract.

## Threat model and limits

What the design guarantees, assuming the token was deployed by its canonical
constructor:

- Hooks cannot move, create, or destroy balances except through `hookMint`.
- No one can change an NFT's flags or metadata hash after mint.
- Token logic is the published logic: `Codehash.isCanonical(token, hash)`
  compares `EXTCODEHASH` directly and never calls into the target.

What it does **not** guarantee:

- **A canonical codehash does not mean canonical state.** `EXTCODEHASH`
  covers runtime code only, not storage and not the initcode that produced it.
  Anyone can deploy initcode that writes arbitrary storage (a phantom balance,
  an attacker-chosen admin, a fake `hooksContract()`) and then installs the
  canonical runtime bytecode verbatim. The result passes `isCanonical`.
  [`test/PoisonedConstructor.t.sol`](test/PoisonedConstructor.t.sol)
  demonstrates this end to end. Today the only way to rule it out is off-chain:
  inspect the deployment transaction and confirm the token was created by
  its hooks contract with the canonical initcode. A fix that can be checked
  on-chain needs the token's address to commit to its initcode (CREATE2 from
  the hooks contract), which is the mechanism
  [create2-receipts](https://github.com/kalebweston100/create2-receipts) is
  built on. That is a planned redesign, not shipped.
- **The issuer is trusted.** The issuer admin can pause transfers, burn any
  holder's tokens, change token URIs, and set royalties.
- **The hooks contract is trusted.** It runs arbitrary developer code. A
  malicious one can let the issuer sell while blocking every resale. Read the
  hooks contract at `token.hooksContract()` before buying.

Flags and metadata commitments made at mint stay trustworthy against the
issuer and the hooks contract either way. Against a poisoned deployment,
nothing about the token's state is trustworthy.

## Verifying a deployment

```solidity
library Codehash {
    function isCanonical(address target, bytes32 expectedCodeHash) internal view returns (bool) {
        return target.codehash == expectedCodeHash;
    }
}
```

`Codehash` is an `internal` library so it compiles into the verifier; there is
no deployed checker to trust. [`test/Codehash.t.sol`](test/Codehash.t.sol)
shows two tokens deployed by independently configured hooks contracts having
identical codehashes.

Hashes are only comparable across machines with a reproducible build. This
repo's settings (in `foundry.toml`) are: solc `0.8.34` pinned, optimizer on
with 200 runs, `evm_version = "cancun"`, `via_ir = true` (needed for
`IntegrityERC1155.mintBatch`), and `bytecode_hash = "none"` /
`cbor_metadata = false` to drop the path-dependent metadata trailer. A release
publishes one hash per token contract alongside its tag; none has been cut yet.

## What's implemented

| | ERC-20 | ERC-721 | ERC-1155 |
|---|---|---|---|
| Locked transfer / mint / burn pipeline | ✅ | ✅ | ✅ |
| Hooks base: before / validate / after | ✅ | ✅ | ✅ |
| `IHooksERC*` + ERC-165 discovery | ✅ | ✅ | ✅ |
| Identical bytecode across deployments | ✅ | ✅ | ✅ |
| Flags + `verifyToken` | n/a | ✅ | ✅ |
| Pause, issuer admin transfer | ✅ | ✅ | ✅ |
| ERC-2981 royalties | n/a | ✅ | ✅ |
| Holder tracking | ✅ `holderCount`, `firstReceivedAt` | ✅ `holderCount` | ✅ per id |

## Tests

`forge test` runs unit tests in `test/` and stateful invariant suites in
`test/invariant/` for all three standards. Handlers drive random sequences of
mints, hook-mints, transfers (including zero-value and self-transfers), burns,
and re-mint attempts. After every step the suites check that:

- holder counts (per id for ERC-1155) equal the number of addresses with a
  non-zero balance,
- the sum of balances equals `totalSupply` equals minted minus burned,
- committed NFT flags and metadata hashes never change,
- a burned ERC-721 id can never be minted again.

CI runs `forge build`, `forge test`, `forge fmt --check`, and Slither on every
push and pull request.

## Development

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

```sh
git clone --recurse-submodules https://github.com/kalebweston100/nft-integrity-framework
forge build
forge test
forge fmt --check
```

## Layout

```
contracts/
  token/       IntegrityERC20 / 721 / 1155, shared base, TokenAdmin
  hooks/       HooksERC20 / 721 / 1155 abstract bases
  interfaces/  IHooksERC*, IIntegrityToken, errors, types
  libraries/   Codehash
  test/        example hooks used by the test suite
test/          unit tests, invariant suites, codehash + poisoned-constructor tests
```

## Related work

- [create2-receipts](https://github.com/kalebweston100/create2-receipts):
  on-chain facts recorded as CREATE2 addresses. Provides the
  initcode commitment this framework needs to close the poisoned-constructor gap.
- [proven-source](https://github.com/kalebweston100/proven-source): proving
  on-chain that deployed bytecode matches a Solidity source, without trusting
  a compiler.

## Not yet done

Security review, a versioned release with published codehashes, and the
CREATE2-based deployment described above.

## License

[MIT](LICENSE)
