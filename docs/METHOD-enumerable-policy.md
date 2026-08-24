# The method, and where it belongs next

> **STATUS: DIRECTION DOCUMENT. NO CODE.**
> This is not a description of `contracts/`. It states the general method the
> token system is one instance of, the conditions under which it works, and the
> case for a second instance in ERC-4337 account validation.

---

## 0. Why this document exists

The repository currently reads as *a token framework that uses a clever
technique*. The technique is the valuable part, and it is more general than the
instance it is trapped in.

> **One instance is a design. Two instances sharing an abstraction is a method.**

That distinction is the whole reason to write this down. A framework is judged
on adoption. A method is judged on whether it is *correct and applicable*, which
is a bar reachable without users — and it is the bar this project is actually
aiming at.

---

## 1. The method, stated generally

> Replace an arbitrary predicate with a **finite, enumerable vocabulary**
> evaluated by a contract whose **bytecode is fixed and published**, so that a
> **negative claim** about the system becomes checkable.

Three moving parts, each doing distinct work:

**Reify the predicate.** Move the decision from code (intensional) to data drawn
from a fixed grammar (extensional). Standard PL practice — restrict the language
to make properties decidable. This alone gives you readability.

**Content-address the evaluator.** The data means nothing unless the thing
interpreting it is pinned. A codehash pins it, which **relocates the question
from runtime to compile time**. This alone gives you nothing readable — you can
verify arbitrary code and still not know what it does.

**Neither half works without the other.** Readable-but-unpinned is a suggestion;
pinned-but-arbitrary is Etherscan. Together they let you assert an absence.

### 1.1 What it actually buys

Not "the rules are trustworthy." Rules are just data; anyone can publish data.

> It buys **exhaustiveness**: no condition exists outside the list.

Exhaustiveness is what converts a list of conditions into a specification. And
exhaustiveness is a negative claim, which is precisely the kind that cannot
otherwise be established — see §3.

---

## 2. Preconditions — the checklist

The method applies to a domain if and only if all five hold. This checklist is
the most portable output of the project.

| # | Precondition | Fails when |
|---|---|---|
| **P1** | The decision surface is **narrow** — a finite set of questions with finite answers | Requirements need an expression language |
| **P2** | The entry point's **bytecode can be known** | Anyone may deploy their own implementation and still expect the claim |
| **P3** | Composition is **predicate-like** — AND of independent conditions, not sequential state transitions | Meaning depends on order or intermediate state |
| **P4** | The **negative claim is what matters** — "nothing else can X" is the valuable statement | Users only care about the positive path |
| **P5** | Configuration varies while **code stays fixed** | Each deployment needs distinct logic |

**P2 is the expensive one**, and it is the one that determines whether a domain
is a good or a mediocre fit. It cannot be engineered away (§3.2). It can only be
*free* — that is, a domain where the entry point was already going to come from
a short list.

**P3 is the one that gets violated by ambition.** See §5.2.

---

## 3. The impossibility results

These bound the method. Each has a worked demonstration in this repository, and
together they are the most original output of the work so far.

### 3.1 Consultation is provable; exclusivity is not

> You can prove an action **went through** the policy.
> You can never prove it went **only** through the policy.

Consultation is a positive, observable fact. "Nothing else blocked it" quantifies
over all paths in arbitrary code. The evaluator returning `true` followed by the
caller reverting for its own reasons is, from the evaluator's side,
indistinguishable from success.

### 3.2 Therefore exhaustiveness and universality are contradictory

Not merely hard — contradictory. Whatever address receives the transaction
decides whether it reverts, so a claim about what *cannot* happen requires that
address to run known code. **"Only these rules apply" and "works with anything"
cannot both hold.** Every attempt to escape this in eight sessions has been the
same theorem in a new costume.

### 3.3 Self-verification is impossible

> A check performed by a contract that the untrusted party controls the call to
> is defeated by omitting the call.

Corollaries: an `isCanonical()` getter is self-report; a contract hashing its own
code hits a fixed-point problem, and storing the expected hash at construction
lands in the unhashed constructor; an evaluator checking `msg.sender.codehash`
is bypassed by not calling the evaluator.

This is also why the **flash-loan pattern does not port.** A flash loan works
because the lender owns the outer call frame *and* its invariant is over its own
balance. A policy evaluator is a callee, and its invariant is over someone
else's state. Both would have to change, and changing either requires trusted
code.

### 3.4 A codehash carries future behaviour, never history

Init code and runtime code are independent byte strings, so an impostor can
fabricate arbitrary storage and return canonical runtime bytes copied off a real
deployment. It passes every codehash check.

This is not a hole *if every claim made is future-tense*. It becomes one the
moment a claim about history is asserted ("these were the launch rules", "supply
was only ever minted by the admin"), and closing it requires CREATE2 provenance —
the address, not the code, is what commits to a constructor.

### 3.5 AND-composition preserves comprehension; sequencing destroys it

> A conjunction of predicates is comprehensible because each element
> independently implies the conclusion. A sequence of state transitions is not,
> because meaning depends on order and intermediate state.

Enumerability was never "can I list the elements." It is "can I understand the
whole from the parts." This is why a stored *program* — an interpreter reading
operations from storage — returns you to the original problem with extra steps,
regardless of how finite its instruction set is.

---

## 4. Instance 1: token transfer policy

Built, shipped, 142 tests. Scored against the checklist:

| | | |
|---|---|---|
| **P1** narrow surface | ✅ | 10 rule kinds × 5 actions |
| **P2** knowable entry point | ⚠️ | **Only via a closed set of tokens — the design's largest cost** |
| **P3** predicate composition | ✅ | Flat AND, no nesting |
| **P4** negative claim matters | ⚠️ | *Nice to have.* Most tokens are unrestricted anyway |
| **P5** fixed code, varying config | ✅ | Identical codehashes across all policies |

**Two amber marks, and they compound.** The closed set is expensive *and* the
claim it buys is not urgent for most of the domain — transfer restrictions
annoy people rather than costing them funds. A perfect solution to a
low-urgency problem has bounded importance regardless of execution quality.

That is the honest ceiling, and it is not an execution problem. It is why
further refinement of this instance will not raise its standing.

**What it nonetheless proved:** the mechanism works. Two engines holding
completely different policies have identical codehashes. `allowedKinds` shows
the vocabulary can carry a bound on *future* configuration, not just current.
The unconditional case shows a proven absence is expressible. All of that is
transferable.

---

## 5. Instance 2: ERC-4337 account validation

The proposed second instance, and the one that would convert the design into a
method.

### 5.1 The question, and why it is currently unanswerable

> **What can authorize a transaction from my account?**

Today: arbitrary Solidity in `validateUserOp`, plus arbitrary Solidity in every
installed validator module. The honest answer is that nobody knows — including,
usually, the account's owner.

This is structurally the same question as *"what can block my transfer"*, with
the polarity inverted: the token policy enumerates conditions that **deny**, and
a validation policy enumerates conditions under which something may be
**authorized**.

### 5.2 Why it scores better on the checklist

| | | |
|---|---|---|
| **P1** narrow surface | ✅ | Signer, target, selector, value, time window, spend limit |
| **P2** knowable entry point | ✅ | **Free — see below** |
| **P3** predicate composition | ✅ | Authorization is naturally a conjunction |
| **P4** negative claim matters | ✅ | **Unauthorized authorization = stolen funds** |
| **P5** fixed code, varying config | ✅ | Every user needs different permissions, identical logic |

**P2 is free, and this is the crux.** Smart accounts are *already* chosen from a
short list — Safe, Kernel, LightAccount, Biconomy. Wallet software already
hardcodes which implementations it supports. A canonical set is not an adoption
penalty in this domain; **it is the status quo.** The single largest cost of the
token design simply does not appear.

**Provenance is also already free.** ERC-4337 accounts are deployed by a factory
via CREATE2, with the factory and its calldata carried in the UserOperation's
`initCode`. The address already commits to the init code. The
address-as-commitment design that would cost the token system a new anchor and a
new contract is **the native deployment pattern here**, already in production.

**P4 is the difference that matters most.** For tokens the negative claim is a
nice-to-have — unexpected blocking is an inconvenience. For accounts it is the
whole ballgame: "nothing outside this list can move my funds" is the security
property, and it is exactly the shape the method delivers. The method's core
strength lines up with the domain's core need.

### 5.3 Sketch

```solidity
enum AccountAction {
    Validate,       // authorize a UserOperation
    Execute,        // the call the operation performs
    InstallModule,  // change what can validate in future
    ChangeOwner
}

struct ValidationContext {
    AccountAction action;
    address account;
    address signer;        // recovered from the signature
    address target;        // what the operation calls
    bytes4  selector;
    uint256 value;
    uint256 spentThisPeriod;
    uint64  validUntil;
}

enum PermissionKind {
    SignerIs,          // ref: an authorized key
    SessionUntil,      // ref + value: a key with an expiry
    TargetAllowlist,   // ref: registry of permitted targets
    SelectorAllowlist, // ref: registry of permitted selectors
    MaxValuePerOp,     // value
    MaxValuePerPeriod, // value + period
    RequiresGuardians, // value: m-of-n threshold
    NoDelegateCall,    // structural
    ExternalGate       // the escape hatch, same as today
}
```

`InstallModule` as a first-class action is the sharp one. *"What can change what
is able to validate in future?"* is the account-abstraction analogue of the
upgrade question, and making it an enumerable, timelocked row of the policy is a
genuinely strong claim nobody currently offers.

**Two routes, mirroring the tiering already understood here:**

- **Canonical validator module (ERC-7579).** Slots into existing modular
  accounts; only the module needs to be in the closed set. Cheap to adopt, but
  the claim requires the account to expose its installed validators *and* for
  all of them to be canonical, since any other installed validator could
  authorize independently.
- **Canonical account.** Stronger claim, higher bar, and the bar is one this
  domain already clears.

Start with the module. It is a real artifact, it works inside deployed
infrastructure, and it makes the account route obvious rather than speculative.

### 5.4 What ports unchanged

`PolicyEngine`'s structure, `CanonicalCode`, the timelock and proposal flow, the
`allowedKinds` permanent-envelope idea, `externalRefs`, the report/verification
shape, and the whole "fix the code, vary the storage" mechanism. The genuinely
new work is the vocabulary and the context struct.

**One thing does not port:** the unconditional headline inverts. An empty policy
on a token means maximal freedom; an empty policy on an account means nothing
can authorize anything — a bricked wallet. The interesting case here is a
*minimal* policy, not an empty one.

> ⚠️ The 7579/6900 module interfaces and 4337 v0.7 signatures above are from
> memory and must be checked against current specs before any code is written.

---

## 6. Other domains, assessed against the checklist

| Domain | P1 | P2 | P3 | P4 | Verdict |
|---|:--:|:--:|:--:|:--:|---|
| Token transfers | ✅ | ⚠️ | ✅ | ⚠️ | Works; bounded importance |
| **ERC-4337 validation** | ✅ | ✅ | ✅ | ✅ | **Strong fit** |
| Governance / DAO powers | ⚠️ | ❌ | ⚠️ | ✅ | Weak — every DAO is bespoke |
| Vault / strategy permissions | ⚠️ | ⚠️ | ❌ | ✅ | Poor — strategies are sequential |
| Upgradeability in general | ❌ | ❌ | ❌ | ✅ | No — "what can change" is unbounded |
| "Any action on any contract" | ❌ | ❌ | ❌ | — | The trap. Already argued down twice |

The pattern: the method wants a domain where the decision surface was *already*
narrow and the implementation set was *already* short. It cannot manufacture
either.

---

## 7. Ordering

1. **Finish instance 1.** The off-chain reader above all — nothing currently
   consumes `rules()`, so the property the whole design exists to provide is
   observed by nobody. Then the parameterized hash set (§8 of `DESIGN-NOTES`),
   so the canonical set stops meaning "contracts in this repo."
2. **Write up §3 separately.** The five impossibility results with their
   demonstrations, as a standalone piece on *what can and cannot be enumerated
   about a contract*. Days of work, highest theory-per-hour available, and it
   stands independently of whether anyone ever uses the contracts.
3. **Build instance 2.** This is the step that converts a design into a method.

Steps 1 and 2 are what make step 3 legible rather than a fresh start.

---

## 8. Open problems

**Who curates a canonical set?** Unsolved and social, not technical. A hash list
needs a maintainer; a registry contract needs governance; a wallet needs a
reason to care. This is the only remaining wall in front of instance 1, and it
is in front of instance 2 as well — though lower there, since account
implementations are already curated by wallet vendors as a matter of course.

**Can conformance be mechanised?** The closed set exists because "every revert is
either standard-conformance or the policy verdict" is checked by a human. A
bytecode analysis proving that property — or a zk proof of it — would replace
curation with computation and make the set open. That is a research project, not
a next commit, but it is the only known route around §3.2 and worth naming as
the theoretical ceiling of the whole line of work.

**Is the vocabulary right?** Ten rule kinds chosen without contact with a real
issuer. A standard's vocabulary is the part that must survive real use, and this
one has not been tested against any. The same risk applies double to instance 2,
where the permission vocabulary would be guarding funds.
