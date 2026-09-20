# Least privilege, proven

RBAC defined in Terraform, and then **actually tested**: each identity signs in and attempts the things it should not be able to do, and the pipeline fails if any of them succeed.

Granting a role is easy. Knowing what that role permits is not, and the gap between the two is where incidents come from. A role assignment tells you what Azure was *asked* to allow. This tells you what it *does* allow — which is not always the same thing, and is never the same thing after somebody edits a role in the portal.

```mermaid
flowchart TB
    matrix["access-matrix.json<br/>the policy, in review"]
    tf["Terraform<br/>roles and assignments"]

    tf --> azure[("Azure RBAC")]
    matrix --> proof

    azure --> analysis["Analysis<br/>what is assigned"]
    azure --> proof["Proof<br/>what is permitted"]

    analysis --> drift{"Declared<br/>in code?"}
    analysis --> esc{"Can it grant<br/>itself more?"}
    proof --> match{"Matches<br/>the policy?"}

    drift -->|no| fail["Fail the run"]
    esc -->|yes| fail
    match -->|no| fail
```

## The distinction this lab is built on

Reading role assignments is **analysis**. Signing in and being refused is **proof**. Most RBAC tooling stops at the first, which is why a subtly over-broad custom role survives review: the assignment looks right.

Three identities exist here, each to be told no about something specific:

| Identity | Holds | Must not be able to |
|---|---|---|
| `reader` | Reader | List storage keys, write a tag, assign a role |
| `operator` | A custom *Restart Only* role | List storage keys, write a tag, assign a role |
| `deployer` | Contributor | **Assign a role** |

The last row is the one that matters. Contributor is widely treated as safe precisely because it cannot grant access — and that belief is load-bearing across a lot of estates. Here it is an assertion that runs on every proof.

## What gets checked

| Check | What it catches |
|---|---|
| **Access proof** | An identity permitted something the policy forbids. Fifteen probes, seven of them asserted denials. |
| **The other direction** | An identity refused something it needs. That failure normally gets "fixed" by widening the role, so it is reported as loudly as a hole. |
| **Drift** | A role granted in the portal that source control never declared, and a declared assignment that never landed. |
| **Escalation paths** | Any assignment carrying `roleAssignments/write` without an ABAC condition. The condition is the difference between delegation and self-promotion. |
| **Secret readers** | Anything able to reach a secret *value* rather than a secret *name*. |

## Two mistakes this tooling is built to avoid

**Flagging Contributor.** Contributor is `*` minus the authorization actions. An escalation check that tests for the *pattern* `*/write` flags it, because `NotActions` can block a concrete action but not a wildcard string. A scanner that reports Contributor on every subscription is one nobody reads, so the escalation list holds only concrete actions. Owner is still caught, because `*` matches every one of them.

**Flagging every Reader.** `Microsoft.KeyVault/vaults/secrets/read` is a management-plane action that lists secret *names*, and Reader holds it legitimately. The action that returns a secret *value* is `getSecret`. Conflating them makes every Reader a finding and buries the real ones.

Both are tested, because both are the sort of thing that gets "fixed" back in later.

## Signing in as each identity, without a credential

The proof has to authenticate as each identity under test. It creates no secret to do it.

The first attempt minted a short-lived secret per run and deleted it afterwards. That failed with `insufficient privileges`: being listed as an application **owner** does not let a service principal reset that application''s credentials, which needs `Application.ReadWrite.OwnedBy` across the directory. Taking a directory-wide grant in order to demonstrate least privilege would have been a poor trade.

So each identity under test federates to the same repository and environment as the pipeline, and the run exchanges **its own OIDC token** for each one. No credential is created, nothing needs cleaning up, and there is nothing to leave behind.

There is deliberately **no step auditing those applications for stray credentials**. The first version of that check ran `az ad app credential list` as the deploy identity, which has no Graph rights over them — the command failed and the check read the empty result as "none found", reporting clean from a query that never ran. Granting the rights to make it real would mean handing the pipeline directory permissions over three applications purely so it can audit them, which is the trade this lab argues against.

## Repository layout

```
access-matrix.json    The policy: what each identity may and may not do, and why
module/LeastPrivilege/  Escalation, drift and expectation logic. Calls no Azure.
scripts/
  Invoke-AccessProof.ps1    Signs in as each identity and attempts the probes
  Invoke-RbacAnalysis.ps1   Reads live access; reports drift, escalation, secrets
tests/                30 Pester tests, no subscription required
infra/                Custom role, assignments, a target to be refused against
bootstrap/            State, federated identity, the three identities under test
.github/workflows/    CI, Prove (manual), Destroy (manual + nightly)
```

## How to run it

**Prerequisites:** Terraform 1.9+, Azure CLI, PowerShell 7, an Azure subscription where you are Owner, directory rights to create applications, and a fork of this repository.

```powershell
Invoke-Pester ./tests    # 30 tests, no Azure needed
```

1. **Bootstrap** once, after creating the repository so its IDs exist.
2. **Configure GitHub.** An environment named `lab`, and the repository variables from the bootstrap outputs. None are secrets.
3. **Prove.** Run the **Prove** workflow. It defaults to plan-only; set `apply` to provision and run the proof.
4. **Tear down.** Run **Destroy**, or let the nightly schedule do it.

## Cost

| Resource | Rate | Lab cost |
|---|---|---|
| Entra applications, service principals | free | $0 |
| Role assignments, custom role definition | free | $0 |
| One storage account as a probe target | $0.115 per GB-month, holding nothing | fractions of a cent |

This is the cheapest lab in the series. Identity is free; the only billable thing is a storage account that exists to have `listKeys` refused against it.

## Design decisions

- **The matrix is a file, not a script.** Who may do what belongs in review. A change to `access-matrix.json` is a change to the security posture and shows up in a diff as one.
- **Every probe states a reason.** CI fails if one does not, and fails if the matrix asserts no denials, and fails if any identity is never denied anything. A policy where everyone is allowed everything would otherwise pass happily.
- **The custom role declares `not_actions` it does not need.** Its `actions` are narrow enough that `listKeys` and `roleAssignments/write` are not granted anyway. They are written down so a later edit widening the actions cannot silently pick them up.
- **Inherited assignments are excluded from drift.** They are visible at the scope but not the scope's to manage. Including them would report the subscription owner as drift on every run, which is how a drift report gets ignored.

### The lab initially failed its own test

The deploy identity held **User Access Administrator** at the lab scope with no condition, so it could assign any role — including Owner — to itself. The escalation analysis here exists to catch exactly that, and flagged it.

Exempting the pipeline from its own check would have been the easy fix, and it is the exemption that makes these tools worthless in practice. It now holds `Role Based Access Control Administrator` constrained by an ABAC condition to three named role definitions, and the analysis grades it `Info` rather than `Critical` because Azure genuinely enforces that condition.

Fixing it properly forced three further problems, each of which is the point:

- **Tightening a condition strands what predates it.** The constrained identity could no longer delete a role assignment created before the condition existed, because that assignment''s role definition was not one of the three permitted. Azure refused it correctly.
- **Constraining removes capabilities you were relying on.** `Role Based Access Control Administrator` grants `roleAssignments/write` but not `roleDefinitions/write`, so the identity could no longer create the custom role it needed to assign. The role definition moved to bootstrap, which is where a stable reviewed artifact belongs anyway.
- **The credential path had to change entirely**, as described above.

### Things that only surface against real systems

- Role assignments are not enforced the instant they are written. Probing too early reports a denial that is really a timing artefact — the worst possible result for a tool whose whole job is distinguishing allowed from denied. The pipeline waits for the assignments to appear and then waits again.
- A freshly minted service principal secret is not always usable on the first attempt, so sign-in retries rather than failing.
- PSScriptAnalyzer 1.25.0 intermittently throws a `NullReferenceException` part way through a recursive scan. It is non-terminating, so without `-ErrorAction Stop` the run continues and reports zero findings from a scan that never completed. A crashed analyzer must fail the build, not pass it.
- `az role assignment list --scope <resource-group>` fails with `MissingSubscription` in az 2.90, while `--resource-group` returns exactly the assignments at that group. `az role assignment delete --ids` has the same problem.
- Shell quoting cuts both ways, and the two rules are complementary rather than interchangeable. A JSON value containing double quotes must not be passed to a native CLI from PowerShell, which strips them. A value beginning `/subscriptions/...` must not be passed from Git Bash, which rewrites it to `C:/Program Files/Git/subscriptions/...`. Both failures are silent at the point of storage and only surface later.

**A pattern worth naming:** three separate failures here took the same shape — a check reporting success from an operation that never completed. A crashed analyzer reporting zero findings, a readiness probe declaring ready while half the permissions had not landed, and a credential audit reporting clean from a command that failed with `insufficient privileges`. A check that cannot run must fail, never pass quietly.

## Part of a series

More at [ziyaduqdah.com](https://ziyaduqdah.com/#labs).