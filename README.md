# RuleKnot

A standalone GenLayer primitive for finding feasible configurations and explaining inconsistent prose policies with a minimum-cardinality conflict core.

## Mechanism

A deployment fixes a publisher repository and up to four Boolean feature meanings. Anyone can submit a commit-pinned policy record with a SHA-256 commitment. The contract fetches the bytes itself; callers supply neither truth tables nor decisions. Each named clause is evaluated independently against every configuration. GenLayer validators fetch the complete record again, check its hash, construct their own table, require exact cell agreement, and separately verify the supporting quotes and interpretations.

The accepted semantic table drives finite enumeration:

| Result | Condition | Consequence |
|---|---|---|
| READY | At least one configuration is ALLOW under every clause | Store a canonical feasible witness |
| CONFLICT | Every configuration is DENY under at least one clause | Store a smallest conflicting subset and removal witnesses |
| REVIEW | Some configurations avoid DENY, but none are all ALLOW | Store possible configurations without claiming feasibility |

UNKNOWN never establishes feasibility and never excludes a configuration by itself. Witnesses prefer fewer enabled features, then the lower integer mask. Core selection prefers smaller cardinality, then source order. A removal witness avoids DENY in the **remaining core**, not necessarily in all original clauses. Its `certain` flag records whether every remaining-core verdict is ALLOW.

## Example

The synthetic conflict record requires human sign-off, prohibits sign-off on expedited releases, and requires expediting. Together these three clauses reject every configuration. A fourth offline-recovery clause is irrelevant to that conflict and is excluded from the core. Removing each core member leaves a concrete satisfying assignment for the others.

This architecture uses semantic constraint tables and finite contradiction explanation. It has no graph proposals, owner overrides, certificates, one-time consumption, payment settlement, auctions, ranking or measurement aggregation. The finite solver is deterministic; consequential GenLayer nondeterminism is the source-derived table consumed by that solver.

## Repository

- [Contract](contracts/rule_knot.py): pinned GenVM runner, immutable feature meanings, append-only results.
- [Consensus design](docs/consensus.md): exact validator gates and trust boundaries.
- [Policy](config/policy.json) and [records](records): reproducible synthetic scenarios.
- [Direct tests](tests/direct/test_policy.py): 19 tests, including all 729 three-clause/two-configuration tables.
- [CLI deployment](deploy/00_rule_knot.js), [live proof runner](scripts/prove-scenarios.cjs), and [proof verifier](scripts/verify-proofs.cjs).
- [Onchain proofs](proofs/README.md).

## Local checks

```sh
python -m pip install -r requirements.txt
genvm-lint download --version v0.2.16
genvm-lint check contracts/rule_knot.py --json
pytest tests/direct -q
node scripts/verify-proofs.cjs
```

The proof workflow creates an ephemeral CLI account and deploys to gasless StudioNet (chain 61999). It submits four records, waits for successful finalized consensus receipts, reads each stored result, and compares deployed source with local bytes. Signing material is excluded from artifacts. Receipt retries are read-only; submitted hashes are journaled to prevent blind resubmission.

## Boundaries

The publisher supplies normative policy text; fetching proves byte binding, not the authority or correctness of the policy. Features model stated Boolean conditions rather than actual deployment events. Only valid `## clause-id` sections are enforceable clauses; preamble text is contextual data. Clauses are interpreted independently. Undefined external facts yield UNKNOWN. This is bounded policy feasibility, not proof of release execution, legal clearance, safety or universal satisfiability.

Limits: 1–4 features, 1–4 clauses, 16 configurations, 8,000 source bytes, and eight batches per deployment. Permissionless callers can exhaust the batch cap using distinct valid publisher records. A new instance is then required. Failed evaluations do not append a result. Semantic consensus can reject a run or agree on a mistaken interpretation; tests and fixtures do not remove that risk.

The CLI account/receipt scaffolding is reused from MutualSlot; RuleKnot's contract mechanism, source fixtures, semantic matrices, solver tests and proof verifier are purpose-built. MIT licensed.
