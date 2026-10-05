# Ready to submit

Category: **Builder → Intelligent Contracts**

Title: **RuleKnot: Consensus policy feasibility and minimum conflict cores**

## Notes / Description (983 characters)

> RuleKnot is a bounded GenLayer policy-feasibility primitive. A deployment fixes Boolean feature meanings and a publisher repository. Anyone submits a commit-pinned prose policy and SHA-256; leader and validators independently fetch full texts and evaluate every clause against every configuration. Validators require exact ALLOW/DENY/UNKNOWN agreement and separately verify source anchors and interpretations. Agreed tables drive exhaustive feasibility checking, a minimum-cardinality conflict core, and removal witnesses. UNKNOWN yields possible configurations without proving feasibility. Append-only results distinguish READY, CONFLICT and REVIEW. Five finalized StudioNet receipts show READY, CONFLICT, REVIEW and a rejected exception stress case with unchanged state. The repo includes a pinned GenVM contract, 19 direct tests, exhaustive checks of 729 tables, and receipt/state verification. Synthetic normative policies demonstrate the mechanism, not actual release execution.

## Evidence links

- [Repository](https://github.com/mahdidaawsh-commits/rule-knot)
- [GenLayer contract source](https://github.com/mahdidaawsh-commits/rule-knot/blob/main/contracts/rule_knot.py)
- [Onchain proofs and full receipts](https://github.com/mahdidaawsh-commits/rule-knot/blob/main/proofs/README.md)
- [Deployment transaction](https://explorer-studio.genlayer.com/tx/0x7e2843a94d010d7336609c8db6841c0504cefaa169910b0ed67fc51b513fb98f)

StudioNet contract: `0x84E91785E324f8F48902dD1043622C65d861aC26`. The exception stress evaluation was rejected; it is not counted as an accepted result. The proof page documents conservative UNKNOWN judgments and the initial workflow's stop/recovery.
