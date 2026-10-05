# StudioNet proofs

Network: **gasless StudioNet**, chain **61999**. This is the development network, not Bradbury.

Contract address: `0x84E91785E324f8F48902dD1043622C65d861aC26`.

| Operation | Transaction | Consensus | Verified result |
|---|---|---|---|
| Deploy | [0x7e2843…](https://explorer-studio.genlayer.com/tx/0x7e2843a94d010d7336609c8db6841c0504cefaa169910b0ed67fc51b513fb98f) | MAJORITY_AGREE | Exact deployed source bytes |
| Feasible policy | [0x33e36d…](https://explorer-studio.genlayer.com/tx/0x33e36dc41c500ea1f3788f44d42f7a405276888bc6fdb191043506dde8d5fb60) | MAJORITY_AGREE | READY; masks 6 and 7; witness 6 |
| Conflict | [0x42fd95…](https://explorer-studio.genlayer.com/tx/0x42fd95b703ccca0dc0776aa2b037d5407d74df17ef1aa18f407c0419000295e1) | MAJORITY_AGREE | CONFLICT; three-member core excludes recovery clause |
| Undefined urgency | [0x567023…](https://explorer-studio.genlayer.com/tx/0x5670239ac70c509aedd996b16e1826936c058de63f5741733dbcb8a3357bd2c8) | MAJORITY_AGREE | REVIEW; possible masks 0, 2, 4, 6; no certain mask |
| Exception stress | [0x1b97aa…](https://explorer-studio.genlayer.com/tx/0x1b97aab47ba9424fb61113a6add616d4588928e8e416c47396f1de51d7fd3fcc) | MAJORITY_DISAGREE | Rejected; state still has exactly three rounds |

All five receipts are FINALIZED. The last is a **rejected evaluation**, not a fourth accepted result. Receipts preserve disagreeing and idle votes.

The rejected leader table incorrectly marks `recovery-exception` ALLOW at mask 1: expedited is true, sign-off and offline recovery are false. That violates the clause requiring recovery whenever sign-off is absent. Three validators disagreed, one agreed and one was canceled/idle after quorum. Rejection prevented that result from being committed; this does not establish why each individual validator disagreed.

The accepted urgency table is conservative: every configuration received UNKNOWN for that clause, including expedited configurations where a material implication would already hold. The second clause still rejects expedited configurations, so the possible masks and REVIEW result remain correct. The offline verifier explicitly allows UNKNOWN instead of ALLOW in those consequent-true cells; it does not relax the contract's exact validator agreement. Direct mocks use the more informative ALLOW values. This demonstrates a model-completeness limitation rather than evidence that semantic consensus is infallible.

The [initial CLI workflow](https://github.com/mahdidaawsh-commits/rule-knot/actions/runs/37311744104) stopped at the rejected stress evaluation. Its artifacts were recovered using [a read-only script](../scripts/finalize-existing.cjs). That script fetched current state and deployed code, verified unchanged state against the prior REVIEW snapshot, and made no further transactions. The proof runner now retains a finalized exception rejection and verifies its unchanged-state outcome.

Reproduce verification:

```sh
node scripts/verify-proofs.cjs
```

[Deployment manifest](deployment.json) records complete hashes, pinned source URLs and byte commitments. Individual `*-receipt.json` files contain transaction receipts; scenario JSON files contain onchain read snapshots. Source SHA-256: `b889a28ce402e68840353d0fa8695165a7f206fecbe0c210992e08609a926d14`. Fixture commit: `674ae2cc768c009b46b897494e14fe8359c21875`.

Synthetic records demonstrate normative policy interpretation. They do not attest to a real release's execution or safety.
