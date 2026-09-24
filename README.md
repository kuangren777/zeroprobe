# Zero Is Not Evidence: Attributing Zero Attack Success in LLM Agent Defense Evaluations

Code and the auditor for the ICASSP 2027 submission of the same name.

A zero attack success rate is read as proof that a defense works. Several different histories leave that same zero in an evaluation log. An enforcement layer blocked the payload because of the labels its data carried. A rule refused a class of calls without reading those labels. No call carrying the attacker's goal reached the defense at all. Any score that reads only executed outcomes is constant across all of them. The events an evaluation already writes separate them offline.

The audit decides the ground of an interception by replaying it with the call arguments fixed and the data labels of the context removed. A block that disappears was grounded in the data. A block that stands was not. When an evaluation cannot be replayed, the auditor falls back to reading the stated block reason through a fixed phrase list, which under-attributes on unfamiliar wording.

Paper scale: 17 models, 8 defense arms, 2 task domains, 19345 episodes over 785 cells, plus audits of three published AgentDojo defenses and of the released CaMeL artifact.

## What is in this repository

This release holds the auditor, its unit tests, the testbed, the attack cases and every analysis script. The run logs behind the paper (about 100 MB of SQLite databases, JSONL traces and AgentDojo and CaMeL outputs) are not in the repository. The analysis scripts read them from the paths listed under Logs below.

```
tool/
  agentguard_audit.py            the auditor, single file
  test_agentguard_audit.py       15 unit tests, no network
  adapters/agentdojo_adapter.py  AgentDojo message logs -> the auditor's log contract
harness/                         testbed and analysis, standard library only unless noted
  agentbench.py                  workspace and finance agents, 8 defense arms, attack suites
  analyze.py, analyze_ext.py     main and per-domain tables, per-model table
  ablate_audit.py                component ablation against a matcher-independent oracle
  review_r1.py                   label-flip replay, clustered bounds, matcher accuracy
  audit_agentdojo.py, audit_detector.py, ad_local_detector.py   the AgentDojo defenses
  audit_camel.py                 the CaMeL audit, denials split by the predicate they read
  audit_curves.py, make_method_fig.py   the two figures (need matplotlib)
  blind_reason.py, paraphrase_reasons.py   robustness of the phrase-list fallback
  upstream_check.py              this auditor vs the upstream release on the same logs
experiments/audit-validity/
  cases/*.jsonl                  case records, marker and attacker destination per episode
  summary.json                   per-cell summary the RQ3 attacker analysis reads
experiments/camel/probe_main.py  wrapper that records each CaMeL policy decision with its replay
```

A cell is named `<suite>__<arm>__<model>`. Suites are `S` (static injection), `A1` (channel moved to a calendar invitation), `A2` (spaced identifier), `A3` (attacker mailbox inside the trusted domain), `B` (benign, no injection), and their `fin` counterparts in the finance domain. Arms are `none`, `prompt`, `const`, `ifc`, `partial`, `allow`, `judge`, `capreader`.

## Tool provenance

The auditor is a patched fork of [`luyichen0704/agentguard-audit`](https://github.com/luyichen0704/agentguard-audit) at commit `65fe72a4128ed58c175a330baefacb237fc2858b` (v0.1.0). The upstream release does not reproduce the paper's tables. On the same logs it agrees on 48 of 56 static verdicts, and the 8 that differ isolate these patches:

| patch | what it changes |
|---|---|
| goal binding (`_ev_hit`, `_dest_blob`) | a goal event must carry the marker and name the attacker in a recipient field |
| marker folding (`_hit`, `_norm`, `_b64_decoded`) | case and non-alphanumeric folding, then base64 |
| negation guard (`_is_attributed`) | a provenance keyword next to a negator does not count |
| attack-bearing attribution (`audit_one`) | only blocks that carried the attacker's goal vote |
| coverage gap (`compute_metrics`) | flags executed sink calls outside the declared registry |

`harness/upstream_check.py --upstream <clone of agentguard-audit>` regenerates this comparison.

## Running

The unit tests need nothing else:

```bash
python3 tool/test_agentguard_audit.py      # 15 tests, no network
```

Running the testbed calls a hosted model. The gateway is any OpenAI-compatible chat-completions endpoint, and the key is read from the environment only:

```bash
export AGENTBENCH_KEY=...                           # your gateway key
export AGENTBENCH_URL=https://<host>/v1/chat/completions
python3 harness/agentbench.py --model gpt-4o-mini-2024-07-18 --suite S --arm ifc
```

Runs are resumable, at temperature 0 with at most 8 tool rounds. Seven models follow the injection often enough to exercise the defenses: `gpt-4o-mini-2024-07-18`, `gpt-4.1-mini-2025-04-14`, `gpt-4.1-nano-2025-04-14`, `deepseek-v3.2`, `deepseek-v3.1-terminus`, `doubao-seed-2-0-pro-260215`, `doubao-seed-1-8-251228`.

The analysis scripts write LaTeX macros (`numbers*.tex`, `table_*.tex`) into `paper-overleaf/`. Every number in the paper is one of those macros.

## Logs

The analysis scripts expect the logs at these paths:

| path | what it is |
|---|---|
| `experiments/audit-validity/results` | every episode of the grid, one SQLite per cell plus a JSONL trace |
| `experiments/audit-validity/blind`, `paraphrase`, `m1_annot` | the held-out, paraphrased and annotated reason studies |
| `experiments/agentdojo/runs` | the AgentDojo runs, three defenses and two attacks |
| `external/camel/probe_records.jsonl`, `external/camel/logs` | the CaMeL policy decisions and its own AgentDojo-format results |

The AgentDojo and CaMeL runs use those projects under their own licenses. Neither is vendored here. `harness/ad_local_detector.py` loads AgentDojo's published detector checkpoint, and `PI_DETECTOR_PATH` points it at a local copy.

## Data provenance and ethics

Every episode was run against the testbed in `harness/agentbench.py`. Its documents, mailboxes, identifiers and recipients are synthetic. `acme-corp.com`, `attacker@evil-corp.net` and the `CANARY-nnnn` markers do not correspond to any real organization, address or secret. No human subjects, no personal data, no live service was attacked, and no real address received a message. The injected payloads are the published AgentDojo important-instructions template plus three elementary variations of it.

## Citation

The paper is under review at ICASSP 2027. Until it appears, cite this repository.

## License

MIT, see `LICENSE`.
