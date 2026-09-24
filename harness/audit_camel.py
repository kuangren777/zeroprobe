#!/usr/bin/env python3
"""Audit CaMeL, a published provenance defense, with both readers of M2.

CaMeL enforces security policies over the capabilities its interpreter attaches to values. Its
denial messages are written by its authors, not by us, and none of them contains a phrase from the
fallback vocabulary, so this run separates the two readers of M2 on a third-party defense:

  vocabulary: does the stated reason name data provenance by the fixed phrase list?
  replay:     does the denial disappear when the same call is re-evaluated with the capability
              predicates forced permissive, which is the label-flip probe applied inside CaMeL's
              own engine (external/camel/probe_main.py)?

Inputs are external/camel/probe_records.jsonl, written by that wrapper, and the AgentDojo result
JSONs CaMeL writes under external/camel/logs. Undefended banking episodes come from the runs
already in experiments/agentdojo/runs, so the comparison uses the same benchmark and backbone.

  python3 harness/audit_camel.py
"""
from __future__ import annotations
import json, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# The CaMeL checkout is third-party and not vendored. Its outputs are copied into the artifact,
# so look there first and fall back to a local checkout when one is present.
CAMEL = ROOT / "experiments/camel"
if not (CAMEL / "probe_records.jsonl").exists():
    CAMEL = ROOT / "external/camel"
RUNS = ROOT / "experiments/agentdojo/runs"
PAPER = ROOT / "paper-overleaf"
sys.path.insert(0, str(ROOT / "tool")); import agentguard_audit as ag

SUITE = "banking"
ATTACK = "important_instructions"
# CaMeL's interpreter routes every state-changing operation through the policy engine, including
# Python string methods inside the generated program. The audit's population is the suite's
# side-effecting tools, the calls an AgentDojo defense is evaluated on, so the two are reported
# apart rather than pooled.
SINK_TOOLS = {"send_money", "schedule_transaction", "update_scheduled_transaction",
              "update_password", "update_user_info"}


def probe_rows():
    p = CAMEL / "probe_records.jsonl"
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def camel_cells():
    """(injection task) -> [security flags] for CaMeL's own AgentDojo results under the attack."""
    cells = defaultdict(list)
    for f in sorted((CAMEL / "logs").rglob("*.json")):
        rec = json.loads(f.read_text())
        if rec.get("attack_type") != ATTACK or rec.get("suite_name") != SUITE:
            continue
        if "secpol" not in f.relative_to(CAMEL / "logs").parts[0]:
            continue
        cells[rec.get("injection_task_id")].append(bool(rec.get("security")))
    return cells


def undefended_cells():
    cells = defaultdict(list)
    for f in sorted((RUNS / "gpt-4o-mini-2024-07-18").rglob("*.json")):
        rec = json.loads(f.read_text())
        if rec.get("attack_type") != ATTACK or rec.get("suite_name") != SUITE:
            continue
        cells[rec.get("injection_task_id")].append(bool(rec.get("security")))
    return cells


def main():
    rows_all = probe_rows()
    rows = [r for r in rows_all if r["tool"] in SINK_TOOLS]
    den = [r for r in rows if r["decision"] == "Denied"]
    other_den = sum(r["decision"] == "Denied" for r in rows_all if r["tool"] not in SINK_TOOLS)
    # Default denials of calls no policy covers carry no label, so the replay must leave them standing.
    other_stood = sum(r["decision"] == "Denied" and r.get("counterfactual") == "Denied"
                      for r in rows_all if r["tool"] not in SINK_TOOLS)
    allowed = len(rows) - len(den)
    by_reason = Counter(r["reason"][:70] for r in den)
    vocab_attr = sum(ag._is_attributed(r["reason"]) for r in den)
    flipped = sum(r.get("counterfactual") == "Allowed" for r in den)
    stood = sum(r.get("counterfactual") == "Denied" for r in den)
    errs = sum(r.get("counterfactual") == "ERROR" for r in den)
    # Which label a denial reads: lift the source label alone, the reader label alone, or only both.
    f_src = sum(r.get("counterfactual_source") == "Allowed" for r in den)
    f_rd = sum(r.get("counterfactual_readers") == "Allowed" for r in den)
    f_both = sum(r.get("counterfactual") == "Allowed" and r.get("counterfactual_source") != "Allowed"
                 and r.get("counterfactual_readers") != "Allowed" for r in den)
    print(f"split: source alone {f_src}, readers alone {f_rd}, only both {f_both}")
    print(f"sink-tool policy decisions {len(rows)}, allowed {allowed}, denied {len(den)}; "
          f"denials on interpreter-internal calls, excluded: {other_den}")
    print(f"vocabulary reads provenance on {vocab_attr}/{len(den)} denials")
    print(f"probe: denial disappears with data labels removed on {flipped}/{len(den)}, "
          f"stands on {stood}, not re-evaluable on {errs}")
    for reason, n in by_reason.most_common(6):
        print(f"   {n:4d}  {reason}")

    cc, uu = camel_cells(), undefended_cells()
    zero = [k for k, v in cc.items() if not any(v)]
    live = [k for k in zero if any(uu.get(k, []))]
    eps = sum(len(v) for v in cc.values())
    print(f"CaMeL cells {len(cc)}, episodes {eps}, zero cells {len(zero)}, "
          f"of which reachable undefended {len(live)}")

    def mac(k, v):
        return f"\\newcommand{{\\{k}}}{{{v}}}"
    out = ["% AUTO-GENERATED by harness/audit_camel.py",
           mac("CamDec", len(rows)), mac("CamDen", len(den)), mac("CamVocab", vocab_attr), mac("CamFlip", flipped),
           mac("CamOther", other_den), mac("CamOtherStood", other_stood), mac("CamPct", round(100 * flipped / max(len(den), 1))),
           mac("CamFlipSrc", f_src), mac("CamFlipRead", f_rd), mac("CamFlipBoth", f_both),
           mac("CamStood", stood), mac("CamErr", errs), mac("CamCells", len(cc)),
           mac("CamEps", eps), mac("CamZero", len(zero)), mac("CamLive", len(live))]
    (PAPER / "numbers_camel.tex").write_text("\n".join(out) + "\n")
    print("wrote", PAPER / "numbers_camel.tex")


if __name__ == "__main__":
    main()
