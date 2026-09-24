#!/usr/bin/env python3
"""Extended analysis: finance domain (D2), workspace A4 encoding, per-model table, Wilson CIs.

Reads the finance (fin*) and A4 result DBs, emits paper-overleaf/numbers_ext.tex, table_fin.tex,
table_models.tex. Run after harness/analyze.py.
"""
from __future__ import annotations
import json, math, sqlite3, sys
from statistics import mean
from collections import Counter
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tool")); import agentguard_audit as ag
sys.path.insert(0, str(ROOT / "harness"))
from analyze import REGISTRY, COMPLY, SHORT, ARMS, N as NWS  # noqa

EXP = ROOT / "experiments/audit-validity"; RES = EXP / "results"; CASES = EXP / "cases"; PAPER = ROOT / "paper-overleaf"
NFIN = 15
FIN = {"finS": "S", "finA1": "A1", "finA2": "A2", "finA3": "A3", "finA4": "A4", "finB": "B"}
WS = {"S": "S", "A1": "A1", "A2": "A2", "A3": "A3", "B": "B"}
mkc = {"gpt-4o-mini-2024-07-18": "Gfo", "gpt-4.1-mini-2025-04-14": "Gfi", "gpt-4.1-nano-2025-04-14": "Gfn",
       "deepseek-v3.2": "Dsk", "doubao-seed-2-0-pro-260215": "Dbo"}


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 1.0)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def cases(suite):
    f = CASES / f"{suite}.jsonl"
    return {json.loads(l)["id"]: json.loads(l) for l in open(f)} if f.exists() else {}


def cell(model, arm, suite):
    p = RES / f"{suite}__{arm}__{model}.sqlite"
    if not p.exists():
        return None
    cs = cases(suite)
    r = ag.audit_one(str(p), cs, REGISTRY[arm])
    m = ag.compute_metrics(r)
    con = sqlite3.connect(str(p)); rows = list(con.execute("select case_id, action_events from runs")); con.close()
    n = len(rows) or 1
    exe = 0
    for cid, ae in rows:
        c = cs.get(cid)
        if not c:
            continue
        if any(ag._ev_hit(ag._keys_of(c), ag._exfil_of(c), e) for e in json.loads(ae or "[]") if not e.get("blocked") and not ag._is_mem_write(e)):
            exe += 1
    m["exe"] = exe / n
    m["util"] = m["util_rate"]
    return m


def arm_agg(suite_map, key):
    """Return per-arm aggregate over COMPLY for one domain. key='fin' or 'ws'."""
    out = {}
    S = "finS" if key == "fin" else "S"
    none_exe = {mm: (cell(mm, "none", S) or {}).get("exe", 0) for mm in COMPLY}
    for arm in ARMS:
        cr = [(mm, cell(mm, arm, S)) for mm in COMPLY]
        cr = [(mm, c) for mm, c in cr if c]
        if not cr:
            continue
        def brk(bs):
            suite = ("fin" + bs) if key == "fin" else bs
            eff = [(mm, c) for mm, c in cr if c["exe"] == 0 and none_exe.get(mm, 0) > 0]
            if not eff:
                return (0, 0)
            b = sum((cell(mm, arm, suite) or {}).get("exe", 0) > 0 for mm, _ in eff)
            return (b, len(eff))
        out[arm] = {
            "verdict": Counter(c["completeness"] for _, c in cr).most_common(1)[0][0],
            "gap": any(c["coverage_gap"] for _, c in cr),
            "exe": mean(c["exe"] for _, c in cr),
            "att": mean(c["asr_attempted"] for _, c in cr),
            "util": mean(c["util"] for _, c in cr if c["util"] is not None) if any(c["util"] is not None for _, c in cr) else None,
            "A1": brk("A1"), "A2": brk("A2"), "A3": brk("A3"),
        }
    return out


def main():
    fin = arm_agg(FIN, "fin")
    ws = arm_agg(WS, "ws")
    macros = []
    def mac(k, v): macros.append(f"\\newcommand{{\\{k}}}{{{v}}}")
    def pct(x): return "--" if x is None else f"{100*x:.0f}"
    vshort = {"ATTRIBUTED": "\\vA{}", "CONST_ONLY": "\\vC{}", "UNATTRIBUTED": "\\vU{}", "LEAK": "\\vL{}"}

    # cross-domain verdict agreement
    agree = sum(1 for a in ws if a in fin and ws[a]["verdict"] == fin[a]["verdict"])
    mac("FinKgOk", agree); mac("FinKgN", sum(1 for a in ws if a in fin))
    mac("NFinTasks", NFIN)
    # finance headline breaks
    for arm, bs in (("const", "A2"), ("partial", "A1"), ("ifc", "A3"), ("capreader", "A3")):
        if arm in fin:
            b, n = fin[arm][bs]
            mac("Fin" + arm.capitalize() + "Broke", b); mac("Fin" + arm.capitalize() + "N", n)
    # finance table (per arm)
    lines = []
    # Every defended arm, so the finance block counts the same cells as Fig. 2B.
    # Same row order as the workspace block, which groups the arms by verdict.
    for arm in ("prompt", "const", "allow", "judge", "ifc", "partial", "capreader"):
        if arm not in fin:
            continue
        a = fin[arm]
        vt = vshort[a["verdict"]] + ("\\,$^{g}$" if a["gap"] and a["verdict"] != "LEAK" else "")
        br = lambda t: (f"{a[t][0]}/{a[t][1]}" if a[t][1] else "--")
        # att and verdict are bold here for the same reason as in the main table, they are
        # what the audit contributes to the row.
        nm = "\\,$^{\\dagger}$" if arm == "judge" else ""   # same marker as the workspace block
        lines.append(f"\\textsf{{{arm}}}{nm} & {pct(a['exe'])} & \\textbf{{{pct(a['att'])}}} & \\textbf{{{vt}}}"
                     f" & {br('A1')} & {br('A2')} & {br('A3')} & {pct(a['util'])} \\\\")
    # One file, no \input boundary inside the tabular. analyze.py writes table_main.tex
    # without its closing, and this appends the finance block and closes it.
    base = (PAPER / "table_main.tex").read_text().rstrip()
    if base.endswith("%"):
        base = base[:-1]
    both = (base + "\n\\midrule\n\\multicolumn{8}{@{}l}{\\emph{finance domain}} \\\\\n\\midrule\n"
            + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}\n")
    (PAPER / "table_both.tex").write_text(both)

    # per-model table: for each complying model, exe under none (S), and verdict of each enforcing arm on S (workspace)
    enf = ["const", "ifc", "capreader", "allow", "judge"]
    mlines = []
    for mm in COMPLY:
        none_c = cell(mm, "none", "S")
        cells = {arm: cell(mm, arm, "S") for arm in enf}
        verds = " ".join(vshort[cells[arm]["completeness"]] if cells[arm] else "--" for arm in enf)
        mlines.append(f"{SHORT[mm]} & {pct(none_c['exe'] if none_c else None)} & {pct(none_c['asr_attempted'] if none_c else None)} & " +
                      " & ".join(vshort[cells[arm]["completeness"]] if cells[arm] else "--" for arm in enf) + " \\\\")
    head2 = "\\begin{tabular}{@{}lrr" + "l" * len(enf) + "@{}}\n\\toprule\nmodel & exe & att & " + " & ".join("\\textsf{" + a + "}" for a in enf) + " \\\\\n\\midrule\n"
    (PAPER / "table_models.tex").write_text(head2 + "\n".join(mlines) + "\n\\bottomrule\n\\end{tabular}\n")

    # Wilson CI on the pooled certified-holds-under-A1A2 and ifc-breaks-under-A3, across domains
    # certified = ifc + capreader; under A3 ifc breaks, capreader holds. Pool workspace+finance.
    ifc_break = capr_hold = ifc_n = capr_n = 0
    for dom in (ws, fin):
        if "ifc" in dom:
            b, n = dom["ifc"]["A3"]; ifc_break += b; ifc_n += n
        if "capreader" in dom:
            b, n = dom["capreader"]["A3"]; capr_hold += (n - b); capr_n += n
    lo, hi = wilson(ifc_break, ifc_n); mac("IfcAThreeBroke", ifc_break); mac("IfcAThreeN", ifc_n); mac("IfcAThreeLo", f"{100*lo:.0f}"); mac("IfcAThreeHi", f"{100*hi:.0f}")
    lo, hi = wilson(capr_n - capr_hold, capr_n); mac("CapAThreeBroke", capr_n - capr_hold); mac("CapAThreeN", capr_n); mac("CapAThreeHi", f"{100*hi:.0f}")

    (PAPER / "numbers_ext.tex").write_text("% AUTO-GENERATED by harness/analyze_ext.py\n" + "\n".join(macros) + "\n")
    print(f"finance arms: {list(fin)}\ncross-domain verdict agreement: {agree}/{sum(1 for a in ws if a in fin)}")
    print(f"wrote {len(macros)} macros, table_fin, table_models")


if __name__ == "__main__":
    main()
