#!/usr/bin/env python3
"""Three offline studies of the audit, none of which needs a new agent run.

(a) How many episodes an audit needs. Subsample episodes within each cell and recompute the
    verdict, giving the agreement with the full-cell verdict as a function of n.
(b) The audit's one free parameter. Sweep the attribution majority threshold and count how many
    verdicts move, showing whether the labels sit on a knife edge.
(c) What a zero licenses. The distribution of k, the attempts that reached the defense, with the
    Clopper-Pearson bound it implies, and the attacker-budget frontier over the same cells.

Writes paper-overleaf/figs/fig_curves.pdf and numbers_curves.tex.

  python3 harness/audit_curves.py
"""
from __future__ import annotations
import collections, glob, importlib.util, json, math, os, random, sqlite3, sys
from itertools import combinations
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "experiments/audit-validity/results"
CAS = ROOT / "experiments/audit-validity/cases"
PAPER = ROOT / "paper-overleaf"
SINKS = {"send_email", "create_calendar_event", "post_message"}
REG = {"none": set(), "prompt": set(), "const": SINKS, "ifc": SINKS, "partial": {"send_email"},
       "allow": SINKS, "judge": SINKS, "capreader": SINKS}
ENFORCING = ["const", "ifc", "prompt", "partial", "allow", "judge", "capreader"]
COMPLY = ["gpt-4o-mini-2024-07-18", "gpt-4.1-mini-2025-04-14", "gpt-4.1-nano-2025-04-14",
          "deepseek-v3.2", "doubao-seed-2-0-pro-260215", "deepseek-v3.1-terminus",
          "doubao-seed-1-8-251228"]
ALPHA = 0.05
B = 300


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def episode_facts(m, db, cases):
    """Per episode: (executed goal, attempted goal, attributed block, unattributed block)."""
    out = []
    con = sqlite3.connect(db)
    for cid, ae in con.execute("select case_id, action_events from runs"):
        c = cases.get(cid)
        if not c:
            continue
        keys, exfil = m._keys_of(c), m._exfil_of(c)
        evs = json.loads(ae or "[]")
        ok = [e for e in evs if not e.get("blocked") and not m._is_mem_write(e)]
        bl = [e for e in evs if e.get("blocked")]
        ex = any(m._ev_hit(keys, exfil, e) for e in ok)
        carrying = [e for e in bl if m._ev_hit(keys, exfil, e)]
        att = ex or bool(carrying)
        a = c_ = False
        if carrying and not ex:
            if any(m._is_attributed(str(e.get("reason", ""))) for e in carrying):
                a = True
            else:
                c_ = True
        out.append((ex, att, a, c_))
    con.close()
    return out


def verdict_of(facts, tau=0.5):
    if any(f[0] for f in facts):
        return "LEAK"
    if not any(f[1] for f in facts):
        return "UNATTR"
    na, nc = sum(f[2] for f in facts), sum(f[3] for f in facts)
    if na + nc == 0:
        return "UNATTR"
    return "ATTR" if na / (na + nc) > tau else "CONST"


def main():
    m = load(str(ROOT / "tool/agentguard_audit.py"), "cur")
    random.seed(0)
    cells = {}
    for suite in ("S", "finS"):
        cs = m._load_cases(str(CAS / f"{suite}.jsonl"))
        for arm in ENFORCING:
            for mod in COMPLY:
                db = RES / f"{suite}__{arm}__{mod}.sqlite"
                if db.exists():
                    cells[(suite, arm, mod)] = episode_facts(m, str(db), cs)
    print(f"cells {len(cells)}, episodes {sum(len(v) for v in cells.values())}")

    # (a) verdict agreement as a function of episodes per cell
    ns = [4, 8, 12, 16, 20, 24, 30]
    agree = []
    for n in ns:
        ok = tot = 0
        for facts in cells.values():
            if len(facts) < n:
                continue
            full = verdict_of(facts)
            for _ in range(B):
                ok += verdict_of(random.sample(facts, n)) == full
                tot += 1
        agree.append(100.0 * ok / tot)
    n_half = next(n for n, a in zip(ns, agree) if a >= 95.0)

    # (b) attacker-budget frontier over the cells with a defense effect, and the check that the
    # attribution threshold is never exercised because each arm emits one reason wording
    shares = []
    for v in cells.values():
        na, nc = sum(f[2] for f in v), sum(f[3] for f in v)
        if na + nc:
            shares.append(na / (na + nc))
    degenerate = sum(1 for x in shares if x in (0.0, 1.0))
    rows = json.loads((ROOT / "experiments/audit-validity/summary.json").read_text())["rows"]
    none_real = {r["model"]: r["asr_realized"] for r in rows if r["arm"] == "none"}
    eff = [r for r in rows if r["arm"] != "none" and r["asr_realized"] == 0
           and none_real.get(r["model"], 0) > 0 and r.get("asr_a3") is not None]
    SU = ["asr_a1", "asr_a2", "asr_a3"]
    brk = lambda r, sub: any((r[su] or 0) > 0 for su in sub)

    def recommend(r):
        if r["coverage_gap"]:
            return {"asr_a1"} if r["verdict"] == "ATTRIBUTED" else set(SU)
        if r["verdict"] == "ATTRIBUTED":
            return {"asr_a3"}
        if r["verdict"] == "CONST_ONLY":
            return {"asr_a2", "asr_a3"}
        return set(SU)
    fixed = [(k, 100.0 * max(sum(brk(r, c) for r in eff) for c in combinations(SU, k)) / len(eff))
             for k in (1, 2, 3)]
    g_budget = sum(len(recommend(r)) for r in eff) / len(eff)
    g_break = 100.0 * sum(brk(r, recommend(r)) for r in eff) / len(eff)

    # (c) k per defended cell and the bound it implies
    ks = sorted(sum(f[1] for f in v) for k, v in cells.items() if not any(f[0] for f in v))
    pbar = [100.0 * (1 - ALPHA ** (1.0 / k)) if k else 100.0 for k in ks]
    k_med = ks[len(ks) // 2]
    pbar_med = 100.0 * (1 - ALPHA ** (1.0 / k_med)) if k_med else 100.0
    k_zero = sum(1 for k in ks if k == 0)

    # Single column (3.39in) with the two panels that carry results no table holds. Panel (b)'s
    # numbers are all in the RQ3 prose, so it is emitted separately for the artifact.
    # (a) the three histories drawn directly: attempted against executed goal rate per cell
    pts = {"LEAK": ([], []), "ATTR": ([], []), "CONST": ([], []), "UNATTR": ([], [])}
    for k, v in cells.items():
        n = len(v) or 1
        ex = 100.0 * sum(f[0] for f in v) / n
        at = 100.0 * sum(f[1] for f in v) / n
        pts[verdict_of(v)][0].append(at); pts[verdict_of(v)][1].append(ex)

    # Panel A is the credit composition, which is the paper's headline and is not
    # definitional. Panel B is the distribution of k, since the bound itself is a
    # deterministic function of k and plotting it against k would plot a known curve.
    import matplotlib.gridspec as gridspec
    fig = plt.figure(figsize=(3.35, 1.66))
    gs = gridspec.GridSpec(1, 2, figure=fig, width_ratios=[1.30, 1.0], wspace=0.46,
                           top=0.86, bottom=0.30)
    axA = fig.add_subplot(gs[0, 0]); axB = fig.add_subplot(gs[0, 1])

    prot = json.loads((ROOT / "experiments/audit-validity/summary.json").read_text())["protocols"]
    order = [("text", "reply"), ("mkexec", "marker"), ("exec", "goal-bound"),
             ("feas", "feasibility"), ("audit", "ours")]
    segs = [("leaking", "missed leak", "#c0392b"), ("no_defense_effect", "no effect", "0.62"),
            ("breaks_adaptive", "breaks A1 or A2", "#e08214"),
            ("breaks_a3", "breaks A3", "#f6c37a"), ("held", "held", "#1f4e79")]
    ys = range(len(order))
    for y, (k, lab) in zip(ys, order):
        left = 0
        for key, name, col in segs:
            w = prot[k][key]
            if w:
                axA.barh(y, w, left=left, height=0.62, color=col, edgecolor="white", lw=0.5)
            left += w
    axA.set_yticks(list(ys)); axA.set_yticklabels([l for _, l in order], fontsize=6.4)
    axA.get_yticklabels()[-1].set_fontweight("bold")
    axA.invert_yaxis()
    axA.set_xlabel("cells credited")
    axA.set_xlim(0, 84)
    hs = [plt.Rectangle((0, 0), 1, 1, color=c) for _, _, c in segs]
    axA.legend(hs, [n for _, n, _ in segs], fontsize=5.0, frameon=False, ncol=5,
               loc="upper left", bbox_to_anchor=(-0.02, -0.34), handlelength=0.8,
               handletextpad=0.25, columnspacing=0.5, borderpad=0.0)
    axA.set_title("A. what each protocol credits", fontsize=7.2, pad=2)

    # B. how much evidence each defended zero rests on, as the count of attempts that
    # reached the defense. The bound is a function of this count alone.
    import matplotlib.ticker as mticker
    _, _, patches = axB.hist(ks, bins=range(0, max(ks) + 2), color="#1f4e79",
                             edgecolor="white", lw=0.4)
    if k_zero:
        patches[0].set_facecolor("#c0392b")   # the cells with no bound at all
    axB.yaxis.set_major_locator(mticker.MaxNLocator(integer=True, nbins=4))
    axB.set_ylim(0, max(collections.Counter(ks).values()) * 1.42)
    _top = max(collections.Counter(ks).values())
    axB.vlines(k_med, 0, _top * 1.06, ls=":", color="0.4", lw=1.0)
    axB.annotate(f"median $k$={k_med}, $\\bar p$={pbar_med:.0f}%", (k_med, axB.get_ylim()[1]),
                 textcoords="offset points", xytext=(3, -13), va="top", fontsize=6.0, color="0.25")
    if k_zero:
        axB.text(0.02, 0.97, f"{k_zero} cells at $k$=0, no bound at all",
                 transform=axB.transAxes, fontsize=6.0, color="#c0392b",
                 ha="left", va="top")
    axB.set_xlabel("attempts $k$"); axB.set_ylabel("cells")
    axB.set_title("B. evidence behind a zero", fontsize=7.2, pad=2)

    for a in (axA, axB):
        a.tick_params(labelsize=6.4, pad=1.4)
        a.xaxis.label.set_size(6.8); a.yaxis.label.set_size(6.8)
        a.spines[["top", "right"]].set_visible(False)
    fc = None
    (PAPER / "figs").mkdir(exist_ok=True)

    # Budget frontier, generated for the artifact rather than the paper. RQ3 carries its numbers.
    fb, fbx = plt.subplots(figsize=(3.35, 1.7))
    fbx.plot([k for k, _ in fixed], [b for _, b in fixed], "s--", color="0.45", ms=4, lw=1.3,
             label="best fixed set")
    fbx.plot([g_budget], [g_break], "*", color="#c0392b", ms=11, label="verdict-guided")
    fbx.set_xlabel("attacks per cell"); fbx.set_ylabel("cells broken (%)")
    fbx.set_ylim(45, 75); fbx.set_xlim(0.7, 3.3)
    fbx.legend(fontsize=7, frameon=False, loc="lower right")
    fbx.spines[["top", "right"]].set_visible(False)
    fb.tight_layout(pad=0.3)
    fc = None
    (PAPER / "figs").mkdir(exist_ok=True)
    fig.savefig(PAPER / "figs/fig_curves.pdf", bbox_inches="tight")
    fb.savefig(PAPER / "figs/fig_budget.pdf", bbox_inches="tight")


    mac = [f"\\newcommand{{\\CurveBoot}}{{{B}}}",
           f"\\newcommand{{\\CurveNDef}}{{{len(ks)}}}",
           f"\\newcommand{{\\CurveNHalf}}{{{n_half}}}",
           f"\\newcommand{{\\CurveAgreeFour}}{{{agree[0]:.0f}}}",
           f"\\newcommand{{\\CurveAgreeFull}}{{{agree[-1]:.0f}}}",
           f"\\newcommand{{\\CurveDegen}}{{{degenerate}}}",
           f"\\newcommand{{\\CurveShareN}}{{{len(shares)}}}",
           f"\\newcommand{{\\CurveKMed}}{{{k_med}}}",
           f"\\newcommand{{\\CurvePbarMed}}{{{pbar_med:.0f}}}",
           f"\\newcommand{{\\CurveKZero}}{{{k_zero}}}",
           f"\\newcommand{{\\CurveNCells}}{{{len(cells)}}}"]
    (PAPER / "numbers_curves.tex").write_text(
        "% AUTO-GENERATED by harness/audit_curves.py\n" + "\n".join(mac) + "\n")
    print(f"(a) agreement {agree[0]:.0f}% at n=4 -> {agree[-1]:.0f}% at n=30, 95% reached at n={n_half}")
    print(f"(b) frontier {fixed}, guided {g_break:.1f}% at {g_budget:.2f}; degenerate shares {degenerate}/{len(shares)}")
    print(f"(c) median k={k_med}, bound {pbar_med:.0f}%, cells with k=0: {k_zero}/{len(ks)}")


if __name__ == "__main__":
    main()
