#!/usr/bin/env python3
"""Figure 1: executed ASR of the three zero-scoring arms under the static and the two adaptive suites.

Reads experiments/audit-validity/summary.json (from analyze.py); writes paper-overleaf/figs/fig_adaptive.pdf.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
S = json.loads((ROOT / "experiments/audit-validity/summary.json").read_text())
rows = {(r["model"], r["arm"]): r for r in S["rows"]}
MODELS = [("gpt-4o-mini-2024-07-18", "GPT-4o-mini"), ("gpt-4.1-mini-2025-04-14", "GPT-4.1-mini"), ("deepseek-v3.2", "DeepSeek-V3.2")]
ARMS = [("const", "const"), ("ifc", "ifc"), ("partial", "partial")]
VERD = {"ATTRIBUTED": "attributed", "CONST_ONLY": "const-only", "UNATTRIBUTED": "unattributed", "LEAK": "leak"}
# Okabe-Ito, colorblind safe: grey for static, blue for A1, orange for A2
COL = {"S": "#999999", "A1": "#0072B2", "A2": "#E69F00"}

plt.rcParams.update({"font.size": 7, "axes.linewidth": 0.6, "pdf.fonttype": 42})
fig, axes = plt.subplots(1, len(MODELS), figsize=(3.4, 1.55), sharey=True)
w = 0.26
for ax, (mid, mname) in zip(axes, MODELS):
    for i, (arm, alab) in enumerate(ARMS):
        r = rows.get((mid, arm))
        if not r:
            continue
        vals = [100 * r["asr_realized"], 100 * r["asr_a1"], 100 * r["asr_a2"]]
        for j, (suite, v) in enumerate(zip(["S", "A1", "A2"], vals)):
            ax.bar(i + (j - 1) * w, v, width=w - 0.03, color=COL[suite], linewidth=0)
        tag = VERD[r["verdict"]] + (" + gap" if r["coverage_gap"] else "")
        ax.text(i, 103, tag, ha="center", va="bottom", fontsize=5.2, color="#333333")
    ax.set_title(mname, fontsize=7, pad=8)
    ax.set_xticks(range(len(ARMS)))
    ax.set_xticklabels([a[1] for a in ARMS])
    ax.set_ylim(0, 125)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.spines[["top", "right"]].set_visible(False)
    ax.tick_params(length=2, width=0.5)
    ax.grid(axis="y", color="#e5e5e5", linewidth=0.5)
    ax.set_axisbelow(True)
axes[0].set_ylabel("executed ASR (%)")
handles = [plt.Rectangle((0, 0), 1, 1, color=COL[s]) for s in ["S", "A1", "A2"]]
fig.legend(handles, ["static S", "A1 channel", "A2 obfuscation"], ncol=3, loc="lower center", bbox_to_anchor=(0.5, -0.06), frameon=False, fontsize=6, handlelength=1, columnspacing=1.2)
fig.tight_layout(rect=(0, 0.06, 1, 1))
out = ROOT / "paper-overleaf/figs/fig_adaptive.pdf"
out.parent.mkdir(exist_ok=True)
fig.savefig(out, bbox_inches="tight")
print("wrote", out)
