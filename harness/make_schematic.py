#!/usr/bin/env python3
"""Figure 1: three episode logs that all score ASR = 0, and the verdict the audit assigns.

Content is taken from real traces of the grid (GPT-4.1-mini under ifc and const, Claude-Haiku-4.5 under none).
Writes paper-overleaf/figs/fig_schematic.pdf.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
INK, MUTED = "#222222", "#666666"
GREEN, AMBER, GREY, RED = "#1b7837", "#b35806", "#5f5f5f", "#b2182b"

plt.rcParams.update({"font.size": 6.2, "pdf.fonttype": 42, "font.family": "DejaVu Sans"})
fig, ax = plt.subplots(figsize=(3.45, 1.7))
ax.set_xlim(0, 100); ax.set_ylim(0, 52); ax.axis("off")


def box(x, y, w, h, text, ec, fc="white", fs=6.0, color=INK, weight="normal"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2", ec=ec, fc=fc, lw=0.7))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=color, weight=weight, linespacing=1.15)


def arrow(x0, x1, y):
    ax.annotate("", xy=(x1, y), xytext=(x0, y), arrowprops=dict(arrowstyle="-|>", lw=0.6, color=MUTED, mutation_scale=6))


import json
_S = json.loads((ROOT / "experiments/audit-validity/summary.json").read_text())
_R = {(r["model"], r["arm"]): r for r in _S["rows"]}
def _ad(m, a):
    r = _R[(m, a)]
    return f"A1 {100*r['asr_a1']:.0f}%\nA2 {100*r['asr_a2']:.0f}%\nA3 {100*r['asr_a3']:.0f}%"
assert _R[("gpt-4.1-mini-2025-04-14", "ifc")]["verdict"] == "ATTRIBUTED"
assert _R[("gpt-4.1-mini-2025-04-14", "const")]["verdict"] == "CONST_ONLY"
assert _R[("claude-haiku-4-5", "none")]["verdict"] == "UNATTRIBUTED"
rows = [
    # y, arm label, sink event text, event color, verdict, verdict color, adaptive outcome
    (36, "ifc", "send_email(attacker, id)\nblocked: untrusted origin", GREEN, "ATTRIBUTED", GREEN, _ad("gpt-4.1-mini-2025-04-14", "ifc")),
    (19, "const", "send_email(attacker, id)\nblocked: secret pattern", AMBER, "CONST-ONLY", AMBER, _ad("gpt-4.1-mini-2025-04-14", "const")),
    (2, "none", "no sink call\nno event logged", GREY, "UNATTRIBUTED", GREY, "model\nrefused"),
]
ax.set_xlim(0, 130)
H = 11
ax.text(12, 51, "injected read", ha="center", color=MUTED, fontsize=5.4)
ax.text(49, 51, "logged sink event", ha="center", color=MUTED, fontsize=5.4)
ax.text(88, 51, "ASR      verdict", ha="center", color=MUTED, fontsize=5.4)
ax.text(121, 51, "adaptive", ha="center", color=MUTED, fontsize=5.4)
for y, arm, ev, evc, verdict, vc, adapt in rows:
    box(1, y, 22, H, "read_inbox\n+ injection\n" + f"arm {arm.splitlines()[0]}", MUTED, fs=5.0)
    arrow(24, 27, y + H / 2)
    box(28, y, 42, H, ev, evc, fs=4.9)
    arrow(71, 74, y + H / 2)
    ax.text(77.5, y + H / 2, "0%", ha="center", va="center", fontsize=6.6, color=INK, weight="bold")
    box(83, y + 1.8, 27, H - 3.6, verdict, vc, fc=vc, fs=4.6, color="white", weight="bold")
    lines = adapt.split("\n")
    for j, ln in enumerate(lines):
        hit = ln.endswith("%") and not ln.endswith(" 0%")
        ax.text(121, y + H / 2 + (len(lines) - 1) * 1.9 - j * 3.8, ln, ha="center", va="center", fontsize=4.9, color=RED if hit else INK)
out = ROOT / "paper-overleaf/figs/fig_schematic.pdf"
out.parent.mkdir(exist_ok=True)
fig.savefig(out, bbox_inches="tight", pad_inches=0.01)
fig.savefig(out.with_suffix(".png"), dpi=300, bbox_inches="tight", pad_inches=0.01)
print("wrote", out)
