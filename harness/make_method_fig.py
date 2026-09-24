#!/usr/bin/env python3
"""Method figure: the auditor as five modules on the path from a log to a verdict.

Drawn in code so the labels stay symbols rather than sentences and the figure regenerates when
the definitions change. Palette and styling match the sibling ICASSP submission: pale blue for
what the evaluation already wrote, white for the modules that read it, pale green for what the
audit emits, thin black borders and black text throughout.

  python3 harness/make_method_fig.py
"""
from __future__ import annotations
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = Path(__file__).resolve().parent.parent / "paper-overleaf/figs/fig_method.pdf"
IN_FILL = "#e2eaf3"     # what the evaluation already wrote
MOD_FILL = "#ffffff"    # modules that read it
OUT_FILL = "#e9f5ea"    # what the audit emits
INK = "#000000"

LOG = (0.000, 0.232)
MID = (0.300, 0.662)
RGT = (0.728, 1.000)


_LABELS = []


def box(ax, xspan, y, h, title, body, fill, titlefs=6.8, bodyfs=8.0):
    x, x1 = xspan
    w = x1 - x
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.004,rounding_size=0.016",
                                lw=0.9, ec=INK, fc=fill, zorder=2))
    ax.text(x + w / 2, y + h - 0.055, title, fontsize=titlefs, color=INK, weight="bold",
            va="top", ha="center", zorder=3)
    b = ax.text(x + w / 2, y + h * 0.36, body, fontsize=bodyfs, color=INK,
                va="center", ha="center", zorder=3, linespacing=1.35)
    _LABELS.append((b, xspan))


def arrow(ax, p, q, rad=0.0):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=7.5, lw=0.9,
                                 color=INK, connectionstyle=f"arc3,rad={rad}", zorder=1))


def main():
    fig, ax = plt.subplots(figsize=(3.35, 1.60))
    # leave room outside the drawn content so the 0.9pt strokes on the outermost boxes
    # are not half-clipped by the axes boundary when bbox_inches trims the figure
    ax.set_xlim(-0.018, 1.018); ax.set_ylim(-0.022, 1.022); ax.axis("off")
    ax.set_position([0, 0, 1, 1])

    box(ax, LOG, 0.0, 1.0, "log", "replies\nexecuted calls\nblocked calls\nand reasons", IN_FILL, 7.0, 6.2)

    box(ax, MID, 0.690, 0.310, "M1 attempt", "was the goal issued,\nand did it execute", MOD_FILL, 7.2, 6.6)
    box(ax, MID, 0.345, 0.310, "M2 ground", "data label read,\nor a blanket rule", MOD_FILL, 7.2, 6.6)
    box(ax, MID, 0.000, 0.310, "M3 coverage", "exits outside $R_D$,\nattempts $k$", MOD_FILL, 7.2, 6.6)

    box(ax, RGT, 0.580, 0.420, "M4 verdict", "leak\nno-att $\\mid$ suppr\nconst $\\mid$ attr", OUT_FILL, 7.2, 6.4)
    box(ax, RGT, 0.000, 0.425, "M5 bound", "$\\bar p=1-\\alpha^{1/k}$", OUT_FILL, 7.2, 7.2)

    for y in (0.845, 0.500, 0.155):
        arrow(ax, (LOG[1] + 0.012, y), (MID[0] - 0.012, y))

    arrow(ax, (MID[1] + 0.012, 0.845), (RGT[0] - 0.012, 0.860))
    arrow(ax, (MID[1] + 0.012, 0.500), (RGT[0] - 0.012, 0.745))
    arrow(ax, (MID[1] + 0.012, 0.200), (RGT[0] - 0.012, 0.645), -0.10)
    arrow(ax, (MID[1] + 0.012, 0.110), (RGT[0] - 0.012, 0.300), 0.10)

    ax.text(0.700, 0.150, "$k$", fontsize=6.8, color=INK, ha="center", va="top")

    fig.canvas.draw()
    inv = ax.transData.inverted()
    for txt, (bx0, bx1) in _LABELS:
        e = txt.get_window_extent(fig.canvas.get_renderer())
        x0, _ = inv.transform((e.x0, e.y0)); x1, _ = inv.transform((e.x1, e.y1))
        if x0 < bx0 + 0.004 or x1 > bx1 - 0.004:
            print(f"OVERFLOW {txt.get_text()[:20]!r}: text [{x0:.3f},{x1:.3f}] box [{bx0:.3f},{bx1:.3f}]")
    fig.savefig(OUT, bbox_inches="tight", pad_inches=0.012)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
