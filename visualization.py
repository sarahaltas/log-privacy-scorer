import json
import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from collections import Counter

SCRIPT_DIR   = os.path.dirname(__file__)
FIGURES_DIR  = os.path.join(SCRIPT_DIR, "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)

DATASETS = ["SSH", "Apache", "HDFS", "Linux"]

RESULT_FILES = {
    "SSH":    os.path.join(SCRIPT_DIR, "results", "OpenSSH_2k.log_structured_results.json"),
    "Apache": os.path.join(SCRIPT_DIR, "results", "Apache_2k.log_structured_results.json"),
    "HDFS":   os.path.join(SCRIPT_DIR, "results", "HDFS_2k.log_structured_results.json"),
    "Linux":  os.path.join(SCRIPT_DIR, "results", "Linux_2k.log_structured_results.json"),
}

RISK_COLORS = {"LOW": "#4CAF50", "MEDIUM": "#FFC107","HIGH": "#FF9800", "CRITICAL": "#F44336"}
DATASET_COLORS = {"SSH": "#2196F3", "Apache": "#F44336", "HDFS": "#FF9800", "Linux": "#4CAF50"}

plt.rcParams.update({
    "figure.facecolor": "white", "axes.facecolor": "white",
    "axes.spines.top": False, "axes.spines.right": False,
    "font.size": 11,
})

def load(dataset: str) -> list:
    path = RESULT_FILES[dataset]
    if not os.path.exists(path):
        print(f"  Warning: {path} not found — skipping {dataset}")
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def scores(data): return [r["analysis"]["score"] for r in data]
def levels(data): return [r["analysis"]["level"] for r in data]
def fig_path(name): return os.path.join(FIGURES_DIR, name)

def fig1_average_scores():
    fig, ax = plt.subplots(figsize=(9, 5))
    avgs = []
    colors = []
    for ds in DATASETS:
        data = load(ds)
        if data:
            avgs.append(np.mean(scores(data)))
            colors.append(DATASET_COLORS[ds])

    bars = ax.bar(DATASETS[:len(avgs)], avgs, color=colors, alpha=0.85, edgecolor="white", width=0.5)
    for bar, val in zip(bars, avgs):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05, f"{val:.2f}", ha="center", va="bottom", fontsize=12, fontweight="bold")

    ax.axhline(y=2.0, color="#F44336", linestyle="--", alpha=0.6, label="Critical (2.0)")
    ax.axhline(y=1.0, color="#FF9800", linestyle="--", alpha=0.6, label="High (1.0)")
    ax.axhline(y=0.5, color="#FFC107", linestyle="--", alpha=0.6, label="Medium (0.5)")
    ax.set_ylabel("Score", fontsize=12)
    ax.set_title("Figure 1 — Average Privacy Risk Score Across Datasets",fontsize=12, pad=15)
    ax.legend(fontsize=9)
    ax.set_ylim(0, max(avgs) * 1.2 if avgs else 3)
    plt.tight_layout()
    plt.savefig(fig_path("fig1_average_scores.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("Figure 1 saved")

def fig2_top_attributes():
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    axes = axes.flatten()

    TIER_COLORS = {
        "ip": "#F44336", "mac": "#F44336", "username": "#F44336",
        "hostname": "#FF9800", "timestamp": "#FF9800",
        "file_path": "#FF9800", "url": "#FF9800", "port": "#FF9800",
        "log_level": "#4CAF50", "status_code": "#4CAF50",
        "method": "#4CAF50", "component": "#4CAF50",
        "config": "#4CAF50", "protocol": "#4CAF50", "process_id": "#4CAF50",
    }

    for ax, ds in zip(axes, DATASETS):
        data = load(ds)
        if not data:
            ax.set_title(f"{ds}\n(no data)")
            continue
        total = len(data)
        attr_counts = Counter()
        for r in data:
            a = r["analysis"]
            for attr in (a["direct_identifiers"] + a["quasi_identifiers"]):
                attr_counts[attr] += 1
        if not attr_counts:
            continue
        top = attr_counts.most_common(8)
        attrs = [t[0] for t in top]
        counts = [t[1] / total * 100 for t in top]
        colors = [TIER_COLORS.get(a, "#9E9E9E") for a in attrs]
        bars = ax.barh(attrs, counts, color=colors, alpha=0.85, edgecolor="white")
        for bar, pct in zip(bars, counts):
            ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2, f"{pct:.0f}%", va="center", fontsize=9)
        ax.set_title(f"{ds}", fontsize=13, fontweight="bold")
        ax.set_xlabel("% of Log Lines")
        ax.set_xlim(0, 120)

    legend_patches = [
        mpatches.Patch(color="#F44336", label="Identifiable"),
        mpatches.Patch(color="#FF9800", label="Quasi-identifier"),
        mpatches.Patch(color="#4CAF50", label="Non-sensitive"),
    ]
    fig.legend(handles=legend_patches, loc="lower center", ncol=3, fontsize=11, bbox_to_anchor=(0.5, -0.02))
    fig.suptitle("Figure 2 — Most Frequently Detected Sensitive Attributes Across Datasets", fontsize=12)
    plt.tight_layout()
    plt.savefig(fig_path("fig2_top_attributes.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("Figure 2 saved")

def fig3_risk_distribution():
    fig, axes = plt.subplots(1, 4, figsize=(16, 5))
    risk_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    for ax, ds in zip(axes, DATASETS):
        data = load(ds)
        if not data:
            ax.set_title(f"{ds}\n(no data)")
            continue

        lvls = levels(data)
        total = len(lvls)

        counts = [lvls.count(l) for l in risk_levels]
        pcts = [c / total * 100 for c in counts]

        bars = ax.bar(risk_levels, pcts, color=[RISK_COLORS[l] for l in risk_levels], edgecolor="white", alpha=0.9)

        for bar, pct in zip(bars, pcts):
            if pct > 2:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5, f"{pct:.0f}%", ha="center", fontsize=10)

        ax.set_title(ds, fontweight="bold")
        ax.set_ylim(0, 100)
        ax.set_xlabel("Risk Level")
        if ds == "SSH":
            ax.set_ylabel("% of Logs")

    fig.suptitle("Figure 3 — Privacy Risk Distribution Across Datasets", fontsize=12)
    plt.tight_layout()
    plt.savefig(fig_path("fig3_risk_distribution.png"), dpi=150, bbox_inches="tight")
    plt.close()
    print("Figure 3 saved")

if __name__ == "__main__":
    print("Generating visualizations...\n")
    fig1_average_scores()
    fig2_top_attributes()
    fig3_risk_distribution()