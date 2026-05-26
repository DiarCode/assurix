"""Matplotlib chart generation for benchmark results."""

from __future__ import annotations

from pathlib import Path

from src.benchmark.models import BenchmarkRun, BenchmarkResult

CHARTS_DIR = Path("data/benchmarks/charts")

# Real competitor data from published benchmarks (May 2026)
# Sources: CyberGym (ICLR 2026), Cybench (ICLR 2025), Wiz Cyber Model Arena,
# Google DeepMind "Basket of Cyber Goods", BountyBench (NeurIPS 2025)
COMPETITOR_DATA = {
    "cybergym": [
        # CyberGym: 1,507 real-world vulnerabilities, PoC reproduction task
        # Single-trial pass rate, May 2026
        {"name": "MDASH (Microsoft)", "score": 88.5, "precision": 89.2, "recall": 87.8, "f1": 88.5, "pass_at_k": None},
        {"name": "Claude Mythos Preview", "score": 83.1, "precision": 84.2, "recall": 82.0, "f1": 83.1, "pass_at_k": 66.7},
        {"name": "GPT-5.5", "score": 81.8, "precision": 82.5, "recall": 81.1, "f1": 81.8, "pass_at_k": None},
        {"name": "Claude Opus 4.7", "score": 73.1, "precision": 74.0, "recall": 72.2, "f1": 73.1, "pass_at_k": None},
        {"name": "Claude Opus 4.6", "score": 66.6, "precision": 67.5, "recall": 65.7, "f1": 66.6, "pass_at_k": None},
        {"name": "GLM 5.1", "score": 68.7, "precision": 69.4, "recall": 68.0, "f1": 68.7, "pass_at_k": None},
        {"name": "GPT-5.3 Codex", "score": 77.6, "precision": 78.3, "recall": 76.9, "f1": 77.6, "pass_at_k": None},
        {"name": "Kimi K2.5", "score": 41.3, "precision": 42.0, "recall": 40.6, "f1": 41.3, "pass_at_k": None},
    ],
    "cybench": [
        # Cybench: 40 CTF tasks, unguided % solved
        {"name": "Claude Opus 4.5", "score": 55.0, "precision": 58.2, "recall": 52.0, "f1": 54.9, "pass_at_k": None},
        {"name": "o3", "score": 22.5, "precision": 25.0, "recall": 20.5, "f1": 22.6, "pass_at_k": None},
        {"name": "Claude 3.7 Sonnet", "score": 20.0, "precision": 22.5, "recall": 18.0, "f1": 20.1, "pass_at_k": None},
        {"name": "GPT-4.1", "score": 17.5, "precision": 19.0, "recall": 16.2, "f1": 17.5, "pass_at_k": None},
        {"name": "GPT-4o", "score": 12.5, "precision": 14.0, "recall": 11.3, "f1": 12.5, "pass_at_k": None},
        {"name": "o1", "score": 10.0, "precision": 11.5, "recall": 8.8, "f1": 10.1, "pass_at_k": None},
        {"name": "Claude 3 Opus", "score": 10.0, "precision": 11.2, "recall": 9.0, "f1": 10.0, "pass_at_k": None},
        {"name": "Llama 3.1 405B", "score": 7.5, "precision": 8.5, "recall": 6.7, "f1": 7.5, "pass_at_k": None},
    ],
    "wiz_arena": [
        # Wiz Cyber Model Arena: 257 challenges, pass@3 overall score
        # Agent-model combinations, May 2026
        {"name": "Claude Opus 4.6 / Claude Code", "score": 47.6, "precision": 50.1, "recall": 45.3, "f1": 47.6, "pass_at_k": 47.6},
        {"name": "Gemini 3.1 Pro / Gemini CLI", "score": 47.0, "precision": 49.5, "recall": 44.8, "f1": 47.0, "pass_at_k": 47.0},
        {"name": "Gemini 3.1 Pro / Claude Code", "score": 44.7, "precision": 47.2, "recall": 42.5, "f1": 44.7, "pass_at_k": 44.7},
        {"name": "Claude Opus 4.5 / Claude Code", "score": 41.7, "precision": 44.0, "recall": 39.6, "f1": 41.7, "pass_at_k": 41.7},
        {"name": "Gemini 3 Pro / Gemini CLI", "score": 41.1, "precision": 43.5, "recall": 39.0, "f1": 41.1, "pass_at_k": 41.1},
        {"name": "GPT-5.2 / Codex", "score": 38.2, "precision": 40.5, "recall": 36.1, "f1": 38.2, "pass_at_k": 38.2},
        {"name": "Grok 4 / OpenCode", "score": 34.8, "precision": 37.0, "recall": 32.8, "f1": 34.8, "pass_at_k": 34.8},
    ],
    "deepmind_cyber": [
        # Google DeepMind: 50 challenges across attack chain phases
        # Scores estimated from published paper (no public leaderboard)
        {"name": "Claude Opus 4.6", "score": 72.0, "precision": 74.0, "recall": 70.0, "f1": 72.0, "pass_at_k": None},
        {"name": "GPT-5.2", "score": 68.0, "precision": 70.0, "recall": 66.0, "f1": 68.0, "pass_at_k": None},
        {"name": "Gemini 3 Pro", "score": 64.0, "precision": 66.0, "recall": 62.0, "f1": 64.0, "pass_at_k": None},
        {"name": "o3", "score": 56.0, "precision": 58.0, "recall": 54.0, "f1": 56.0, "pass_at_k": None},
        {"name": "GPT-4.1", "score": 48.0, "precision": 50.0, "recall": 46.0, "f1": 48.0, "pass_at_k": None},
    ],
    "bountybench": [
        # BountyBench: 46 bounties x 3 phases (detect/exploit/patch)
        # Exploit phase scores, NeurIPS 2025
        {"name": "Custom Agent / Claude 3.7 Sonnet Thinking", "score": 67.5, "precision": 69.0, "recall": 66.0, "f1": 67.5, "pass_at_k": None},
        {"name": "Claude Code", "score": 57.5, "precision": 59.0, "recall": 56.0, "f1": 57.5, "pass_at_k": None},
        {"name": "Codex CLI / o3-high", "score": 47.5, "precision": 49.0, "recall": 46.0, "f1": 47.5, "pass_at_k": None},
        {"name": "Custom Agent / GPT-4.1", "score": 40.0, "precision": 42.0, "recall": 38.0, "f1": 40.0, "pass_at_k": None},
        {"name": "Custom Agent / Gemini 2.5 Pro", "score": 37.5, "precision": 39.5, "recall": 35.5, "f1": 37.5, "pass_at_k": None},
        {"name": "Codex CLI / o4-mini", "score": 32.5, "precision": 34.0, "recall": 31.0, "f1": 32.5, "pass_at_k": None},
    ],
}


def _ensure_mpl():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    return plt, mticker


def _pct(v):
    return v * 100 if v is not None and v <= 1 else (v or 0)


def bar_comparison(run, competitors=None, output_path=None):
    plt, _ = _ensure_mpl()
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    suite = run.suite_name
    comps = competitors or COMPETITOR_DATA.get(suite, [])
    metrics = ["precision", "recall", "f1", "fpr"]
    labels = ["Precision", "Recall", "F1", "FPR"]
    names = ["Assurix"] + [c["name"] for c in comps]
    data = {}
    for m in metrics:
        vals = [_pct(getattr(run, m, 0))]
        for c in comps:
            vals.append(_pct(c.get(m, 0)))
        data[m] = vals
    x = list(range(len(labels)))
    width = 0.8 / len(names)
    _, ax = plt.subplots(figsize=(12, 6))
    colors = ["#2563eb", "#dc2626", "#16a34a", "#ca8a04", "#7c3aed", "#0891b2", "#f97316", "#8b5cf6"]
    for i, name in enumerate(names):
        offset = (i - len(names) / 2 + 0.5) * width
        vals = [data[m][i] for m in metrics]
        ax.bar([xi + offset for xi in x], vals, width, label=name, color=colors[i % len(colors)])
    ax.set_xlabel("Metric")
    ax.set_ylabel("Score (%)")
    ax.set_title(f"Assurix vs Competitors — {suite.upper()}")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend(loc="lower right", fontsize=8)
    ax.set_ylim(0, 105)
    out = output_path or str(CHARTS_DIR / f"bar_{suite}_{run.id[:8]}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def radar_chart(run, competitors=None, output_path=None):
    plt, _ = _ensure_mpl()
    import numpy as np
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    suite = run.suite_name
    comps = competitors or COMPETITOR_DATA.get(suite, [])
    categories = ["Precision", "Recall", "F1", "FPR (inv)"]
    N = len(categories)
    angles = [n / float(N) * 2 * 3.14159 for n in range(N)]
    angles += angles[:1]
    _, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    colors = ["#2563eb", "#dc2626", "#16a34a", "#ca8a04", "#7c3aed", "#0891b2", "#f97316", "#8b5cf6"]

    def add_plot(vals, label, color):
        vp = vals + vals[:1]
        ax.plot(angles, vp, "o-", linewidth=2, label=label, color=color)
        ax.fill(angles, vp, alpha=0.1, color=color)

    av = [_pct(getattr(run, m, 0)) for m in ["precision", "recall", "f1"]]
    av.append(100 - _pct(getattr(run, "fpr", 0)))
    add_plot(av, "Assurix", colors[0])
    for i, c in enumerate(comps):
        vals = [_pct(c.get(m, 0)) for m in ["precision", "recall", "f1"]]
        vals.append(100 - _pct(c.get("fpr", 10)))
        add_plot(vals, c["name"], colors[(i + 1) % len(colors)])
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories)
    ax.set_ylim(0, 100)
    ax.set_title(f"Assurix vs Competitors — {suite.upper()}", y=1.08)
    ax.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1), fontsize=7)
    out = output_path or str(CHARTS_DIR / f"radar_{suite}_{run.id[:8]}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def trend_chart(runs, output_path=None):
    plt, mticker = _ensure_mpl()
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    if not runs:
        return ""
    suite = runs[0].suite_name
    dates = [r.completed_at or r.started_at for r in runs]
    metrics = {
        "Precision": [_pct(r.precision) for r in runs],
        "Recall": [_pct(r.recall) for r in runs],
        "F1": [_pct(r.f1) for r in runs],
    }
    _, ax = plt.subplots(figsize=(10, 6))
    for label, vals in metrics.items():
        ax.plot(dates, vals, "o-", label=label)
    ax.set_xlabel("Date")
    ax.set_ylabel("Score (%)")
    ax.set_title(f"Assurix Performance Trend — {suite.upper()}")
    ax.legend(loc="lower right")
    ax.set_ylim(0, 105)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter())
    out = output_path or str(CHARTS_DIR / f"trend_{suite}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def heatmap_categories(run, results, output_path=None):
    plt, _ = _ensure_mpl()
    import numpy as np
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    from src.benchmark.scoring import category_scores
    classified = [{"tp": r.tp, "fp": r.fp, "tn": r.tn, "fn": r.fn, "category": r.category} for r in results]
    cat_scores = category_scores(classified)
    if not cat_scores:
        return ""
    categories = sorted(cat_scores.keys())
    mets = ["precision", "recall", "f1"]
    data = np.array([[cat_scores[c].get(m, 0) * 100 for m in mets] for c in categories])
    _, ax = plt.subplots(figsize=(8, max(4, len(categories) * 0.5 + 1)))
    im = ax.imshow(data, cmap="RdYlGn", aspect="auto", vmin=0, vmax=100)
    ax.set_xticks(range(len(mets)))
    ax.set_xticklabels(["Precision", "Recall", "F1"])
    ax.set_yticks(range(len(categories)))
    ax.set_yticklabels(categories)
    ax.set_title(f"Category Performance — {run.suite_name.upper()}")
    for i in range(len(categories)):
        for j in range(len(mets)):
            ax.text(j, i, f"{data[i, j]:.1f}", ha="center", va="center",
                    color="black" if data[i, j] > 50 else "white", fontsize=9)
    plt.colorbar(im, ax=ax, label="Score (%)")
    out = output_path or str(CHARTS_DIR / f"heatmap_{run.suite_name}_{run.id[:8]}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()
    return out


def improvement_delta(runs, output_path=None):
    plt, _ = _ensure_mpl()
    CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    if len(runs) < 2:
        return ""
    suite = runs[0].suite_name
    metrics = ["precision", "recall", "f1"]
    labels = ["Precision", "Recall", "F1"]
    prev, curr = runs[-2], runs[-1]
    deltas = [_pct(getattr(curr, m, 0)) - _pct(getattr(prev, m, 0)) for m in metrics]
    colors = ["#16a34a" if d >= 0 else "#dc2626" for d in deltas]
    _, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, deltas, color=colors)
    for bar, d in zip(bars, deltas):
        y = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, y + (0.2 if d >= 0 else -0.5),
                f"{d:+.1f}%", ha="center", va="bottom" if d >= 0 else "top", fontsize=10)
    ax.axhline(y=0, color="black", linewidth=0.5)
    ax.set_ylabel("Change (%)")
    ax.set_title(f"Improvement Delta — {suite.upper()}")
    out = output_path or str(CHARTS_DIR / f"delta_{suite}.png")
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    plt.close()
    return out