"""HTML and text report generation for benchmark results."""

from __future__ import annotations

from pathlib import Path

from src.benchmark.models import BenchmarkRun, BenchmarkResult
from src.benchmark.scoring import overall_scores, category_scores
from src.benchmark.charts import COMPETITOR_DATA

REPORTS_DIR = Path("data/benchmarks/reports")


class ReportGenerator:

    def __init__(self) -> None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def generate_text(self, run, results):
        classified = [{"tp": r.tp, "fp": r.fp, "tn": r.tn, "fn": r.fn, "category": r.category} for r in results]
        scores = overall_scores(classified)
        cat_scores = category_scores(classified)
        lines = [
            "=" * 60,
            f"  BENCHMARK REPORT \u2014 {run.suite_name.upper()}",
            "=" * 60,
            f"  Run ID:        {run.id}",
            f"  Status:        {run.status}",
            f"  Started:       {run.started_at}",
            f"  Completed:     {run.completed_at}",
            f"  Agent Version: {run.agent_version}",
            "-" * 60,
            "  OVERALL SCORES",
            "-" * 60,
            f"  Precision:  {scores['precision']:.1%}",
            f"  Recall:     {scores['recall']:.1%}",
            f"  F1 Score:   {scores['f1']:.1%}",
            f"  FPR:        {scores['fpr']:.1%}",
            f"  Accuracy:   {scores['accuracy']:.1%}",
        ]
        if "weighted_score" in scores:
            lines.append(f"  Weighted:   {scores['weighted_score']:.1%}")
        if run.pass_at_k_score is not None:
            lines.append(f"  Pass@{run.k_value}:     {run.pass_at_k_score:.1%}")
        lines += [
            f"  TP: {scores['tp']}  FP: {scores['fp']}  TN: {scores['tn']}  FN: {scores['fn']}",
            "-" * 60,
            "  CATEGORY BREAKDOWN",
            "-" * 60,
        ]
        for cat, cs in sorted(cat_scores.items()):
            lines.append(f"  {cat:20s}  P:{cs['precision']:.1%}  R:{cs['recall']:.1%}  F1:{cs['f1']:.1%}  (n={cs['total']})")
        comps = COMPETITOR_DATA.get(run.suite_name, [])
        if comps:
            lines.extend(["-" * 60, "  COMPETITOR COMPARISON", "-" * 60])
            lines.append(f"  {'Model':20s}  {'Score':>6s}  {'P':>6s}  {'R':>6s}  {'F1':>6s}")
            lines.append("  " + "-" * 56)
            af1 = scores["f1"] * 100 if scores["f1"] <= 1 else scores["f1"]
            lines.append(f"  {'Assurix':20s}  {af1:6.1f}  {scores['precision']*100:6.1f}  {scores['recall']*100:6.1f}  {af1:6.1f}")
            for c in comps:
                lines.append(f"  {c['name']:20s}  {c['score']:6.1f}  {c['precision']:6.1f}  {c['recall']:6.1f}  {c['f1']:6.1f}")
        fp_results = [r for r in results if r.fp]
        if fp_results:
            lines.extend(["-" * 60, "  FALSE POSITIVE ANALYSIS", "-" * 60])
            for r in fp_results[:10]:
                lines.append(f"  {r.test_case_id:30s}  category: {r.category}")
                if r.actual:
                    title = r.actual.get("title", "N/A") if isinstance(r.actual, dict) else "N/A"
                    lines.append(f"    Reported: {title}")
        lines.append("=" * 60)
        return "\n".join(lines)

    def generate_html(self, run, results, chart_paths=None):
        classified = [{"tp": r.tp, "fp": r.fp, "tn": r.tn, "fn": r.fn, "category": r.category} for r in results]
        scores = overall_scores(classified)
        cat_scores = category_scores(classified)
        comps = COMPETITOR_DATA.get(run.suite_name, [])
        cat_rows = ""
        for cat, cs in sorted(cat_scores.items()):
            cat_rows += f"<tr><td>{cat}</td><td>{cs['precision']:.1%}</td><td>{cs['recall']:.1%}</td><td>{cs['f1']:.1%}</td><td>{cs['total']}</td></tr>"
        comp_rows = ""
        af1 = scores["f1"] * 100 if scores["f1"] <= 1 else scores["f1"]
        comp_rows += f"<tr style='font-weight:bold;background:#e0e7ff'><td>Assurix</td><td>{af1:.1f}</td><td>{scores['precision']*100:.1f}</td><td>{scores['recall']*100:.1f}</td><td>{af1:.1f}</td></tr>"
        for c in comps:
            comp_rows += f"<tr><td>{c['name']}</td><td>{c['score']:.1f}</td><td>{c['precision']:.1f}</td><td>{c['recall']:.1f}</td><td>{c['f1']:.1f}</td></tr>"
        chart_imgs = ""
        if chart_paths:
            for p in chart_paths:
                chart_imgs += f'<img src="{p}" style="max-width:100%;margin:10px 0;">'
        html = f"""<!DOCTYPE html>
<html><head><title>Benchmark Report \u2014 {run.suite_name}</title>
<style>
body {{ font-family: -apple-system, sans-serif; margin: 20px; background: #f8fafc; }}
h1 {{ color: #1e293b; }} h2 {{ color: #334155; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th, td {{ border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }}
th {{ background: #f1f5f9; }} tr:nth-child(even) {{ background: #f8fafc; }}
.metric {{ display: inline-block; margin: 10px; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
.metric .value {{ font-size: 24px; font-weight: bold; color: #2563eb; }}
.metric .label {{ font-size: 12px; color: #64748b; }}
</style></head>
<body>
<h1>Benchmark Report \u2014 {run.suite_name.upper()}</h1>
<p>Run ID: {run.id} | Status: {run.status} | Agent: {run.agent_version}</p>
<h2>Overall Scores</h2>
<div>
<div class="metric"><div class="value">{scores['precision']:.1%}</div><div class="label">Precision</div></div>
<div class="metric"><div class="value">{scores['recall']:.1%}</div><div class="label">Recall</div></div>
<div class="metric"><div class="value">{scores['f1']:.1%}</div><div class="label">F1 Score</div></div>
<div class="metric"><div class="value">{scores['fpr']:.1%}</div><div class="label">FPR</div></div>
<div class="metric"><div class="value">{scores['accuracy']:.1%}</div><div class="label">Accuracy</div></div>
{f'<div class="metric"><div class="value">{scores["weighted_score"]:.1%}</div><div class="label">Weighted</div></div>' if 'weighted_score' in scores else ''}
{f'<div class="metric"><div class="value">{run.pass_at_k_score:.1%}</div><div class="label">Pass@{run.k_value}</div></div>' if run.pass_at_k_score is not None else ''}
</div>
<p>TP: {scores['tp']} | FP: {scores['fp']} | TN: {scores['tn']} | FN: {scores['fn']} | Total: {scores['total']}</p>
<h2>Category Breakdown</h2>
<table><tr><th>Category</th><th>Precision</th><th>Recall</th><th>F1</th><th>Cases</th></tr>{cat_rows}</table>
<h2>Competitor Comparison</h2>
<table><tr><th>Model</th><th>Score</th><th>Precision</th><th>Recall</th><th>F1</th></tr>{comp_rows}</table>
{chart_imgs}
</body></html>"""
        out = str(REPORTS_DIR / f"report_{run.suite_name}_{run.id[:8]}.html")
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)
        return out
