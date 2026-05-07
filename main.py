import json
import os
import sys
import argparse
from datetime import datetime
from collections import Counter

ROOT = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(ROOT, "scripts")
RESULTS = os.path.join(ROOT, "results")
sys.path.insert(0, SCRIPTS)
from sensitivity_scorer import process_logs, classify
os.makedirs(RESULTS, exist_ok=True)

def aggregate(results: list) -> dict:
    scores = [r["analysis"]["score"] for r in results]
    levels = [r["analysis"]["level"] for r in results]
    total = len(scores)

    attr_counts = Counter()
    for r in results:
        a = r["analysis"]
        for attr in (a["direct_identifiers"] + a["quasi_identifiers"]):
            attr_counts[attr] += 1

    risk_dist = {
        "LOW": levels.count("LOW"),
        "MEDIUM": levels.count("MEDIUM"),
        "HIGH": levels.count("HIGH"),
        "CRITICAL": levels.count("CRITICAL"),
    }
    hc = risk_dist["HIGH"] + risk_dist["CRITICAL"]
    avg = round(sum(scores) / total, 2)

    return {
        "results": results,
        "total": total,
        "average_score": avg,
        "max_score": round(max(scores), 2),
        "overall_level": classify(avg),
        "high_crit_pct": round(hc / total * 100, 1),
        "critical_pct": round(risk_dist["CRITICAL"] / total * 100, 1),
        "risk_dist": risk_dist,
        "top_attrs": [(a, c, round(c / total * 100, 1)) for a, c in attr_counts.most_common(5)],
    }

def format_report(file_path: str, s: dict) -> str:
    w = 62
    lines = []

    lines.append("=" * w)
    lines.append("  PRIVACY RISK ASSESSMENT REPORT")
    lines.append(f"  File     : {os.path.basename(file_path)}")
    lines.append(f"  Lines    : {s['total']:,}")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * w)
    lines.append("")
    lines.append("  SENSITIVITY SCORING")
    lines.append("  " + "─" * (w - 2))
    lines.append(f"  Average score       : {s['average_score']}  [{s['overall_level']}]")
    lines.append(f"  Max score           : {s['max_score']}")
    lines.append(f"  High/Critical lines : {s['high_crit_pct']}%")
    lines.append(f"  Critical lines      : {s['critical_pct']}%")
    lines.append("")
    lines.append("  Risk distribution:")
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        count = s["risk_dist"][level]
        pct   = round(count / s["total"] * 100, 1)
        bar   = "█" * int(pct / 3)
        lines.append(f"    {level:>8} : {count:>5} ({pct:>5.1f}%) {bar}")
    lines.append("")
    lines.append("  Top sensitive attributes:")
    for attr, count, pct in s["top_attrs"]:
        lines.append(f"    {attr:<20} {count:>5} lines ({pct}%)")
    lines.append("")
    lines.append("=" * w)
    return "\n".join(lines)

def save_outputs(file_path: str, s: dict, report: str):
    base = os.path.splitext(os.path.basename(file_path))[0]

    report_path = os.path.join(RESULTS, f"{base}_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    results_path = os.path.join(RESULTS, f"{base}_results.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(s["results"], f, indent=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser( description="Privacy Risk Assessment Tool for Software Logs")
    parser.add_argument("log_file", help="Path to structured CSV log file")
    args = parser.parse_args()

    if not os.path.exists(args.log_file):
        print(f"ERROR: File not found: {args.log_file}")
        sys.exit(1)

    results = process_logs(args.log_file)

    s = aggregate(results)
    rep = format_report(args.log_file, s)
    save_outputs(args.log_file, s, rep)