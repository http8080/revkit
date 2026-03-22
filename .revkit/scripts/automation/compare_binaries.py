#!/usr/bin/env python3
"""Compare two binaries side-by-side using revkit IDA engine.

Usage:
    python compare_binaries.py file1.exe file2.elf
    python compare_binaries.py file1.exe file2.dll --remote http://server:8080
    python compare_binaries.py a.exe b.exe --output comparison.md
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import argparse
import json
from _helpers import detect_engine, run_rk, start_and_wait, stop_all, setup_cleanup


def build_summary(label: str, engine: str, iid: str, remote=None) -> dict:
    """Collect summary data for one binary."""
    info = {"label": label}
    out, _ = run_rk(engine, "summary", "-i", iid, "--json", remote=remote)
    try:
        info["summary"] = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        info["summary"] = {"raw": out}
    return info


def run_diff(engine: str, iid1: str, iid2: str, remote=None) -> dict:
    """Run diff and code-diff between two instances."""
    results = {}
    out, _ = run_rk(engine, "diff", "-i", iid1,
                     "--target", iid2, "--json",
                     timeout=120, remote=remote)
    try:
        results["diff"] = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        results["diff"] = {"raw": out}

    out, _ = run_rk(engine, "code-diff", "-i", iid1,
                     "--target", iid2, "--json",
                     timeout=120, remote=remote)
    try:
        results["code_diff"] = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        results["code_diff"] = {"raw": out}
    return results


def generate_markdown(info1: dict, info2: dict, diffs: dict) -> str:
    """Generate comparison table in markdown."""
    lines = ["# Binary Comparison Report", ""]
    lines.append("## Targets")
    lines.append(f"- **A**: {info1['label']}")
    lines.append(f"- **B**: {info2['label']}")
    lines.append("")

    s1 = info1.get("summary", {})
    s2 = info2.get("summary", {})
    lines.append("## Summary Comparison")
    lines.append("")
    lines.append("| Attribute | Binary A | Binary B |")
    lines.append("|-----------|----------|----------|")
    all_keys = sorted(set(list(s1.keys()) + list(s2.keys())))
    for k in all_keys:
        if k == "raw":
            continue
        lines.append(f"| {k} | {s1.get(k, '-')} | {s2.get(k, '-')} |")
    lines.append("")

    lines.append("## Diff Results")
    lines.append("```json")
    lines.append(json.dumps(diffs.get("diff", {}), indent=2, default=str))
    lines.append("```")
    lines.append("")
    lines.append("## Code Diff")
    lines.append("```json")
    lines.append(json.dumps(diffs.get("code_diff", {}), indent=2, default=str))
    lines.append("```")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Compare two binaries with revkit")
    parser.add_argument("file1", help="First binary path")
    parser.add_argument("file2", help="Second binary path")
    parser.add_argument("--remote", default=None, help="Gateway URL for remote mode")
    parser.add_argument("--output", "-o", default=None, help="Output markdown file")
    args = parser.parse_args()

    setup_cleanup(args.remote)

    engine = "ida"
    print(f"[*] Starting analysis of {args.file1} ...")
    iid1 = start_and_wait(engine, args.file1, remote=args.remote)
    print(f"[*] Starting analysis of {args.file2} ...")
    iid2 = start_and_wait(engine, args.file2, remote=args.remote)

    print("[*] Collecting summaries ...")
    info1 = build_summary(args.file1, engine, iid1, args.remote)
    info2 = build_summary(args.file2, engine, iid2, args.remote)

    print("[*] Running diff ...")
    diffs = run_diff(engine, iid1, iid2, args.remote)

    report = generate_markdown(info1, info2, diffs)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"[+] Report saved to {args.output}")
    else:
        print(report)

    print("[*] Stopping instances ...")
    stop_all(engine, args.remote)
    print("[+] Done.")


if __name__ == "__main__":
    main()
