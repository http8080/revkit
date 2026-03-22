#!/usr/bin/env python3
"""revkit batch analysis + comparison report.

Usage:
    python batch_report.py Samples/ELF/
    python batch_report.py Samples/APK/ --remote http://server:8080
"""

import argparse
import os
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from _helpers import detect_engine, run_rk, start_and_wait, stop_all, setup_cleanup


def find_targets(directory):
    """Find analyzable files in directory."""
    targets = []
    for f in sorted(Path(directory).iterdir()):
        if not f.is_file():
            continue
        try:
            engine = detect_engine(str(f))
            targets.append((str(f), engine))
        except ValueError:
            continue
    return targets


def analyze_single(path, engine, remote=None):
    """Analyze a single file and return result dict."""
    result = {
        "file": os.path.basename(path),
        "engine": engine,
        "size": os.path.getsize(path),
        "status": "ok",
    }
    try:
        start_and_wait(engine, path, fresh=(engine == "jeb"), remote=remote)
        out, _ = run_rk(engine, "summary", remote=remote)
        result["summary"] = out
        stop_all(engine, remote)
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        stop_all(engine, remote)
    return result


def generate_report(results, directory, output_path):
    """Generate batch comparison report."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    ok = sum(1 for r in results if r["status"] == "ok")
    err = sum(1 for r in results if r["status"] == "error")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"# Batch Analysis: {directory}\n\n")
        f.write(f"- **Date**: {datetime.now().isoformat()}\n")
        f.write(f"- **Files**: {len(results)} (OK: {ok}, Error: {err})\n\n")
        f.write("## Comparison Table\n\n")
        f.write("| File | Engine | Size | Status |\n")
        f.write("| --- | --- | --- | --- |\n")
        for r in results:
            size_kb = r["size"] // 1024
            f.write(f"| {r['file']} | {r['engine']} | {size_kb}KB | {r['status']} |\n")
        f.write("\n## Details\n\n")
        for r in results:
            f.write(f"### {r['file']}\n\n")
            if r["status"] == "ok":
                f.write(f"```\n{r.get('summary', 'N/A')}\n```\n\n")
            else:
                f.write(f"**Error**: {r.get('error', 'Unknown')}\n\n")

    print(f"[+] Report: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="revkit batch analysis")
    parser.add_argument("directory", help="Directory to analyze")
    parser.add_argument("--remote", default=None, help="Gateway URL")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[-] Not a directory: {args.directory}")
        sys.exit(1)

    setup_cleanup(args.remote)
    targets = find_targets(args.directory)
    print(f"[*] Found {len(targets)} files")

    results = []
    for i, (path, engine) in enumerate(targets, 1):
        print(f"[*] [{i}/{len(targets)}] {os.path.basename(path)} ({engine})")
        r = analyze_single(path, engine, args.remote)
        results.append(r)

    dirname = Path(args.directory).name
    generate_report(results, args.directory, f"tmp/reports/batch_{dirname}.md")


if __name__ == "__main__":
    main()
