#!/usr/bin/env python3
"""Vulnerability research automation for binaries and APKs.

Usage:
    python vuln_research.py sample.exe
    python vuln_research.py app.apk --remote http://server:8080
    python vuln_research.py sample.dll --output vulns.json
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import argparse
import json
from _helpers import detect_engine, run_rk, start_and_wait, stop_all, setup_cleanup

DANGEROUS_IMPORTS = {
    "HIGH": ["strcpy", "strcat", "gets", "sprintf", "vsprintf", "scanf"],
    "MEDIUM": ["strncpy", "strncat", "snprintf", "memcpy", "memmove"],
    "LOW": ["strlen", "strcmp", "atoi", "atol"],
}

INPUT_HANDLERS = ["recv", "recvfrom", "read", "fread", "ReadFile",
                  "WSARecv", "InternetReadFile"]


def research_ida(iid: str, remote=None) -> list[dict]:
    """IDA vulnerability research."""
    vulns = []

    # Check dangerous imports
    for severity, funcs in DANGEROUS_IMPORTS.items():
        for func_name in funcs:
            out, _ = run_rk("ida", "find-func", func_name, "-i", iid,
                             "--json", remote=remote)
            if out and "no " not in out.lower():
                vulns.append({
                    "type": "dangerous_function",
                    "name": func_name,
                    "severity": severity,
                    "detail": f"Use of {func_name} may lead to buffer overflow",
                })

    # Find input handlers
    for handler in INPUT_HANDLERS:
        out, _ = run_rk("ida", "find-func", handler, "-i", iid,
                         "--json", remote=remote)
        if out and "no " not in out.lower():
            # Trace callgraph from input handler to dangerous functions
            out2, _ = run_rk("ida", "callees", handler, "-i", iid,
                              "--json", remote=remote)
            vulns.append({
                "type": "input_handler",
                "name": handler,
                "severity": "MEDIUM",
                "detail": f"Input handler {handler} found; check data flow",
                "callees": out2[:500] if out2 else None,
            })

    # Format string vulnerabilities
    for fmt_func in ["printf", "fprintf", "syslog", "wprintf"]:
        out, _ = run_rk("ida", "find-func", fmt_func, "-i", iid,
                         "--json", remote=remote)
        if out and "no " not in out.lower():
            vulns.append({
                "type": "format_string",
                "name": fmt_func,
                "severity": "HIGH",
                "detail": f"{fmt_func} usage - check for user-controlled format strings",
            })

    return vulns


def research_jeb(iid: str, remote=None) -> list[dict]:
    """JEB vulnerability research."""
    vulns = []

    # Entry points
    out, _ = run_rk("jeb", "entry-points", "-i", iid, "--json", remote=remote)
    if out and "no " not in out.lower():
        vulns.append({
            "type": "attack_surface",
            "name": "entry_points",
            "severity": "MEDIUM",
            "detail": out[:500],
        })

    # WebView JavaScript enabled
    out, _ = run_rk("jeb", "search-code", "setJavaScriptEnabled", "-i", iid,
                     "--json", remote=remote)
    if out and "no " not in out.lower() and "0 result" not in out.lower():
        vulns.append({
            "type": "webview_js",
            "name": "setJavaScriptEnabled",
            "severity": "HIGH",
            "detail": "WebView with JavaScript enabled - XSS risk",
        })

    # Insecure TrustManager
    out, _ = run_rk("jeb", "search-code", "X509TrustManager", "-i", iid,
                     "--json", remote=remote)
    if out and "no " not in out.lower() and "0 result" not in out.lower():
        vulns.append({
            "type": "ssl_bypass",
            "name": "X509TrustManager",
            "severity": "HIGH",
            "detail": "Custom TrustManager - possible SSL pinning bypass",
        })

    # Deep links
    out, _ = run_rk("jeb", "manifest", "-i", iid, "--json", remote=remote)
    manifest = out or ""
    if "android:scheme" in manifest.lower():
        vulns.append({
            "type": "deeplink",
            "name": "custom_scheme",
            "severity": "MEDIUM",
            "detail": "Deep link handlers found - check input validation",
        })

    # SQL injection
    for api in ["rawQuery", "execSQL"]:
        out, _ = run_rk("jeb", "search-code", api, "-i", iid,
                         "--json", remote=remote)
        if out and "no " not in out.lower() and "0 result" not in out.lower():
            vulns.append({
                "type": "sql_injection",
                "name": api,
                "severity": "HIGH",
                "detail": f"{api} usage - check for SQL injection",
            })

    return vulns


def main():
    parser = argparse.ArgumentParser(description="Vulnerability research automation")
    parser.add_argument("path", help="Binary or APK file path")
    parser.add_argument("--remote", default=None, help="Gateway URL for remote mode")
    parser.add_argument("--output", "-o", default=None, help="Output JSON file")
    args = parser.parse_args()

    setup_cleanup(args.remote)

    engine = detect_engine(args.path)
    print(f"[*] Engine: {engine} | File: {args.path}")

    iid = start_and_wait(engine, args.path, remote=args.remote)
    print(f"[*] Instance {iid} ready, researching vulnerabilities ...")

    if engine == "ida":
        vulns = research_ida(iid, args.remote)
    else:
        vulns = research_jeb(iid, args.remote)

    high = sum(1 for v in vulns if v["severity"] == "HIGH")
    med = sum(1 for v in vulns if v["severity"] == "MEDIUM")
    low = sum(1 for v in vulns if v["severity"] == "LOW")

    report = {
        "file": args.path,
        "engine": engine,
        "total": len(vulns),
        "high": high,
        "medium": med,
        "low": low,
        "vulnerabilities": vulns,
    }

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))

    print(f"[!] Found {len(vulns)} issues: {high} HIGH, {med} MEDIUM, {low} LOW")
    stop_all(engine, args.remote)
    print("[+] Done.")


if __name__ == "__main__":
    main()
