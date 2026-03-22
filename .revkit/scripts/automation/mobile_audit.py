#!/usr/bin/env python3
"""Mobile app audit with OWASP MASVS checks.

Usage:
    python mobile_audit.py app.apk
    python mobile_audit.py app.apk --remote http://server:8080
    python mobile_audit.py app.apk --output masvs_report.json
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import argparse
import json
from _helpers import run_rk, start_and_wait, stop_all, setup_cleanup

MASVS_CHECKS: dict[str, list[dict]] = {
    "STORAGE": [
        {"id": "S-1", "name": "SharedPreferences", "query": "SharedPreferences",
         "severity": "MEDIUM", "desc": "Insecure local storage via SharedPreferences"},
        {"id": "S-2", "name": "SQLiteDatabase", "query": "SQLiteDatabase",
         "severity": "MEDIUM", "desc": "Local database - check encryption"},
        {"id": "S-3", "name": "getExternalStorage", "query": "getExternalStorage",
         "severity": "HIGH", "desc": "External storage usage - world-readable"},
        {"id": "S-4", "name": "MODE_WORLD_READABLE", "query": "MODE_WORLD_READABLE",
         "severity": "HIGH", "desc": "World-readable file mode"},
    ],
    "CRYPTO": [
        {"id": "C-1", "name": "MD5", "query": "MessageDigest.getInstance",
         "severity": "MEDIUM", "desc": "Weak hashing - check for MD5/SHA1"},
        {"id": "C-2", "name": "Hardcoded Key", "query": "SecretKeySpec",
         "severity": "HIGH", "desc": "Hardcoded crypto key possible"},
        {"id": "C-3", "name": "ECB Mode", "query": "AES/ECB",
         "severity": "HIGH", "desc": "ECB mode - insecure block cipher mode"},
        {"id": "C-4", "name": "Random", "query": "java.util.Random",
         "severity": "MEDIUM", "desc": "Weak PRNG - use SecureRandom"},
    ],
    "NETWORK": [
        {"id": "N-1", "name": "HTTP", "query": "http://",
         "severity": "HIGH", "desc": "Cleartext HTTP communication"},
        {"id": "N-2", "name": "TrustManager", "query": "X509TrustManager",
         "severity": "HIGH", "desc": "Custom TrustManager - SSL bypass risk"},
        {"id": "N-3", "name": "HostnameVerifier", "query": "HostnameVerifier",
         "severity": "HIGH", "desc": "Custom HostnameVerifier - MitM risk"},
        {"id": "N-4", "name": "setHostnameVerifier", "query": "ALLOW_ALL",
         "severity": "HIGH", "desc": "Permissive hostname verification"},
    ],
    "PLATFORM": [
        {"id": "P-1", "name": "WebView JS", "query": "setJavaScriptEnabled",
         "severity": "HIGH", "desc": "WebView JavaScript enabled - XSS risk"},
        {"id": "P-2", "name": "addJavascriptInterface",
         "query": "addJavascriptInterface",
         "severity": "HIGH", "desc": "JS bridge - code injection risk (< API 17)"},
        {"id": "P-3", "name": "setAllowFileAccess", "query": "setAllowFileAccess",
         "severity": "MEDIUM", "desc": "WebView file access enabled"},
        {"id": "P-4", "name": "ContentProvider", "query": "ContentProvider",
         "severity": "MEDIUM", "desc": "Content provider - check exported status"},
    ],
    "RESILIENCE": [
        {"id": "R-1", "name": "Root Detection", "query": "su",
         "severity": "LOW", "desc": "Root detection check present"},
        {"id": "R-2", "name": "Frida Detection", "query": "frida",
         "severity": "LOW", "desc": "Frida detection check present"},
        {"id": "R-3", "name": "Debug Detection", "query": "isDebuggerConnected",
         "severity": "LOW", "desc": "Debugger detection present"},
        {"id": "R-4", "name": "Emulator Detection", "query": "Build.FINGERPRINT",
         "severity": "LOW", "desc": "Emulator detection present"},
    ],
}


def run_masvs_checks(iid: str, remote=None) -> dict:
    """Execute all MASVS checks and return results."""
    results: dict[str, list[dict]] = {}
    for category, checks in MASVS_CHECKS.items():
        cat_results = []
        for check in checks:
            out, _ = run_rk("jeb", "search-code", check["query"],
                             "-i", iid, "--json", remote=remote)
            found = bool(out and "no " not in out.lower()
                         and "0 result" not in out.lower())
            cat_results.append({
                "id": check["id"],
                "name": check["name"],
                "severity": check["severity"],
                "description": check["desc"],
                "found": found,
            })
        results[category] = cat_results
    return results


def calculate_protection_level(masvs: dict, resilience_found: int) -> int:
    """Calculate protection level 0-4 based on MASVS findings."""
    high_issues = sum(
        1 for cat in masvs.values()
        for c in cat if c["found"] and c["severity"] == "HIGH"
    )
    if high_issues >= 5:
        return 0
    if high_issues >= 3:
        return 1
    if high_issues >= 1:
        return 2
    if resilience_found >= 2:
        return 4
    return 3


def main():
    parser = argparse.ArgumentParser(
        description="Mobile app audit with OWASP MASVS checks (JEB only)")
    parser.add_argument("path", help="APK file path")
    parser.add_argument("--remote", default=None, help="Gateway URL for remote mode")
    parser.add_argument("--output", "-o", default=None, help="Output JSON file")
    args = parser.parse_args()

    setup_cleanup(args.remote)

    print(f"[*] APK: {args.path}")
    iid = start_and_wait("jeb", args.path, remote=args.remote)
    print(f"[*] Instance {iid} ready, running MASVS audit ...")

    # App info
    remote = args.remote
    info_out, _ = run_rk("jeb", "info", "-i", iid, "--json", remote=remote)
    perms_out, _ = run_rk("jeb", "permissions", "-i", iid, "--json", remote=remote)
    manifest_out, _ = run_rk("jeb", "manifest", "-i", iid, "--json", remote=remote)
    security_out, _ = run_rk("jeb", "security-scan", "-i", iid, "--json",
                              timeout=180, remote=remote)
    entry_out, _ = run_rk("jeb", "entry-points", "-i", iid, "--json", remote=remote)

    # MASVS checks
    masvs = run_masvs_checks(iid, args.remote)

    resilience_found = sum(1 for c in masvs.get("RESILIENCE", []) if c["found"])
    protection = calculate_protection_level(masvs, resilience_found)

    total_issues = sum(1 for cat in masvs.values() for c in cat if c["found"])
    high_count = sum(
        1 for cat in masvs.values()
        for c in cat if c["found"] and c["severity"] == "HIGH"
    )

    report = {
        "file": args.path,
        "engine": "jeb",
        "app_info": info_out,
        "permissions": perms_out,
        "protection_level": protection,
        "protection_label": f"L{protection}",
        "total_findings": total_issues,
        "high_findings": high_count,
        "masvs_results": masvs,
        "security_scan": security_out,
        "entry_points": entry_out,
    }

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))

    print(f"[!] Protection Level: L{protection} | "
          f"Findings: {total_issues} ({high_count} HIGH)")
    stop_all("jeb", args.remote)
    print("[+] Done.")


if __name__ == "__main__":
    main()
