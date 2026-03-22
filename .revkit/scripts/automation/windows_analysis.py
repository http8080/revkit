#!/usr/bin/env python3
"""Windows PE binary analysis using IDA engine.

Usage:
    python windows_analysis.py sample.exe
    python windows_analysis.py sample.dll --remote http://server:8080
    python windows_analysis.py sample.exe --output pe_report.json
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import argparse
import json
from _helpers import run_rk, start_and_wait, stop_all, setup_cleanup

IMPORT_CATEGORIES = {
    "file": ["CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
             "DeleteFileA", "DeleteFileW", "CopyFileA", "MoveFileA"],
    "registry": ["RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA",
                  "RegSetValueExW", "RegDeleteValueA", "RegCreateKeyExA"],
    "process": ["CreateProcessA", "CreateProcessW", "OpenProcess",
                "TerminateProcess", "CreateRemoteThread", "VirtualAllocEx",
                "WriteProcessMemory", "NtCreateProcess"],
    "network": ["WSAStartup", "connect", "send", "recv", "socket",
                "InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
                "URLDownloadToFileA", "WinHttpOpen"],
    "crypto": ["CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
               "CryptDeriveKey", "BCryptEncrypt", "BCryptDecrypt"],
    "debug": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
              "NtQueryInformationProcess", "OutputDebugStringA"],
    "injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                   "NtMapViewOfSection", "SetWindowsHookExA", "QueueUserAPC"],
}

DANGEROUS_COMBOS = [
    ({"process", "injection"}, "Process injection capability"),
    ({"network", "file"}, "Download and execute capability"),
    ({"network", "crypto"}, "Encrypted C2 communication"),
    ({"registry", "process"}, "Persistence via registry + process creation"),
    ({"debug", "process"}, "Anti-debug with process manipulation"),
]


def analyze_pe(iid: str, remote=None) -> dict:
    """Run Windows PE-specific analysis."""
    results: dict[str, object] = {}

    # Summary
    out, _ = run_rk("ida", "summary", "-i", iid, "--json", remote=remote)
    try:
        results["summary"] = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        results["summary"] = {"raw": out}

    # Image base
    out, _ = run_rk("ida", "imagebase", "-i", iid, "--json", remote=remote)
    results["imagebase"] = out.strip() if out else "unknown"

    # Segments
    out, _ = run_rk("ida", "segments", "-i", iid, "--json",
                     timeout=120, remote=remote)
    try:
        results["segments"] = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        results["segments"] = {"raw": out}

    # Import categorization
    found_categories: dict[str, list[str]] = {}
    for category, apis in IMPORT_CATEGORIES.items():
        for api in apis:
            out, _ = run_rk("ida", "find-func", api, "-i", iid,
                             "--json", remote=remote)
            if out and "no " not in out.lower():
                found_categories.setdefault(category, []).append(api)
    results["imports"] = found_categories

    # Dangerous combos
    present = set(found_categories.keys())
    combos_found = []
    for required, desc in DANGEROUS_COMBOS:
        if required.issubset(present):
            combos_found.append({
                "categories": sorted(required),
                "description": desc,
            })
    results["dangerous_combos"] = combos_found

    # Profile
    out, _ = run_rk("ida", "profile", "-i", iid, "--json",
                     timeout=120, remote=remote)
    try:
        results["profile"] = json.loads(out)
    except (json.JSONDecodeError, TypeError):
        results["profile"] = {"raw": out}

    # Security mechanisms check via strings
    out, _ = run_rk("ida", "strings-xrefs", "-i", iid, "--json",
                     timeout=120, remote=remote)
    strings_text = (out or "").lower()
    security_mechs = {
        "stack_canary": "__security_cookie" in strings_text
                        or "__stack_chk_fail" in strings_text,
        "cfg": "__guard_dispatch" in strings_text
               or "__guard_check" in strings_text,
    }
    results["security_mechanisms"] = security_mechs

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Windows PE analysis (IDA only)")
    parser.add_argument("path", help="PE binary file path (.exe/.dll/.sys)")
    parser.add_argument("--remote", default=None, help="Gateway URL for remote mode")
    parser.add_argument("--output", "-o", default=None, help="Output JSON file")
    args = parser.parse_args()

    setup_cleanup(args.remote)

    print(f"[*] PE: {args.path}")
    iid = start_and_wait("ida", args.path, remote=args.remote)
    print(f"[*] Instance {iid} ready, analyzing PE ...")

    results = analyze_pe(iid, args.remote)

    import_cats = list(results.get("imports", {}).keys())
    combos = results.get("dangerous_combos", [])

    report = {
        "file": args.path,
        "engine": "ida",
        "imagebase": results.get("imagebase"),
        "import_categories": import_cats,
        "dangerous_combos": combos,
        "security_mechanisms": results.get("security_mechanisms"),
        "analysis": results,
    }

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[+] Report saved to {args.output}")
    else:
        print(json.dumps(report, indent=2))

    print(f"[!] Import categories: {', '.join(import_cats) or 'none'}")
    print(f"[!] Dangerous combos: {len(combos)}")
    stop_all("ida", args.remote)
    print("[+] Done.")


if __name__ == "__main__":
    main()
