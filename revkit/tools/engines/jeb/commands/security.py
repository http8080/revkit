"""Security commands -- entry points analysis, security scan."""

import logging

from ..core import _rpc_call, _opt
from .analysis import _output_text
from ...base import CmdContext

log = logging.getLogger(__name__)


def cmd_entry_points(ctx: CmdContext):
    """#49: Analyze exported components, deeplinks, JS interfaces."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_entry_points: requesting entry points")
    r = _rpc_call(args, config, "entry_points")
    if not r:
        log.warning("cmd_entry_points: RPC returned None")
        return
    log.debug("cmd_entry_points: exported=%d deeplinks=%d js_interfaces=%d",
              len(r.get('exported_components', [])), len(r.get('deeplinks', [])),
              len(r.get('js_interfaces', [])))
    lines = ["Attack Surface Summary:"]

    # Exported components
    exported = r.get("exported_components", [])
    lines.append(f"\n  Exported Components ({len(exported)}):")
    for comp in exported:
        tag = comp.get("type", "?")
        name = comp.get("name", "?")
        lines.append(f"    [{tag}] {name}")
        intents = comp.get("intent_filters", [])
        for intent in intents:
            lines.append(f"      action: {intent.get('action', '')}")
            if intent.get("data"):
                lines.append(f"      data: {intent['data']}")

    # Deeplinks
    deeplinks = r.get("deeplinks", [])
    if deeplinks:
        lines.append(f"\n  Deeplinks ({len(deeplinks)}):")
        for dl in deeplinks:
            lines.append(f"    {dl.get('scheme', '')}://{dl.get('host', '')}{dl.get('path', '')}")
            lines.append(f"      -> {dl.get('activity', '')}")

    # JS Interfaces
    js_interfaces = r.get("js_interfaces", [])
    if js_interfaces:
        lines.append(f"\n  JavaScript Interfaces ({len(js_interfaces)}):")
        for jsi in js_interfaces:
            lines.append(f"    {jsi.get('class', '')} -> {jsi.get('method', '')}")

    # Content providers
    providers = r.get("content_providers", [])
    if providers:
        lines.append(f"\n  Content Providers ({len(providers)}):")
        for p in providers:
            lines.append(f"    {p.get('name', '')} (exported={p.get('exported', False)})")

    # Dynamic receivers
    dyn_receivers = r.get("dynamic_receivers", [])
    if dyn_receivers:
        lines.append(f"\n  Dynamic Receivers ({len(dyn_receivers)}):")
        for dr in dyn_receivers:
            lines.append(f"    {dr.get('class', '')} <- {dr.get('caller', '')}")

    text = "\n".join(lines)
    _output_text(args, config, text)


def cmd_security_scan(ctx: CmdContext):
    """#50: Automated security issue detection."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_security_scan: requesting scan")
    r = _rpc_call(args, config, "security_scan")
    if not r:
        log.warning("cmd_security_scan: RPC returned None")
        return
    lines = ["Security Scan Results:"]
    total_issues = 0

    categories = [
        ("crypto_issues", "Crypto Issues"),
        ("hardcoded_secrets", "Hardcoded Secrets"),
        ("dangerous_permissions", "Dangerous Permissions"),
        ("insecure_storage", "Insecure Storage"),
        ("network_issues", "Network Issues"),
        ("webview_issues", "WebView Issues"),
    ]
    for key, label in categories:
        items = r.get(key, [])
        if items:
            total_issues += len(items)
            lines.append(f"\n  {label} ({len(items)}):")
            for item in items:
                severity = item.get("severity", "INFO")
                desc = item.get("description", "")
                loc = item.get("location", "")
                lines.append(f"    [{severity}] {desc}")
                if loc:
                    lines.append(f"           @ {loc}")

    log.debug("cmd_security_scan: found %d total issues", total_issues)
    if total_issues == 0:
        lines.append("  No issues detected")
    else:
        lines.append(f"\n  Total: {total_issues} issue(s)")

    text = "\n".join(lines)
    _output_text(args, config, text)
