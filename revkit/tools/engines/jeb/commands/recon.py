"""Recon commands -- APK reconnaissance (summary, permissions, components, etc.)."""

import json
import logging
import os

from ..core import (
    _rpc_call, _opt, _log_ok, _log_err, _log_info, _log_warn,
    _truncate, _save_local, _is_md_out, _maybe_output_param,
    _md_summary, _build_params,
)
from .analysis import _output_text
from ...base import CmdContext

log = logging.getLogger(__name__)


def _extract_pkg_activity(summary):
    """Extract package name and main activity from summary response."""
    apk_info = summary.get("apk_info") or {}
    pkg = apk_info.get("package") or summary.get("package_name")
    act = apk_info.get("main_activity") or summary.get("main_activity")
    return pkg, act


def cmd_summary(ctx: CmdContext):
    """Display binary overview (classes, methods, strings, etc.)."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_summary: requesting summary")
    md_out = _is_md_out(args)
    r = _rpc_call(args, config, "summary")
    if not r:
        log.warning("cmd_summary: RPC returned None")
        return
    log.debug("cmd_summary: classes=%s methods=%s", r.get('class_count'), r.get('method_count'))
    if md_out:
        _save_local(args.out, _md_summary(r))
        return
    for key, label in [("binary", "Binary"), ("jeb_version", "JEB"),
                        ("class_count", "Classes"), ("method_count", "Methods"),
                        ("native_method_count", "Native"),
                        ("string_count", "Strings"), ("dex_count", "DEX files"),
                        ("permission_count", "Permissions")]:
        print(f"  {label + ':':<13} {r.get(key, '?')}")
    apk_info = r.get("apk_info") or {}
    pkg, act = _extract_pkg_activity(r)
    if pkg:
        print(f"  Package:     {pkg}")
    if act:
        print(f"  Activity:    {act}")
    if apk_info.get("min_sdk"):
        print(f"  Min SDK:     {apk_info['min_sdk']}")
    if apk_info.get("target_sdk"):
        print(f"  Target SDK:  {apk_info['target_sdk']}")
    if r.get("top_packages"):
        print()
        print("  Top Packages:")
        for pkg in r["top_packages"]:
            print(f"    {pkg['name']:<50}  {pkg['count']} classes")
    sample = r.get("sample_strings") or r.get("strings_sample") or []
    if sample:
        print()
        print(f"  Strings (first {len(sample)}):")
        for s in sample:
            val = s.get("value", s) if isinstance(s, dict) else s
            print(f"    {_truncate(str(val), 60)}")


def cmd_permissions(ctx: CmdContext):
    """#9: List uses-permission from AndroidManifest."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_permissions: requesting manifest")
    r = _rpc_call(args, config, "get_manifest")
    if not r:
        return
    content = r.get("xml") or r.get("manifest", "")
    if not content:
        _log_err("No manifest available")
        return
    import re
    perms = re.findall(r'<uses-permission[^>]*android:name="([^"]*)"', content)
    log.debug("cmd_permissions: found %d permissions", len(perms))
    if _opt(args, 'json_output', False):
        print(json.dumps({"permissions": perms, "count": len(perms)}, indent=2))
        return
    print(f"Permissions ({len(perms)}):")
    for p in perms:
        # Categorize dangerous permissions
        dangerous = any(d in p for d in [
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_PHONE", "CALL_LOG",
            "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "READ_EXTERNAL", "WRITE_EXTERNAL", "READ_SMS", "SEND_SMS",
            "READ_CALENDAR", "WRITE_CALENDAR", "BODY_SENSORS",
        ])
        marker = " [DANGEROUS]" if dangerous else ""
        print(f"  {p}{marker}")


def cmd_components(ctx: CmdContext):
    """#10: List activities, services, receivers, providers with exported status."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_components: type=%s", _opt(args, 'type'))
    r = _rpc_call(args, config, "get_manifest")
    if not r:
        return
    content = r.get("xml") or r.get("manifest", "")
    if not content:
        _log_err("No manifest available")
        return
    import re
    comp_types = ["activity", "service", "receiver", "provider"]
    filter_type = _opt(args, 'type')
    if filter_type:
        comp_types = [t for t in comp_types if t == filter_type.lower()]

    all_components = []
    for tag in comp_types:
        # Match both self-closing and paired tags
        patterns = [
            r'<' + tag + r'\b([^>]*)/>',
            r'<' + tag + r'\b([^>]*)>',
        ]
        for pat in patterns:
            for m in re.finditer(pat, content):
                attrs = m.group(1)
                name_m = re.search(r'android:name="([^"]*)"', attrs)
                exported_m = re.search(r'android:exported="([^"]*)"', attrs)
                name = name_m.group(1) if name_m else "?"
                exported = exported_m.group(1) if exported_m else "unset"
                entry = {"type": tag, "name": name, "exported": exported}
                # Deduplicate
                if not any(c["name"] == name and c["type"] == tag for c in all_components):
                    all_components.append(entry)

    if _opt(args, 'json_output', False):
        print(json.dumps({"components": all_components, "count": len(all_components)}, indent=2))
        return

    for tag in comp_types:
        items = [c for c in all_components if c["type"] == tag]
        if not items:
            continue
        print(f"\n{tag.upper()}S ({len(items)}):")
        for c in items:
            exp = c["exported"]
            marker = ""
            if exp == "true":
                marker = " [EXPORTED]"
            elif exp == "unset":
                marker = " [exported=unset]"
            print(f"  {c['name']}{marker}")


def cmd_info(ctx: CmdContext):
    """#17: APK metadata — signature, SDK versions, certificate, build info."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_info: requesting info")
    r = _rpc_call(args, config, "info")
    if not r:
        return
    if _opt(args, 'json_output', False):
        print(json.dumps(r, indent=2, default=str))
        return
    for key, label in [("package", "Package"), ("app_name", "App Name"),
                        ("main_activity", "Main Activity"),
                        ("version_code", "Version Code"),
                        ("version_name", "Version Name"),
                        ("min_sdk", "Min SDK"), ("target_sdk", "Target SDK"),
                        ("compile_sdk", "Compile SDK"),
                        ("platform_build", "Platform Build"),
                        ("dex_count", "DEX Files"),
                        ("jeb_version", "JEB Version")]:
        val = r.get(key)
        if val is not None and val != "":
            print(f"  {label + ':':<16} {val}")

    perms = r.get("permissions", [])
    if perms:
        print(f"\n  Permissions ({len(perms)}):")
        for p in perms:
            print(f"    {p}")

    certs = r.get("certificates", [])
    if certs:
        print(f"\n  Certificates ({len(certs)}):")
        for c in certs:
            for k in ["subject", "issuer", "serial", "sig_algorithm", "not_before", "not_after"]:
                if c.get(k):
                    print(f"    {k}: {c[k]}")
            print()


def cmd_main_activity(ctx: CmdContext):
    """Show the main activity class."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_main_activity: requesting main activity")
    r = _rpc_call(args, config, "get_main_activity")
    if not r:
        return
    activity = r.get("main_activity") or r.get("name", "")
    print(f"  Main Activity: {activity}")
    sig = r.get("sig", "")
    if sig:
        print(f"  Signature:     {sig}")


def cmd_app_class(ctx: CmdContext):
    """Show the Application class."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_app_class: requesting app class")
    r = _rpc_call(args, config, "get_app_class")
    if not r:
        return
    classes = r.get("classes", [])
    # Filter for application-type classes
    app_classes = [c for c in classes if c.get("type") == "application"]
    if app_classes:
        c = app_classes[0]
        print(f"  Application class: {c.get('sig', '')}")
        print(f"  Superclass:        {c.get('superclass', '')}")
    else:
        _log_info("No custom Application class found")
    # Also show activities if present
    activities = [c for c in classes if c.get("type") == "activity"]
    if activities:
        print(f"  Activities ({len(activities)}):")
        for a in activities[:10]:
            print(f"    {a.get('sig', '')}")


def cmd_resources(ctx: CmdContext):
    """List resource file names in the APK."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_resources: requesting resources")
    r = _rpc_call(args, config, "get_resources")
    if not r:
        log.warning("cmd_resources: RPC returned None")
        return
    log.debug("cmd_resources: got %d resources", r.get('total', 0))
    lines = [f"Resources ({r.get('total', 0)}):"]
    for res in r.get("data") or r.get("resources", []):
        if isinstance(res, dict):
            # #16: show file size
            size = res.get('size', 0)
            if size >= 1024 * 1024:
                size_str = f"{size / (1024*1024):.1f}MB"
            elif size >= 1024:
                size_str = f"{size / 1024:.1f}KB"
            elif size > 0:
                size_str = f"{size}B"
            else:
                size_str = ""
            lines.append(f"  {res.get('path', ''):<30}  [{res.get('type', '')}]  {size_str}")
        else:
            lines.append(f"  {res}")
    text = "\n".join(lines)
    _output_text(args, config, text)


def cmd_resource(ctx: CmdContext):
    """Retrieve content of a specific resource file."""
    import base64
    args, config = ctx.args, ctx.config
    log.debug("cmd_resource: path=%s", args.path)
    p = {"path": args.path}
    r = _rpc_call(args, config, "get_resource", p)
    if not r:
        return
    # Server returns content_b64 (base64-encoded bytes)
    content_b64 = r.get("content_b64", "")
    if content_b64:
        raw = base64.b64decode(content_b64)
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = raw.decode("utf-8", errors="replace")
    else:
        content = r.get("content", "")
    saved_to = r.get("saved_to")
    if saved_to:
        _log_ok(f"Saved to: {saved_to}")
    else:
        _output_text(args, config, content)


def cmd_manifest(ctx: CmdContext):
    """Retrieve AndroidManifest.xml content."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_manifest: component=%s", _opt(args, 'component'))
    r = _rpc_call(args, config, "get_manifest")
    if not r:
        return
    content = r.get("xml") or r.get("manifest", "")
    # #18: --component filter
    component = _opt(args, 'component')
    if component and content:
        import re
        known_tags = ["activity", "service", "receiver", "provider",
                      "uses-permission", "meta-data", "intent-filter"]
        found = []
        if component.lower() in known_tags:
            # Filter by tag name (e.g., --component activity)
            tag = component.lower()
            pattern = r'<' + tag + r'\b[^>]*/>'
            found.extend(re.findall(pattern, content, re.DOTALL))
            pattern = r'<' + tag + r'\b[^>]*>.*?</' + tag + r'>'
            found.extend(re.findall(pattern, content, re.DOTALL))
        else:
            # Filter by component name (e.g., --component LoginActivity)
            for tag in known_tags:
                pattern = r'<' + tag + r'[^>]*' + re.escape(component) + r'[^>]*/>'
                found.extend(re.findall(pattern, content, re.DOTALL))
                pattern = r'<' + tag + r'[^>]*' + re.escape(component) + r'[^>]*>.*?</' + tag + r'>'
                found.extend(re.findall(pattern, content, re.DOTALL))
        if found:
            content = "\n\n".join(found)
        else:
            _log_warn(f"Component '{component}' not found in manifest")
    _output_text(args, config, content)
