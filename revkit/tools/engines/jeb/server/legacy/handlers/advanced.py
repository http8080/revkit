# -*- coding: utf-8 -*-
"""Advanced handlers -- auto-rename, info, summary, exec, strings_xrefs, etc.

Runs under Jython 2.7 (Python 2 syntax). No f-strings, no type hints.
"""

import json

from .helpers import (
    _to_str, _require_apk, _require_param, _read_manifest_text,
    _get_decompiler, _FRAMEWORK_PREFIXES, _OBFUSCATED_NAME_MAX_LEN,
)


def _handle_auto_rename(self, params):
    """Heuristic auto-rename based on string references.

    Looks for classes/methods with obfuscated names that reference
    distinctive strings, and suggests/applies meaningful names.
    """
    from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType

    max_classes = params.get("max_classes", 100)
    # Support both "dry_run" and "apply" params (CLI sends "apply")
    if "apply" in params:
        dry_run = not params["apply"]
    else:
        dry_run = params.get("dry_run", True)

    renames = []
    processed = 0

    for dex in self.dex_units:
        refmgr = dex.getReferenceManager()

        for cls in dex.getClasses():
            if processed >= max_classes:
                break

            sig = cls.getSignature(True)
            name = cls.getName(True)

            # Skip framework, already-renamed, or non-obfuscated classes
            if any(sig.startswith(p) for p in _FRAMEWORK_PREFIXES):
                continue
            if cls.isRenamed():
                continue
            # Heuristic: obfuscated names are typically 1-3 chars
            short_name = name.split("/")[-1] if "/" in name else name
            if short_name.endswith(";"):
                short_name = short_name[:-1]
            if len(short_name) > _OBFUSCATED_NAME_MAX_LEN:
                continue

            processed += 1

            # Look for string references in methods of this class
            best_string = None
            for m in cls.getMethods():
                if not m.isInternal():
                    continue
                idx = m.getIndex()
                if refmgr:
                    try:
                        ref_map = refmgr.getReferences(DexPoolType.METHOD, idx)
                        if ref_map:
                            for e in ref_map.entrySet():
                                pool = e.getKey()
                                if str(pool) == str(DexPoolType.STRING):
                                    for str_idx in e.getValue():
                                        s = dex.getString(str_idx)
                                        if s:
                                            val = s.getValue()
                                            # Pick strings that look like meaningful identifiers
                                            if val and len(val) >= 4 and len(val) <= 40:
                                                if not best_string or len(val) > len(best_string):
                                                    best_string = val
                    except Exception:
                        pass

            if best_string:
                # Sanitize: only alphanumeric + underscore
                new_name = "".join(
                    ch if (ch.isalnum() or ch == "_")
                    else "_" if ch in (" ", "-", ".")
                    else ""
                    for ch in best_string
                )
                if not new_name or not new_name[0].isalpha():
                    new_name = "C_" + new_name
                new_name = new_name[:40]

                old_name = cls.getName(True)
                renames.append({
                    "sig": sig,
                    "old_name": old_name,
                    "new_name": new_name,
                    "reason": best_string,
                })

                if not dry_run:
                    cls.setName(new_name)
                    dex.notifyGenericChange()

    applied = len(renames) if not dry_run else 0
    return {
        "total": len(renames),
        "dry_run": dry_run,
        "applied": applied,
        "suggestions": renames,
    }


def _handle_info(self, params):
    """APK metadata -- signatures, SDK, build tools, certificate info."""
    result = {}

    if self.apk_unit:
        apk = self.apk_unit
        result["package"] = _to_str(apk.getPackageName()) if apk.getPackageName() else ""
        result["app_name"] = _to_str(apk.getApplicationName()) if apk.getApplicationName() else ""
        result["main_activity"] = _to_str(apk.getMainActivity()) if apk.getMainActivity() else ""

        for key, method_name in [("min_sdk", "getMinSdkVersion"),
                                  ("target_sdk", "getTargetSdkVersion"),
                                  ("version_code", "getVersionCode"),
                                  ("version_name", "getVersionName")]:
            try:
                val = getattr(apk, method_name)()
                if val is not None:
                    result[key] = _to_str(val) if isinstance(val, type(u"")) or isinstance(val, str) else val
            except Exception:
                pass

    # Certificate info
    certs = []
    if self.apk_unit:
        try:
            for cert in self.apk_unit.getCertificates():
                cert_info = {}
                try:
                    cert_info["subject"] = _to_str(cert.getSubjectDN())
                except Exception:
                    pass
                try:
                    cert_info["issuer"] = _to_str(cert.getIssuerDN())
                except Exception:
                    pass
                try:
                    cert_info["serial"] = _to_str(cert.getSerialNumber())
                except Exception:
                    pass
                try:
                    cert_info["not_before"] = _to_str(cert.getNotBefore())
                except Exception:
                    pass
                try:
                    cert_info["not_after"] = _to_str(cert.getNotAfter())
                except Exception:
                    pass
                try:
                    cert_info["sig_algorithm"] = _to_str(cert.getSigAlgName())
                except Exception:
                    pass
                certs.append(cert_info)
        except Exception:
            pass
    result["certificates"] = certs

    # Permissions from manifest
    permissions = []
    if self.apk_unit:
        try:
            xml = _read_manifest_text(self)
            if xml:
                import re
                permissions = re.findall(
                    r'<uses-permission[^>]*android:name="([^"]*)"', xml)
        except Exception:
            pass
    result["permissions"] = permissions

    # DEX info
    result["dex_count"] = len(self.dex_units)
    dex_infos = []
    for dex in self.dex_units:
        dex_infos.append({
            "class_count": dex.getClasses().size(),
            "string_count": dex.getStrings().size(),
        })
    result["dex_files"] = dex_infos

    # Manifest raw attributes
    if self.apk_unit:
        try:
            xml = _read_manifest_text(self)
            if xml:
                import re
                m = re.search(r'android:compileSdkVersion="(\d+)"', xml)
                if m:
                    result["compile_sdk"] = int(m.group(1))
                m = re.search(r'platformBuildVersionName="([^"]*)"', xml)
                if m:
                    result["platform_build"] = m.group(1)
        except Exception:
            pass

    try:
        from com.pnfsoftware.jeb.core import Version
        result["jeb_version"] = _to_str(Version.software)
    except Exception:
        pass

    return result


def _handle_summary(self, params):
    """Comprehensive overview of the loaded binary."""
    string_count = params.get("string_count", 20)

    class_count = 0
    method_count = 0
    field_count = 0
    internal_method_count = 0
    native_method_count = 0
    total_strings = 0
    sample_strings = []

    for dex in self.dex_units:
        classes = dex.getClasses()
        class_count += classes.size()
        for cls in classes:
            methods = cls.getMethods()
            for m in methods:
                method_count += 1
                if m.isInternal():
                    internal_method_count += 1
                    data = m.getData()
                    if data and (data.getAccessFlags() & 0x0100):
                        native_method_count += 1
            field_count += cls.getFields().size()

        strings = dex.getStrings()
        total_strings += strings.size()
        if len(sample_strings) < string_count:
            for s in strings:
                if len(sample_strings) >= string_count:
                    break
                sample_strings.append(s.getValue())

    # APK info
    apk_info = None
    binary_name = ""
    if self.apk_unit:
        apk = self.apk_unit
        binary_name = _to_str(apk.getName())

        def _apk_str(getter):
            val = getter()
            return _to_str(val) if val else None

        apk_info = {
            "package": _apk_str(apk.getPackageName),
            "main_activity": _apk_str(apk.getMainActivity),
            "app_name": _apk_str(apk.getApplicationName),
        }
        for key, method_name in [("min_sdk", "getMinSdkVersion"),
                                  ("target_sdk", "getTargetSdkVersion")]:
            try:
                apk_info[key] = getattr(apk, method_name)()
            except Exception:
                pass

    # Permissions from manifest
    permissions = []
    if self.apk_unit:
        try:
            xml = _read_manifest_text(self)
            if xml:
                import re
                permissions = re.findall(
                    r'<uses-permission[^>]*android:name="([^"]*)"', xml)
        except Exception:
            pass

    jeb_version = ""
    try:
        from com.pnfsoftware.jeb.core import Version
        jeb_version = _to_str(Version.software)
    except Exception:
        pass

    return {
        "binary": binary_name,
        "jeb_version": jeb_version,
        "class_count": class_count,
        "method_count": method_count,
        "internal_method_count": internal_method_count,
        "native_method_count": native_method_count,
        "field_count": field_count,
        "string_count": total_strings,
        "dex_count": len(self.dex_units),
        "apk_info": apk_info,
        "sample_strings": sample_strings,
        "permission_count": len(permissions),
        "permissions": permissions,
    }


def _handle_exec(self, params):
    """Execute arbitrary Jython code.

    Requires security.exec_enabled=true in config.
    Variables persist across calls (shell REPL support).
    JEB context (ctx, prj, dex_units, apk_unit, server) is always available
    and protected from accidental overwrite.
    """
    if not self.config.get("security", {}).get("exec_enabled", False):
        raise self.RpcError(
            "EXEC_DISABLED",
            "exec is disabled",
            "Set security.exec_enabled=true in config.json")

    code = params.get("code", "")
    import sys
    from StringIO import StringIO

    # Initialize shared state on first call
    if not hasattr(self, "_exec_globals"):
        self._exec_globals = {}
    if not hasattr(self, "_exec_locals"):
        self._exec_locals = {}

    # JEB reserved names — always fresh in globals, cleared from locals
    _jeb_reserved = {
        "ctx": self.ctx,
        "prj": self.prj,
        "dex_units": self.dex_units,
        "apk_unit": self.apk_unit,
        "server": self,
    }
    self._exec_globals.update(_jeb_reserved)
    for k in _jeb_reserved:
        self._exec_locals.pop(k, None)

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    out_buf = StringIO()
    err_buf = StringIO()
    try:
        sys.stdout = out_buf
        sys.stderr = err_buf
        try:
            exec(code, self._exec_globals, self._exec_locals)
        except SystemExit:
            raise
        except:
            # bare except needed in Jython to catch Java Throwable
            import traceback
            try:
                err_buf.write(traceback.format_exc())
            except:
                err_buf.write("exec error (traceback unavailable)")
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
    stdout_val = _to_str(out_buf.getvalue())
    stderr_val = _to_str(err_buf.getvalue())
    saved_to = self._save_output(params.get("output"), stdout_val)
    return {"stdout": stdout_val,
            "stderr": stderr_val,
            "saved_to": saved_to}


def _handle_strings_xrefs(self, params):
    """Get strings with their cross-references.

    Returns strings that have xrefs, with caller information.
    """
    from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType

    filt = params.get("filter")
    min_refs = params.get("min_refs", 0)
    max_results = params.get("max_results", 0)  # 0 = no limit (paginate handles it)
    results = []
    for dex in self.dex_units:
        for s in dex.getStrings():
            if max_results and len(results) >= max_results:
                break
            value = s.getValue()
            if filt and filt.lower() not in value.lower():
                continue
            idx = s.getIndex()
            xref_addrs = dex.getCrossReferences(DexPoolType.STRING, idx)
            if not xref_addrs:
                continue
            # Resolve caller method names from addresses
            callers = []
            for addr in xref_addrs:
                addr_str = str(addr)
                caller_info = {"address": addr_str}
                # Try to resolve internal address to method sig
                internal = addr.getInternalAddress() if hasattr(addr, "getInternalAddress") else addr_str
                if internal:
                    # Internal address format: Lcom/...;->method(...)V+offset
                    iaddr = str(internal)
                    plus_pos = iaddr.rfind("+")
                    method_part = iaddr[:plus_pos] if plus_pos > 0 else iaddr
                    m = dex.getMethod(method_part)
                    if m:
                        caller_info["method_sig"] = m.getSignature(True)
                        caller_info["method_name"] = m.getName(True)
                        caller_info["class_sig"] = m.getClassType().getSignature(True, False)
                callers.append(caller_info)
            if len(callers) < min_refs:
                continue
            results.append({
                "value": value,
                "index": idx,
                "xrefs": callers,
                "xref_count": len(callers),
            })
        if max_results and len(results) >= max_results:
            break
    return self._paginate(results, params)


def _handle_get_main_activity(self, params):
    """Get the main launcher activity from the manifest."""
    _require_apk(self)
    text = _read_manifest_text(self)
    if not text:
        raise self.RpcError("MANIFEST_NOT_FOUND", "Cannot read manifest",
                            "Ensure this is an APK file with a valid manifest")

    import re
    main_activity = None

    # Find MAIN+LAUNCHER intent filter
    chunks = text.split("<activity")
    for chunk in chunks[1:]:
        name_m = re.search(r'android:name="([^"]*)"', chunk)
        if not name_m:
            continue
        if "android.intent.action.MAIN" in chunk and "android.intent.category.LAUNCHER" in chunk:
            main_activity = name_m.group(1)
            break

    # Fallback: first activity
    if not main_activity:
        activities = re.findall(r'<activity[^>]*android:name="([^"]*)"', text)
        if activities:
            main_activity = activities[0]

    if not main_activity:
        raise self.RpcError("MAIN_ACTIVITY_NOT_FOUND",
                            "Cannot find main launcher activity",
                            "Check 'manifest' output for activity declarations")

    return {"main_activity": main_activity}


def _handle_get_app_classes(self, params):
    """Get application-level classes (Application subclass, main activity, etc.)."""
    app_classes = []
    for dex in self.dex_units:
        for cls in dex.getClasses():
            sig = cls.getSignature(True)
            # Skip android/java framework classes
            if any(sig.startswith(p) for p in _FRAMEWORK_PREFIXES):
                continue
            supers = cls.getSupertypes()
            if supers:
                for sup in supers:
                    sup_str = str(sup)
                    if "Application" in sup_str:
                        app_classes.append({
                            "sig": sig,
                            "type": "application",
                            "superclass": sup_str,
                        })
                    elif "Activity" in sup_str:
                        app_classes.append({
                            "sig": sig,
                            "type": "activity",
                            "superclass": sup_str,
                        })
    return {"classes": app_classes, "total": len(app_classes)}


def _handle_report(self, params):
    """Generate analysis report (summary + top classes + security hints)."""
    from .helpers import _decompile_class_code
    summary = _handle_summary(self, params)
    report_lines = []
    report_lines.append("# revkit JEB Analysis Report")
    report_lines.append("")
    report_lines.append("## Summary")
    for k, v in summary.items():
        report_lines.append("- %s: %s" % (k, v))
    report_lines.append("")
    report_lines.append("## Classes (top 20)")
    try:
        classes = self.dex_units[0].getClasses()
        count = 0
        for cls in classes:
            if count >= 20:
                break
            sig = str(cls.getSignature())
            report_lines.append("- %s" % sig)
            count += 1
    except Exception:
        report_lines.append("- (unable to list classes)")
    return {"report": "\n".join(report_lines), "format": "markdown"}


def _handle_decompile_diff(self, params):
    """Compare current decompile with previous version (if stored)."""
    sig = params.get("sig", params.get("class_sig", ""))
    if not sig:
        return {"error": "sig parameter required"}
    # Decompile current version
    from .helpers import _decompile_class_code
    try:
        current_code = str(_decompile_class_code(self, sig))
    except Exception as e:
        return {"error": "decompile failed: %s" % str(e)}
    # Check previous version in snapshot history
    prev_key = "_prev_decompile_%s" % sig.replace("/", "_").replace(";", "")
    prev_code = getattr(self, prev_key, None)
    if not prev_code:
        # Store current for next comparison
        setattr(self, prev_key, current_code)
        return {"diff": None, "message": "No previous version. Current stored for future comparison.", "code": current_code}
    # Simple line diff
    import difflib
    diff = list(difflib.unified_diff(
        prev_code.splitlines(True), current_code.splitlines(True),
        fromfile="previous", tofile="current", lineterm=""
    ))
    # Store current for next comparison
    setattr(self, prev_key, current_code)
    return {"diff": "\n".join(diff) if diff else "(identical)", "has_changes": len(diff) > 0}
