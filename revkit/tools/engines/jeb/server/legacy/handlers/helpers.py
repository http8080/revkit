# -*- coding: utf-8 -*-
"""Shared helper functions and constants for handler submodules.

Runs under Jython 2.7 (Python 2 syntax). No f-strings, no type hints.
"""

import json
import os
import time
import base64

from ..constants import MAX_SEARCH_RESULTS

# Framework class prefixes to skip in app-class detection
_FRAMEWORK_PREFIXES = ("Landroid/", "Ljava/", "Landroidx/", "Lcom/google/")
_OBFUSCATED_NAME_MAX_LEN = 3


def _get_decompiler(server, dex):
    """Get decompiler for a DEX unit, raise RpcError if unavailable."""
    from com.pnfsoftware.jeb.core.util import DecompilerHelper
    decomp = DecompilerHelper.getDecompiler(dex)
    if not decomp:
        raise server.RpcError("DECOMPILER_NOT_AVAILABLE",
                               "No decompiler for this unit",
                               "Try 'get_smali' for bytecode-level view")
    return decomp


def _make_decompile_context():
    """Create standard DecompilationContext for method decompilation."""
    from com.pnfsoftware.jeb.core.units.code import (
        DecompilationContext, DecompilationOptions, IDecompilerUnit,
    )
    from java.lang import Long
    opt = DecompilationOptions.Builder.newInstance() \
        .flags(IDecompilerUnit.FLAG_NO_INNER_DECOMPILATION
               | IDecompilerUnit.FLAG_NO_DEFERRED_DECOMPILATION) \
        .maxTimePerMethod(Long(30000)) \
        .build()
    return DecompilationContext(opt)


def _batch_process(items, processor_fn):
    """Generic batch processor with success/failure tracking.

    processor_fn(item) -> dict with 'ok' key.
    Returns: {"total": N, "success": N, "failed": N, "results": [...]}.
    """
    results = []
    success = 0
    failed = 0
    for item in items:
        try:
            result = processor_fn(item)
            results.append(result)
            if result.get("ok"):
                success += 1
            else:
                failed += 1
        except Exception as e:
            results.append({"ok": False, "error": str(e)})
            failed += 1
    return {"total": len(items), "success": success, "failed": failed,
            "results": results}


def _to_str(obj):
    """Convert Java/Jython objects to unicode string safely.

    On Jython 2.7, str() does ascii encoding which fails on non-ASCII.
    Use unicode() instead. On CPython 3.x, str() works fine.
    """
    if obj is None:
        return ""
    try:
        return unicode(obj)
    except NameError:
        return str(obj)


def _raise_not_found(self, item_type, sig):
    """Raise RpcError for a not-found item (class/method/field)."""
    code = "%s_NOT_FOUND" % item_type.upper()
    raise self.RpcError(code, "%s not found: %s" % (item_type.capitalize(), sig),
                        "Use 'search_%ss' to find valid signatures" % item_type)


def _require_class(self, class_sig):
    """Find the IDexUnit and class object for a class signature.

    Returns (dex, cls). Raises RpcError if not found.
    """
    dex = self._find_dex_for_class(class_sig)
    if not dex:
        _raise_not_found(self, "class", class_sig)
    cls = dex.getClass(class_sig)
    if not cls:
        _raise_not_found(self, "class", class_sig)
    return dex, cls


def _resolve_dex_item(dex, sig):
    """Resolve a signature to (item, pool_type) from a dex unit.

    Tries method -> class -> field. Returns (None, None) if not found.
    """
    from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType

    item = dex.getMethod(sig)
    if item:
        return item, DexPoolType.METHOD
    item = dex.getClass(sig)
    if item:
        return item, DexPoolType.TYPE
    item = dex.getField(sig)
    if item:
        return item, DexPoolType.FIELD
    return None, None


def _require_method(self, method_sig):
    """Find the IDexUnit and method object for a method signature.

    Returns (dex, method). Raises RpcError if not found.
    """
    dex = self._find_dex_for_method(method_sig)
    if not dex:
        _raise_not_found(self, "method", method_sig)
    m = dex.getMethod(method_sig)
    if not m:
        _raise_not_found(self, "method", method_sig)
    return dex, m


def _require_apk(self):
    """Return the IApkUnit or raise RpcError if not available."""
    try:
        apk = self.apk_unit
    except Exception:
        apk = None
    if not apk:
        raise self.RpcError("NOT_APK", "No APK unit found",
                            "This binary is a DEX file; manifest/resources require an APK")
    return apk


def _require_param(self, params, key):
    """Get a required parameter or raise RpcError."""
    val = params.get(key)
    if not val:
        raise self.RpcError("MISSING_PARAM", "%s is required" % key,
                            "Include '%s' in the request params" % key)
    return val


class _EdgeCollector:
    """Deduplicating edge collector for graph traversals."""
    def __init__(self):
        self.edges = []
        self._seen = set()

    def add(self, src, dst):
        edge = (src, dst)
        if edge not in self._seen:
            self._seen.add(edge)
            self.edges.append(edge)

    def to_dicts(self):
        return [{"from": e[0], "to": e[1]} for e in self.edges]


def _graph_result(self, params, root, nodes, ec, graph_name):
    """Build standard graph result dict from EdgeCollector."""
    mermaid = _edges_to_graph(ec.edges, "mermaid", graph_name)
    dot = _edges_to_graph(ec.edges, "dot", graph_name)
    saved_to = self._save_output(params.get("output"), mermaid)
    return {
        "root": root,
        "nodes": list(nodes),
        "edges": ec.to_dicts(),
        "mermaid": mermaid,
        "dot": dot,
        "saved_to": saved_to,
    }


def _edges_to_graph(edges, fmt="mermaid", graph_name="callgraph"):
    """Generate Mermaid or DOT graph text from a list of (src, dst) edges."""
    if fmt == "dot":
        esc = lambda s: _to_str(s).replace('"', '\\"')
        lines = ["digraph %s {" % graph_name]
        for src, dst in edges:
            lines.append('  "%s" -> "%s";' % (esc(src), esc(dst)))
        lines.append("}")
    else:
        esc = lambda s: _to_str(s).replace('"', "'")
        lines = ["graph LR"]
        for src, dst in edges:
            lines.append('  "%s" --> "%s"' % (esc(src), esc(dst)))
    return "\n".join(lines)


def _decompile_class_code(self, class_sig):
    """Shared decompile logic: returns (dex, cls, code_str).

    Tries getDecompiledClassText first, falls back to per-method decompilation.
    """
    dex, cls = _require_class(self, class_sig)
    decomp = _get_decompiler(self, dex)

    # Method 1: decompileClass -> getDecompiledClassText
    decomp.decompileClass(class_sig)
    code = decomp.getDecompiledClassText(class_sig)

    # Method 2 (fallback): per-method iteration
    if not code:
        dctx = _make_decompile_context()
        methods_code = []
        for m in cls.getMethods():
            sig = m.getSignature(True)
            try:
                decomp.decompileMethod(sig, dctx)
                text = decomp.getDecompiledMethodText(sig)
                if text:
                    methods_code.append(_to_str(text))
            except Exception:
                methods_code.append("// decompile failed: %s" % sig)
        code = "\n\n".join(methods_code)

    return dex, cls, _to_str(code) if code else ""


def _search_max(params):
    """Extract max_results from params with cap."""
    return min(params.get("max_results", params.get("max", 50)),
               MAX_SEARCH_RESULTS)


def _read_manifest_text(self):
    """Read AndroidManifest.xml text from the APK unit.

    Returns the XML string, or None if not available.
    Callers must ensure self.apk_unit exists (via _require_apk).
    """
    apk = self.apk_unit
    xml_unit = apk.getManifest()  # IXmlUnit
    if not xml_unit:
        return None

    xml = None
    try:
        xml = xml_unit.getDocumentAsText()
    except Exception:
        pass
    if not xml:
        try:
            doc = xml_unit.getDocument()
            if doc:
                xml = _to_str(doc.toString())
        except Exception:
            pass

    def _looks_like_xml(s):
        t = s.strip()
        return t.startswith("<?xml") or t.startswith("<manifest")

    if not xml or not _looks_like_xml(xml):
        try:
            fallback = xml_unit.toString()
            if fallback and _looks_like_xml(fallback):
                xml = fallback
        except Exception:
            pass
    if not xml or not _looks_like_xml(xml):
        # Fallback: read manifest via resource child unit
        try:
            from com.pnfsoftware.jeb.util.io import IO
            children = apk.getChildren()
            if children:
                for child in children:
                    if child.getName() == "Manifest":
                        inp = child.getInput()
                        if inp:
                            data = IO.readInputStream(inp.getStream())
                            py_bytes = bytearray([b & 0xff for b in data])
                            xml = py_bytes.decode("utf-8") if hasattr(py_bytes, "decode") else str(py_bytes)
                            break
        except Exception:
            pass
    if xml and _looks_like_xml(xml):
        return xml
    return None
