# -*- coding: utf-8 -*-
"""Analysis handlers -- decompile methods/classes, smali, manifest.

Runs under Jython 2.7 (Python 2 syntax). No f-strings, no type hints.
"""

import os

from .helpers import (
    _get_decompiler, _make_decompile_context, _batch_process,
    _to_str, _raise_not_found, _require_class, _require_apk,
    _require_param, _decompile_class_code, _read_manifest_text,
)
from ..constants import MAX_BATCH_DECOMPILE


def _handle_get_method_by_name(self, params):
    """Decompile a single method to Java source.

    with_xrefs=True adds callers/callees info.
    """
    from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType

    method_sig = params.get("method_sig")
    if not method_sig:
        raise self.RpcError("MISSING_PARAM", "method_sig is required",
                            "Use 'search_methods' to find method signatures")

    dex = self._find_dex_for_method(method_sig)
    if not dex:
        _raise_not_found(self, "method", method_sig)

    decomp = _get_decompiler(self, dex)
    decomp.decompileMethod(method_sig, _make_decompile_context())
    text = decomp.getDecompiledMethodText(method_sig)
    if not text:
        raise self.RpcError("DECOMPILE_FAILED",
                            "Decompile returned empty for %s" % method_sig,
                            "Try 'get_smali' for bytecode-level view")

    code = _to_str(text)
    saved_to = self._save_output(params.get("output"), code)
    result = {"method_sig": method_sig, "code": code, "saved_to": saved_to}

    # Xrefs
    if params.get("with_xrefs"):
        m = dex.getMethod(method_sig)
        if m:
            idx = m.getIndex()
            callers = []
            xref_addrs = dex.getCrossReferences(DexPoolType.METHOD, idx)
            if xref_addrs:
                for addr in xref_addrs:
                    callers.append({
                        "address": addr.getInternalAddress(),
                        "type": str(addr.getReferenceType()) if hasattr(addr, "getReferenceType") else "CALL",
                    })
            callees = []
            refmgr = dex.getReferenceManager()
            if m.isInternal() and refmgr:
                try:
                    ref_map = refmgr.getReferences(DexPoolType.METHOD, idx)
                    if ref_map:
                        for e in ref_map.entrySet():
                            if str(e.getKey()) != str(DexPoolType.METHOD):
                                continue
                            for ref_idx in e.getValue():
                                target = dex.getMethod(ref_idx)
                                if target:
                                    callees.append({"sig": target.getSignature(True)})
                except Exception:
                    pass
            # Referenced fields
            fields_ref = []
            if m.isInternal() and refmgr:
                try:
                    ref_map = refmgr.getReferences(DexPoolType.METHOD, idx)
                    if ref_map:
                        for e in ref_map.entrySet():
                            if str(e.getKey()) != str(DexPoolType.FIELD):
                                continue
                            for ref_idx in e.getValue():
                                target = dex.getField(ref_idx)
                                if target:
                                    fields_ref.append({"sig": target.getSignature(True)})
                except Exception:
                    pass
            result["callers"] = callers
            result["callees"] = callees
            result["fields_ref"] = fields_ref

    return result


def _handle_get_class_source(self, params):
    """Decompile a class to Java source.

    1st: getDecompiledClassText (fast, cached).
    2nd (fallback): per-method decompilation.
    """
    class_sig = params.get("class_sig")
    _dex, _cls, code = _decompile_class_code(self, class_sig)
    saved_to = self._save_output(params.get("output"), code)
    return {"class_sig": class_sig, "code": code, "saved_to": saved_to}


def _handle_get_class_source_with_xrefs(self, params):
    """Decompile a class + gather callers/callees xref info."""
    from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType

    class_sig = params.get("class_sig")
    dex, cls, code = _decompile_class_code(self, class_sig)
    if not code:
        code = "// decompile failed"

    callers = []
    callees = []
    refmgr = dex.getReferenceManager()
    for m in cls.getMethods():
        m_sig = m.getSignature(True)
        idx = m.getIndex()
        # callers: who calls this method
        xref_addrs = dex.getCrossReferences(DexPoolType.METHOD, idx)
        if xref_addrs:
            for addr in xref_addrs:
                callers.append({
                    "method_sig": m_sig,
                    "address": addr.getInternalAddress(),
                    "type": str(addr.getReferenceType()) if hasattr(addr, "getReferenceType") else "CALL",
                })
        # callees: what this method calls
        if m.isInternal() and refmgr:
            try:
                ref_map = refmgr.getReferences(DexPoolType.METHOD, idx)
                if ref_map:
                    for e in ref_map.entrySet():
                        for ref_idx in e.getValue():
                            target = dex.getMethod(ref_idx)
                            if target:
                                callees.append({
                                    "from": m_sig,
                                    "to": target.getSignature(True),
                                })
            except Exception:
                pass

    saved_to = self._save_output(params.get("output"), _to_str(code))
    return {
        "class_sig": class_sig,
        "code": _to_str(code),
        "callers": callers,
        "callees": callees,
        "saved_to": saved_to,
    }


def _handle_get_smali(self, params):
    """Extract Dalvik bytecode in smali-like format.

    JEB has no direct getSmali(); we iterate Dalvik instructions.
    Supports method_sig param to extract only a specific method's smali.
    """
    method_sig = params.get("method_sig")
    class_sig = params.get("class_sig")

    # If method_sig given, extract class_sig from it
    if method_sig and not class_sig:
        # Lcom/example/Foo;->bar(I)V  =>  Lcom/example/Foo;
        arrow = method_sig.find("->")
        if arrow > 0:
            class_sig = method_sig[:arrow]
            if not class_sig.endswith(";"):
                class_sig += ";"

    if not class_sig:
        raise self.RpcError("MISSING_PARAM", "class_sig or method_sig is required",
                            "Provide a class or method signature")

    _dex, cls = _require_class(self, class_sig)

    smali_lines = []
    for m in cls.getMethods():
        if not m.isInternal():
            continue
        m_sig = m.getSignature(True)
        # Filter to specific method if method_sig given
        if method_sig and m_sig != method_sig:
            continue
        smali_lines.append(".method %s" % m.getSignature(False))
        data = m.getData()
        if data:
            code_item = data.getCodeItem()
            if code_item:
                for insn in code_item.getInstructions():
                    smali_lines.append("    %04x: %s" % (
                        insn.getOffset(), insn.format(None)))
        smali_lines.append(".end method")
        smali_lines.append("")

    smali = "\n".join(smali_lines)
    saved_to = self._save_output(params.get("output"), smali)
    result_sig = method_sig or class_sig
    return {"class_sig": class_sig, "method_sig": method_sig,
            "smali": smali, "saved_to": saved_to}


def _handle_decompile_batch(self, params):
    """Batch decompile multiple classes (max 20)."""
    sigs = params.get("class_sigs", [])
    if len(sigs) > MAX_BATCH_DECOMPILE:
        raise self.RpcError("LIMIT_EXCEEDED",
                            "Max %d classes per batch" % MAX_BATCH_DECOMPILE,
                            "Split into multiple decompile_batch calls or use decompile_all")

    server = self
    decomp_cache = {}

    def _decompile_one(sig):
        dex = server._find_dex_for_class(sig)
        if not dex:
            return {"sig": sig, "ok": False, "error": "CLASS_NOT_FOUND"}
        dex_id = id(dex)
        if dex_id not in decomp_cache:
            decomp_cache[dex_id] = _get_decompiler(server, dex)
        decomp = decomp_cache[dex_id]
        decomp.decompileClass(sig)
        code = decomp.getDecompiledClassText(sig)
        if code:
            return {"sig": sig, "ok": True, "code": _to_str(code)}
        return {"sig": sig, "ok": False, "error": "DECOMPILE_FAILED"}

    result = _batch_process(sigs, _decompile_one)
    result["saved_to"] = self._save_output(params.get("output"), result["results"])
    return result


def _handle_decompile_all(self, params):
    """Decompile all classes to file(s).

    Params:
        filter: optional class name filter
        skip_external: skip non-internal classes (default True)
        output: output file or directory (required)
        split: if True, write one file per class
    """
    output = _require_param(self, params, "output")

    filt = params.get("filter", "")
    skip_external = params.get("skip_external", True)
    split = params.get("split", False)

    total = 0
    success = 0
    failed = 0
    all_code = []

    for dex in self.dex_units:
        try:
            decomp = _get_decompiler(self, dex)
        except Exception:
            continue

        for cls in dex.getClasses():
            sig = cls.getSignature(True)
            name = cls.getName(True)

            if filt and filt.lower() not in sig.lower():
                continue

            # skip_external: skip classes that have no internal methods
            if skip_external and not any(m.isInternal() for m in cls.getMethods()):
                continue

            total += 1
            try:
                decomp.decompileClass(sig)
                code = decomp.getDecompiledClassText(sig)
                if code:
                    code = _to_str(code)
                    if split:
                        # Write each class to its own file
                        # Convert Lcom/example/Foo; -> com/example/Foo.java
                        rel_path = sig
                        if rel_path.startswith("L") and rel_path.endswith(";"):
                            rel_path = rel_path[1:-1]
                        rel_path = rel_path + ".java"
                        out_path = os.path.join(output, rel_path)
                        out_dir = os.path.dirname(out_path)
                        if not os.path.isdir(out_dir):
                            os.makedirs(out_dir)
                        with open(out_path, "w") as f:
                            f.write(code)
                    else:
                        all_code.append("// === %s ===\n%s" % (sig, code))
                    success += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

    saved_to = None
    combined = "\n\n".join(all_code) if all_code else ""
    if not split and all_code:
        saved_to = self._save_output(output, combined)
    elif split:
        saved_to = output

    resp = {"total": total, "success": success, "failed": failed,
            "saved_to": saved_to}
    if not saved_to and combined:
        resp["code"] = combined
    return resp


def _handle_get_manifest(self, params):
    """Extract AndroidManifest.xml."""
    _require_apk(self)
    xml = _read_manifest_text(self)
    if not xml:
        raise self.RpcError("MANIFEST_EMPTY", "Manifest text is empty",
                            "The APK may have a corrupt or missing AndroidManifest.xml")

    saved_to = self._save_output(params.get("output"), xml)
    return {"xml": xml, "saved_to": saved_to}
