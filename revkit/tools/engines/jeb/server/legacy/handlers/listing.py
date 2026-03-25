# -*- coding: utf-8 -*-
"""Listing handlers -- classes, methods, fields, strings, resources.

Runs under Jython 2.7 (Python 2 syntax). No f-strings, no type hints.
"""

import base64

from .helpers import (
    _require_class, _require_apk, _require_method,
    _decompile_class_code, _to_str,
)


def _handle_get_classes(self, params):
    """List all DEX classes with pagination."""
    all_classes = []
    for dex in self.dex_units:
        for c in dex.getClasses():
            sig = c.getSignature(False)
            name = c.getName(False)
            name_cur = c.getName(True)
            all_classes.append({
                "sig": sig,
                "name": name,
                "current_name": name_cur,
                "access": c.getAccessFlags(),
            })
    return self._paginate(all_classes, params)


def _handle_get_methods_of_class(self, params):
    """List methods of a class."""
    class_sig = params.get("class_sig")
    _, cls = _require_class(self, class_sig)
    methods = []
    for m in cls.getMethods():
        rt = m.getReturnType()
        internal = m.isInternal()
        access = 0
        if internal:
            data = m.getData()
            if data:
                access = data.getAccessFlags()
        methods.append({
            "sig": m.getSignature(True),
            "name": m.getName(True),
            "access": access,
            "return_type": rt.getSignature(True, False) if rt else "?",
            "is_internal": internal,
        })
    return {"class_sig": class_sig, "methods": methods}


def _handle_get_fields_of_class(self, params):
    """List fields of a class."""
    class_sig = params.get("class_sig")
    _, cls = _require_class(self, class_sig)
    fields = [{
        "sig": f.getSignature(True),
        "name": f.getName(True),
        "type": f.getFieldType().getSignature(True, False) if f.getFieldType() else "?",
        "access": f.getGenericFlags(),
    } for f in cls.getFields()]
    return {"class_sig": class_sig, "fields": fields}


def _handle_get_method_info(self, params):
    """Detailed method information."""
    method_sig = params.get("method_sig")
    _dex, m = _require_method(self, method_sig)
    param_types = m.getParameterTypes()
    param_list = []
    if param_types:
        for i, pt in enumerate(param_types):
            param_list.append({"index": i, "type": pt.getSignature(True, False)})
    access_flags = 0
    if m.isInternal():
        data = m.getData()
        if data:
            access_flags = data.getAccessFlags()
    return {
        "method_sig": method_sig,
        "name": m.getName(True),
        "class_sig": m.getClassType().getSignature(True, False),
        "return_type": m.getReturnType().getSignature(True, False),
        "params": param_list,
        "access_flags": access_flags,
        "is_internal": m.isInternal(),
        "is_renamed": m.isRenamed(),
    }


def _handle_get_imports(self, params):
    """External methods (isInternal()==False) -- analogous to PE imports."""
    all_imports = []
    for dex in self.dex_units:
        for m in dex.getMethods():
            if not m.isInternal():
                all_imports.append({
                    "sig": m.getSignature(True),
                    "name": m.getName(True),
                    "class_sig": m.getClassType().getSignature(True, False),
                })
    return self._paginate(all_imports, params)


def _handle_get_exports(self, params):
    """Public classes (ACC_PUBLIC 0x0001) -- analogous to PE exports."""
    all_exports = []
    for dex in self.dex_units:
        for cls in dex.getClasses():
            flags = cls.getAccessFlags()
            if not (flags & 0x0001):  # ACC_PUBLIC
                continue
            all_exports.append({
                "sig": cls.getSignature(True),
                "name": cls.getName(True),
                "access": flags,
            })
    return self._paginate(all_exports, params)


def _handle_native_methods(self, params):
    """List native methods (ACC_NATIVE) with associated SO library info."""
    ACC_NATIVE = 0x0100
    all_natives = []
    lib_map = {}  # class_sig -> [lib_name, ...]

    # Pass 1: collect native methods
    for dex in self.dex_units:
        for cls in dex.getClasses():
            cls_sig = cls.getSignature(True)
            for m in cls.getMethods():
                if not m.isInternal():
                    continue
                data = m.getData()
                if not data:
                    continue
                if not (data.getAccessFlags() & ACC_NATIVE):
                    continue
                rt = m.getReturnType()
                param_types = m.getParameterTypes()
                params_str = ""
                if param_types:
                    params_str = ", ".join(
                        pt.getSignature(True, False) for pt in param_types
                    )
                all_natives.append({
                    "sig": m.getSignature(True),
                    "class_sig": cls_sig,
                    "name": m.getName(True),
                    "return_type": rt.getSignature(True, False) if rt else "void",
                    "params": params_str,
                    "lib": "",
                })

    if not all_natives:
        return {"data": [], "total": 0, "libraries": []}

    # Pass 2: find System.loadLibrary/System.load calls to map classes -> SO
    native_classes = set(n["class_sig"] for n in all_natives)
    for cls_sig in native_classes:
        try:
            _, _, text = _decompile_class_code(self, cls_sig)
            if not text:
                continue
            # Find System.loadLibrary("xxx") patterns
            idx = 0
            while True:
                pos = text.find("loadLibrary(", idx)
                if pos < 0:
                    pos = text.find('.load("', idx)
                    if pos < 0:
                        break
                    q1 = text.find('"', pos + 6)
                    if q1 < 0:
                        break
                    q2 = text.find('"', q1 + 1)
                    if q2 < 0:
                        break
                    lib_name = text[q1 + 1:q2]
                    lib_map.setdefault(cls_sig, []).append(lib_name)
                    idx = q2 + 1
                    continue
                q1 = text.find('"', pos)
                if q1 < 0:
                    break
                q2 = text.find('"', q1 + 1)
                if q2 < 0:
                    break
                lib_name = text[q1 + 1:q2]
                lib_map.setdefault(cls_sig, []).append(lib_name)
                idx = q2 + 1
        except Exception:
            pass

    # Enrich native methods with library info
    all_libs = set()
    for n in all_natives:
        libs = lib_map.get(n["class_sig"], [])
        if libs:
            lib_str = ", ".join("lib%s.so" % l for l in libs)
            n["lib"] = lib_str
            for l in libs:
                all_libs.add("lib%s.so" % l)

    filt = params.get("filter")
    if filt:
        filt_lower = filt.lower()
        all_natives = [n for n in all_natives
                       if filt_lower in n["sig"].lower()
                       or filt_lower in n.get("lib", "").lower()]

    return {
        "data": all_natives,
        "total": len(all_natives),
        "libraries": sorted(all_libs),
    }


def _handle_get_strings(self, params):
    """DEX string pool entries with optional filters.

    Params:
        min_len (int): minimum string length filter
        regex (str): regex pattern filter
        encoding (str): encoding filter (ascii, base64, url, hex)
    """
    try:
        min_len = int(params.get("min_len", 0))
    except (ValueError, TypeError):
        min_len = 0
    regex_pat = params.get("regex")
    encoding = params.get("encoding", "").lower()
    compiled_re = None
    if regex_pat:
        import re
        compiled_re = re.compile(regex_pat, re.IGNORECASE)

    all_strings = []
    for dex in self.dex_units:
        for s in dex.getStrings():
            val = s.getValue()
            if not val:
                continue
            if min_len and len(val) < min_len:
                continue
            if compiled_re and not compiled_re.search(val):
                continue
            if encoding:
                if encoding == "ascii":
                    try:
                        val.encode("ascii")
                    except (UnicodeEncodeError, UnicodeDecodeError):
                        continue
                elif encoding == "base64":
                    import re as re2
                    if not re2.match(r'^[A-Za-z0-9+/=]{4,}$', val):
                        continue
                elif encoding == "url":
                    if not (val.startswith("http://") or val.startswith("https://")
                            or val.startswith("ftp://") or val.startswith("//")):
                        continue
                elif encoding == "hex":
                    import re as re3
                    if not re3.match(r'^(0x)?[0-9a-fA-F]{4,}$', val):
                        continue
            all_strings.append({
                "value": val,
                "index": s.getIndex(),
            })
    return self._paginate(all_strings, params)


def _handle_get_resources_list(self, params):
    """List APK resource/child units."""
    apk = _require_apk(self)

    resources = []
    children = apk.getChildren()
    if children:
        for child in children:
            size = 0
            try:
                inp = child.getInput()
                if inp:
                    size = inp.getCurrentSize()
            except Exception:
                pass
            resources.append({
                "path": child.getName(),
                "type": child.getFormatType(),
                "size": size,
            })
    return {"total": len(resources), "data": resources}


def _handle_get_resource(self, params):
    """Get a single APK resource by path."""
    apk = _require_apk(self)

    path = params.get("path")
    from com.pnfsoftware.jeb.util.io import IO

    children = apk.getChildren()
    if children:
        # Try exact match first, then case-insensitive, then partial match
        path_lower = path.lower() if path else ""
        matched = None
        for child in children:
            cname = child.getName()
            if cname == path:
                matched = child
                break
        if not matched:
            for child in children:
                cname = child.getName()
                if cname and cname.lower() == path_lower:
                    matched = child
                    break
        if not matched:
            for child in children:
                cname = child.getName()
                if cname and (path_lower in cname.lower() or cname.lower() in path_lower):
                    matched = child
                    break
        if matched:
            try:
                inp = matched.getInput()
                if inp:
                    data = IO.readInputStream(inp.getStream())
                    # Java byte[] -> Python bytearray (signed->unsigned)
                    py_bytes = bytearray([b & 0xff for b in data])
                    b64 = base64.b64encode(bytes(py_bytes))
                    saved_to = self._save_output(params.get("output"), py_bytes)
                    return {"path": matched.getName(), "size": len(data),
                            "content_b64": b64, "saved_to": saved_to}
            except Exception:
                pass
    raise self.RpcError("RESOURCE_NOT_FOUND",
                        "Resource not found: %s" % path,
                        "Use 'get_resources_list' to see available resources")
