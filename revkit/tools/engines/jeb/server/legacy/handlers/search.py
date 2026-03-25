# -*- coding: utf-8 -*-
"""Search handlers -- search classes, methods, and decompiled code.

Runs under Jython 2.7 (Python 2 syntax). No f-strings, no type hints.
"""

from .helpers import (
    _require_param, _get_decompiler, _to_str, _search_max,
)


def _handle_search_classes(self, params):
    """Search classes by keyword (substring or regex match)."""
    keyword = params.get("keyword", "")
    use_regex = params.get("regex", False)
    max_results = _search_max(params)

    if use_regex:
        import re
        try:
            pattern = re.compile(keyword, re.IGNORECASE)
        except Exception as e:
            raise self.RpcError("INVALID_REGEX", "Bad regex: %s" % str(e),
                                "Check your regex syntax")

    kw_lower = keyword.lower()
    matches = []
    for dex in self.dex_units:
        if len(matches) >= max_results:
            break
        for cls in dex.getClasses():
            sig = cls.getSignature(True)
            name = cls.getName(True)
            if use_regex:
                if pattern.search(sig) or pattern.search(name):
                    matches.append({"sig": sig, "name": name})
            else:
                if kw_lower in sig.lower() or kw_lower in name.lower():
                    matches.append({"sig": sig, "name": name})
            if len(matches) >= max_results:
                break
    return {"query": keyword, "total": len(matches), "matches": matches}


def _handle_search_methods(self, params):
    """Search methods by name (substring or regex match)."""
    name_q = params.get("name", "")
    use_regex = params.get("regex", False)
    max_results = _search_max(params)

    if use_regex:
        import re
        try:
            pattern = re.compile(name_q, re.IGNORECASE)
        except Exception as e:
            raise self.RpcError("INVALID_REGEX", "Bad regex: %s" % str(e),
                                "Check your regex syntax")

    nq_lower = name_q.lower()
    matches = []
    for dex in self.dex_units:
        if len(matches) >= max_results:
            break
        for cls in dex.getClasses():
            if len(matches) >= max_results:
                break
            for m in cls.getMethods():
                mname = m.getName(True)
                if use_regex:
                    matched = pattern.search(mname) or pattern.search(m.getSignature(True))
                else:
                    matched = nq_lower in mname.lower()
                if matched:
                    matches.append({
                        "sig": m.getSignature(True),
                        "class_sig": cls.getSignature(True),
                        "name": mname,
                    })
                    if len(matches) >= max_results:
                        break
    return {"query": name_q, "total": len(matches), "matches": matches}


def _handle_search_code(self, params):
    """Search within decompiled Java source code.

    Decompiles classes on the fly and searches for the query string.
    """
    query = _require_param(self, params, "query")
    case_sensitive = params.get("case_sensitive", False)
    max_results = _search_max(params)
    max_classes = params.get("max_classes", 0)  # 0 = no limit
    context_lines = params.get("context_lines", 0)
    use_regex = params.get("regex", False)
    package_filter = params.get("package", "")

    if use_regex:
        import re
        try:
            if case_sensitive:
                regex = re.compile(query)
            else:
                regex = re.compile(query, re.IGNORECASE)
        except Exception as e:
            raise self.RpcError("INVALID_REGEX", "Bad regex: %s" % str(e),
                                "Check your regex syntax")

    matches = []
    classes_searched = 0

    for dex in self.dex_units:
        try:
            decomp = _get_decompiler(self, dex)
        except Exception:
            continue

        query_cmp = query if case_sensitive else query.lower()
        for cls in dex.getClasses():
            if len(matches) >= max_results:
                break
            if max_classes and classes_searched >= max_classes:
                break

            sig = cls.getSignature(True)

            # Package filter
            if package_filter and package_filter.lower() not in sig.lower():
                continue

            try:
                decomp.decompileClass(sig)
                code = decomp.getDecompiledClassText(sig)
                if not code:
                    continue
                code = _to_str(code)
            except Exception:
                continue
            classes_searched += 1

            code_lines = code.split("\n")
            for line_no, line in enumerate(code_lines, 1):
                if len(matches) >= max_results:
                    break
                # Match check
                if use_regex:
                    if not regex.search(line):
                        continue
                else:
                    line_cmp = line if case_sensitive else line.lower()
                    if query_cmp not in line_cmp:
                        continue

                match = {
                    "class_sig": sig,
                    "line_no": line_no,
                    "line": line.strip(),
                }
                # Context lines
                if context_lines > 0:
                    start = max(0, line_no - 1 - context_lines)
                    end = min(len(code_lines), line_no + context_lines)
                    ctx = []
                    for ci in range(start, end):
                        ctx.append({
                            "line_no": ci + 1,
                            "line": code_lines[ci].rstrip(),
                            "match": (ci == line_no - 1),
                        })
                    match["context"] = ctx
                matches.append(match)

        if len(matches) >= max_results:
            break

    saved_to = self._save_output(params.get("output"), matches)
    return {"query": query, "total": len(matches),
            "classes_searched": classes_searched,
            "matches": matches, "saved_to": saved_to}
