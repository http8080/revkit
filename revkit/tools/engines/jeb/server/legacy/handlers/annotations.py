# -*- coding: utf-8 -*-
"""Annotation handlers -- export/import renames and comments.

Runs under Jython 2.7 (Python 2 syntax). No f-strings, no type hints.
"""

import json
import time

from .helpers import _require_param, _resolve_dex_item, _to_str


def _handle_export_annotations(self, params):
    """Export all renames and comments to JSON."""
    output = params.get("output")

    names = []
    comments_dict = {}

    for dex in self.dex_units:
        for cls in dex.getClasses():
            if cls.isRenamed():
                names.append({
                    "sig": cls.getSignature(False),
                    "original_name": cls.getName(False),
                    "current_name": cls.getName(True),
                    "type": "class",
                })
            for m in cls.getMethods():
                if m.isRenamed():
                    names.append({
                        "sig": m.getSignature(False),
                        "original_name": m.getName(False),
                        "current_name": m.getName(True),
                        "type": "method",
                    })
            for f in cls.getFields():
                if f.isRenamed():
                    names.append({
                        "sig": f.getSignature(False),
                        "original_name": f.getName(False),
                        "current_name": f.getName(True),
                        "type": "field",
                    })

        # Comments
        all_c = dex.getInlineComments()
        if all_c:
            for e in all_c.entrySet():
                comments_dict[_to_str(e.getKey())] = _to_str(e.getValue())

    binary_name = ""
    if self.apk_unit:
        binary_name = _to_str(self.apk_unit.getName())

    result = {
        "binary": binary_name,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "names": names,
        "comments": comments_dict,
    }

    json_str = json.dumps(result, indent=2, ensure_ascii=True)
    result["saved_to"] = self._save_output(output, json_str)
    return result


def _handle_import_annotations(self, params):
    """Import renames and comments from JSON data."""
    data = _require_param(self, params, "data")

    # data can be a dict or a JSON string
    if isinstance(data, str):
        data = json.loads(data)

    names_applied = 0
    comments_applied = 0
    errors = []

    # Apply names
    name_entries = data.get("names", [])
    for entry in name_entries:
        sig = entry.get("sig", "")
        new_name = entry.get("current_name", "")
        if not sig or not new_name:
            continue
        try:
            dex = self._find_dex_for_any(sig)
            if not dex:
                errors.append("Item not found: %s" % sig)
                continue

            item_type = entry.get("type", "")
            if item_type == "class":
                item = dex.getClass(sig)
            elif item_type == "method":
                item = dex.getMethod(sig)
            elif item_type == "field":
                item = dex.getField(sig)
            else:
                item, _pt = _resolve_dex_item(dex, sig)

            if item:
                item.setName(new_name)
                dex.notifyGenericChange()
                names_applied += 1
            else:
                errors.append("Cannot resolve: %s" % sig)
        except Exception as e:
            errors.append("Error renaming %s: %s" % (sig, str(e)))

    # Apply comments (dict {addr: text} or list [{addr, text}])
    comment_entries = data.get("comments", {})
    if isinstance(comment_entries, list):
        comment_entries = {}
    for addr, text in comment_entries.items():
        try:
            dex = self._find_dex_for_any(addr)
            if not dex:
                dex = self.dex_units[0]
            dex.setInlineComment(addr, text)
            comments_applied += 1
        except Exception as e:
            errors.append("Error setting comment at %s: %s" % (addr, str(e)))

    return {
        "names": names_applied,
        "comments": comments_applied,
        "errors": errors,
    }
