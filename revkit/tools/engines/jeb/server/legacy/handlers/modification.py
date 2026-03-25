# -*- coding: utf-8 -*-
"""Modification handlers -- rename, comment.

Runs under Jython 2.7 (Python 2 syntax). No f-strings, no type hints.
"""

from .helpers import (
    _raise_not_found, _resolve_dex_item, _batch_process, _to_str,
)


def _rename_item(self, sig, new_name, item_type):
    """Shared rename logic for class/method/field.

    item_type: "class", "method", or "field".
    Returns {"ok": True, "old_name": ..., "new_name": ...}.
    """
    dex = self._find_dex_for_any(sig)
    if not dex:
        _raise_not_found(self, item_type, sig)

    getter = {"class": dex.getClass, "method": dex.getMethod, "field": dex.getField}[item_type]
    item = getter(sig)
    if not item:
        _raise_not_found(self, item_type, sig)

    old_name = item.getName(True)
    item.setName(new_name)
    dex.notifyGenericChange()
    return {"ok": True, "old_name": old_name, "new_name": new_name}


_RENAME_SIG_KEYS = {
    "rename_class": ("class_sig", "class"),
    "rename_method": ("method_sig", "method"),
    "rename_field": ("field_sig", "field"),
}


def _handle_rename_typed(self, params, rpc_method=None):
    """Unified rename handler for class/method/field."""
    sig_key, item_type = _RENAME_SIG_KEYS.get(rpc_method, ("sig", "item"))
    return _rename_item(self, params.get(sig_key), params.get("new_name"), item_type)


def _handle_rename(self, params):
    """Unified rename: auto-detect class/method/field from sig format.

    sig format:
      class:  Lcom/example/Foo;
      method: Lcom/example/Foo;->bar(I)V
      field:  Lcom/example/Foo;->baz:I
    """
    sig = params.get("sig", "")
    name = params.get("name", params.get("new_name", ""))
    if not sig:
        raise self.RpcError("MISSING_PARAM", "sig is required")
    if not name:
        raise self.RpcError("MISSING_PARAM", "name (new name) is required")
    # Auto-detect type
    if "->" in sig:
        if "(" in sig:
            item_type = "method"
        elif ":" in sig.split("->")[1]:
            item_type = "field"
        else:
            item_type = "method"  # fallback
    else:
        item_type = "class"
    return _rename_item(self, sig, name, item_type)


def _handle_rename_class(self, params):
    """Rename a class."""
    return _handle_rename_typed(self, params, "rename_class")


def _handle_rename_method(self, params):
    """Rename a method."""
    return _handle_rename_typed(self, params, "rename_method")


def _handle_rename_field(self, params):
    """Rename a field."""
    return _handle_rename_typed(self, params, "rename_field")


def _handle_rename_batch(self, params):
    """Batch rename classes/methods/fields.

    entries: list of {sig, new_name}.
    Automatically detects item type (class/method/field) from sig.
    """
    server = self

    def _rename_one(entry):
        sig = entry.get("sig", "")
        new_name = entry.get("new_name", "")
        dex = server._find_dex_for_any(sig)
        if not dex:
            return {"sig": sig, "ok": False, "error": "ITEM_NOT_FOUND"}
        item, _pool_type = _resolve_dex_item(dex, sig)
        if not item:
            return {"sig": sig, "ok": False, "error": "CANNOT_RESOLVE"}
        old_name = item.getName(True)
        item.setName(new_name)
        dex.notifyGenericChange()
        return {"sig": sig, "ok": True, "old_name": old_name, "new_name": new_name}

    return _batch_process(params.get("entries", []), _rename_one)


def _handle_set_comment(self, params):
    """Set an inline comment at an address/sig."""
    addr = params.get("addr") or params.get("address")
    if not addr:
        raise self.RpcError("MISSING_PARAM", "addr or address is required",
                            "Provide a method/field signature or hex address")
    comment = params.get("comment", "")
    dex = self._find_dex_for_any(addr)
    if not dex:
        dex = self.dex_units[0]  # fallback to first dex
    dex.setInlineComment(addr, comment)
    return {"ok": True, "addr": addr}


def _handle_get_comments(self, params):
    """Get comments. If addr specified, single lookup; else all comments."""
    addr = params.get("addr")
    if addr:
        dex = self._find_dex_for_any(addr)
        if not dex:
            dex = self.dex_units[0]
        c = dex.getInlineComment(addr)
        return {"addr": addr, "comment": c}

    # Get all comments
    comments = {}
    for dex in self.dex_units:
        all_c = dex.getInlineComments()
        if all_c:
            for e in all_c.entrySet():
                comments[_to_str(e.getKey())] = _to_str(e.getValue())
    return {"comments": comments}


def _handle_undo(self, params):
    """Undo the last rename/comment via server-side history.

    The server maintains an undo stack (_undo_history) that tracks
    rename and comment operations. Each undo pops the last entry
    and reverses it.
    """
    if not hasattr(self, "_undo_history") or not self._undo_history:
        return {"ok": False, "message": "No undo history"}

    entry = self._undo_history.pop()
    action = entry.get("type", "")

    if action == "rename":
        sig = entry.get("sig", "")
        old_name = entry.get("old_name", "")
        item_type = entry.get("item_type", "class")
        try:
            result = _rename_item(self, sig, old_name, item_type)
            return {"ok": True, "action": "undo_rename",
                    "reverted": "%s -> %s" % (entry.get("new_name", ""), old_name)}
        except Exception as e:
            return {"ok": False, "message": "Undo rename failed: %s" % str(e)}

    elif action == "comment":
        addr = entry.get("addr", "")
        old_comment = entry.get("old_comment", "")
        try:
            dex = self._find_dex_for_any(addr)
            if not dex:
                dex = self.dex_units[0]
            dex.setInlineComment(addr, old_comment)
            return {"ok": True, "action": "undo_comment", "addr": addr}
        except Exception as e:
            return {"ok": False, "message": "Undo comment failed: %s" % str(e)}

    return {"ok": False, "message": "Unknown undo type: %s" % action}


def _handle_rename_preview(self, params):
    """Preview what a rename would do without applying it."""
    sig = params.get("sig", params.get("class_sig", ""))
    new_name = params.get("name", params.get("new_name", ""))
    if not sig or not new_name:
        return {"ok": False, "error": "sig and name required"}
    # Resolve item to verify it exists
    try:
        dex = self.dex_units[0] if self.dex_units else None
        if dex:
            item, _ = _resolve_dex_item(dex, sig)
            old_name = _to_str(item.getName()) if item else sig.split(";")[0].split("/")[-1]
        else:
            old_name = sig
    except Exception:
        old_name = sig
    return {
        "ok": True,
        "preview": True,
        "sig": sig,
        "old_name": old_name,
        "new_name": new_name,
        "would_rename": True,
        "applied": False,
    }
