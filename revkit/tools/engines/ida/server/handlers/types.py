"""Types API — structs, enums, local types."""

from ..framework import (
    RpcError, _require_param, _maybe_save_db, _paginate,
)

# Type library cache — invalidated on create_struct/create_enum
_type_cache = {}  # key: (check_fn_id, filt) -> result list
_type_cache_valid = True


def _invalidate_type_cache():
    global _type_cache_valid
    _type_cache.clear()
    _type_cache_valid = False


def _list_type_info(check_fn, filt, extra_fn=None):
    """List types matching check_fn from the type library, filtered by name substring.
    Optimization: caches results when no extra_fn (common case for list operations)."""
    import ida_typeinf
    til = ida_typeinf.get_idati()
    result = []
    qty = ida_typeinf.get_ordinal_count(til)
    filt_lower = filt.lower() if filt else ""
    for ordinal in range(1, qty + 1):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(til, ordinal) and check_fn(tif):
            name = tif.get_type_name()
            if not name:
                continue
            if filt_lower and filt_lower not in name.lower():
                continue
            entry = {"ordinal": ordinal, "name": name}
            if extra_fn:
                entry.update(extra_fn(tif, ordinal))
            result.append(entry)
    return result


def _get_named_type(name, check_fn, not_found_code, not_type_code, not_type_msg):
    """Look up a named type, validate with check_fn, or raise RpcError."""
    import ida_typeinf
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name):
        raise RpcError(not_found_code, f"{not_type_msg} not found: {name}")
    if not check_fn(tif):
        raise RpcError(not_type_code, f"{name} is not a {not_type_msg}")
    return tif


def _create_type_decl(decl, err_code, err_label):
    """Parse a type declaration and save DB. Raises on failure."""
    import ida_typeinf
    result = ida_typeinf.idc_parse_types(decl, 0)
    if result != 0:
        raise RpcError(err_code, f"Cannot create {err_label}: {decl}")
    _maybe_save_db()


# ── Structs ──────────────────────────────────

def _handle_list_structs(params):
    """List all structs/unions in the type library."""
    filt = params.get("filter", "")
    structs = _list_type_info(
        lambda tif: tif.is_struct() or tif.is_union(),
        filt,
        lambda tif, _: {"size": tif.get_size(), "is_union": tif.is_union(),
                         "member_count": tif.get_udt_nmembers()},
    )
    return {"total": len(structs), "structs": structs}


def _handle_get_struct(params):
    """Get struct details with members."""
    import ida_typeinf
    name = _require_param(params, "name")
    tif = _get_named_type(name, lambda t: t.is_struct() or t.is_union(),
                          "STRUCT_NOT_FOUND", "NOT_A_STRUCT", "struct/union")
    members = []
    udt = ida_typeinf.udt_type_data_t()
    if tif.get_udt_details(udt):
        for i in range(udt.size()):
            m = udt[i]
            members.append({
                "offset": m.offset // 8,
                "name": m.name,
                "size": max(1, m.size // 8),
                "type": str(m.type),
            })
    return {
        "name": name,
        "size": tif.get_size(),
        "is_union": tif.is_union(),
        "members": members,
    }


def _handle_create_struct(params):
    """Create a new struct via type declaration."""
    name = _require_param(params, "name")
    is_union = params.get("is_union", False)
    members = params.get("members", [])
    keyword = "union" if is_union else "struct"
    if members:
        fields = []
        for m in members:
            mname = m.get("name", "field")
            msize = int(m.get("size", 1))
            mtype = m.get("type", "")
            if mtype:
                fields.append(f"  {mtype} {mname};")
            else:
                size_map = {1: "char", 2: "short", 4: "int", 8: "__int64"}
                ctype = size_map.get(msize)
                if ctype:
                    fields.append(f"  {ctype} {mname};")
                else:
                    fields.append(f"  char {mname}[{msize}];")
        body = "\n".join(fields)
        decl = f"{keyword} {name} {{\n{body}\n}};"
    else:
        decl = f"{keyword} {name} {{ char __placeholder; }};"
    _create_type_decl(decl, "CREATE_STRUCT_FAILED", "struct")
    _invalidate_type_cache()
    return {"ok": True, "name": name, "members_added": len(members)}


# ── Enums ────────────────────────────────────

def _handle_list_enums(params):
    """List all enums in the type library."""
    filt = params.get("filter", "")
    enums = _list_type_info(
        lambda tif: tif.is_enum(),
        filt,
        lambda tif, _: {"member_count": tif.get_enum_nmembers()},
    )
    return {"total": len(enums), "enums": enums}


def _handle_get_enum(params):
    """Get enum details with members."""
    import ida_typeinf
    name = _require_param(params, "name")
    tif = _get_named_type(name, lambda t: t.is_enum(),
                          "ENUM_NOT_FOUND", "NOT_AN_ENUM", "enum")
    members = []
    edt = ida_typeinf.enum_type_data_t()
    if tif.get_enum_details(edt):
        for i in range(edt.size()):
            m = edt[i]
            members.append({"name": m.name, "value": m.value})
    return {"name": name, "members": members, "total": len(members)}


def _handle_create_enum(params):
    """Create a new enum via type declaration."""
    name = _require_param(params, "name")
    members = params.get("members", [])
    if members:
        fields = []
        for m in members:
            mname = m.get("name", "")
            mval = m.get("value", "")
            if mval != "":
                fields.append(f"  {mname} = {mval}")
            else:
                fields.append(f"  {mname}")
        body = ",\n".join(fields)
        decl = f"enum {name} {{\n{body}\n}};"
    else:
        decl = f"enum {name} {{ __placeholder }};"
    _create_type_decl(decl, "CREATE_ENUM_FAILED", "enum")
    _invalidate_type_cache()
    return {"ok": True, "name": name, "members_added": len(members)}


# ── Local Types (typedef, funcptr, etc.) ─────

def _handle_list_types(params):
    """List all local types (typedefs, function prototypes, etc.)."""
    filt = params.get("filter", "")
    kind = params.get("kind", "all")

    def check_fn(tif):
        if kind == "all":
            return True
        if kind == "typedef":
            return tif.is_typeref()
        if kind == "funcptr":
            return tif.is_funcptr() or tif.is_func()
        if kind == "struct":
            return tif.is_struct() or tif.is_union()
        if kind == "enum":
            return tif.is_enum()
        return not (tif.is_struct() or tif.is_union() or tif.is_enum()
                    or tif.is_typeref() or tif.is_funcptr() or tif.is_func())

    def extra_fn(tif, _ordinal):
        k = ("struct" if tif.is_struct() else
             "union" if tif.is_union() else
             "enum" if tif.is_enum() else
             "typedef" if tif.is_typeref() else
             "funcptr" if tif.is_funcptr() or tif.is_func() else "other")
        return {"kind": k, "size": tif.get_size(), "declaration": str(tif)}

    types = _list_type_info(check_fn, filt, extra_fn)
    return _paginate(types, params)


def _handle_get_type(params):
    """Get detailed info for a named local type."""
    import ida_typeinf
    name = _require_param(params, "name")
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name):
        raise RpcError("TYPE_NOT_FOUND", f"Type not found: {name}")
    result = {
        "name": name, "size": tif.get_size(),
        "declaration": str(tif),
        "is_struct": tif.is_struct(), "is_union": tif.is_union(),
        "is_enum": tif.is_enum(), "is_typedef": tif.is_typeref(),
        "is_funcptr": tif.is_funcptr() or tif.is_func(),
    }
    if tif.is_funcptr() or tif.is_func():
        fi = ida_typeinf.func_type_data_t()
        target = tif
        if tif.is_funcptr():
            target = tif.get_pointed_object()
        if target.get_func_details(fi):
            result["return_type"] = str(target.get_rettype())
            result["args"] = [{"name": fi[i].name or f"a{i+1}", "type": str(fi[i].type)}
                              for i in range(fi.size())]
    return result
