# -*- coding: utf-8 -*-
"""Server handlers package -- re-export all _handle_* for framework.py.

_bind_handlers() uses dir(handlers) to find _handle_* prefix.
_handle_rename_typed is intentionally NOT re-exported (internal dispatcher).
"""

from .helpers import (  # noqa: F401
    _get_decompiler, _make_decompile_context, _batch_process, _to_str,
    _raise_not_found, _require_class, _resolve_dex_item, _require_method,
    _require_apk, _require_param, _EdgeCollector, _graph_result,
    _edges_to_graph, _decompile_class_code, _search_max, _read_manifest_text,
)
from .listing import (  # noqa: F401
    _handle_get_classes, _handle_get_methods_of_class, _handle_get_fields_of_class,
    _handle_get_method_info, _handle_get_imports, _handle_get_exports,
    _handle_native_methods, _handle_get_strings,
    _handle_get_resources_list, _handle_get_resource,
)
from .analysis import (  # noqa: F401
    _handle_get_method_by_name, _handle_get_class_source,
    _handle_get_class_source_with_xrefs, _handle_get_smali,
    _handle_decompile_batch, _handle_decompile_all, _handle_get_manifest,
)
from .search import (  # noqa: F401
    _handle_search_classes, _handle_search_methods, _handle_search_code,
)
from .graph import (  # noqa: F401
    _handle_get_xrefs, _handle_callgraph, _handle_cross_refs,
)
from .modification import (  # noqa: F401
    _handle_rename, _handle_rename_class, _handle_rename_method, _handle_rename_field,
    _handle_rename_batch, _handle_set_comment, _handle_get_comments, _handle_undo,
    _handle_rename_preview,
)
from .annotations import (  # noqa: F401
    _handle_export_annotations, _handle_import_annotations,
)
from .snapshot import (  # noqa: F401
    _handle_snapshot_save, _handle_snapshot_list, _handle_snapshot_restore,
)
from .advanced import (  # noqa: F401
    _handle_auto_rename, _handle_info, _handle_summary, _handle_exec,
    _handle_strings_xrefs, _handle_get_main_activity, _handle_get_app_classes,
    _handle_report, _handle_decompile_diff,
)
from .security import (  # noqa: F401
    _handle_entry_points, _handle_security_scan,
)
