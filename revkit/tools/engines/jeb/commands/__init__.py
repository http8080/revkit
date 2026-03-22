"""JEB command modules -- all cmd_* functions re-exported."""

from .analysis import (
    cmd_method,
    cmd_decompile,
    cmd_decompile_diff,
    cmd_decompile_batch,
    cmd_decompile_all,
    cmd_smali,
    cmd_strings,
    cmd_classes,
    cmd_methods_of_class,
    cmd_fields_of_class,
    cmd_method_info,
    cmd_methods,
    cmd_native_methods,
)

from .batch import (
    cmd_batch,
)

from .config import (
    cmd_config_show,
    cmd_config_set,
)

from .instance import (
    cmd_init,
    cmd_check,
    cmd_start,
    cmd_stop,
    cmd_restart,
    cmd_wait,
    cmd_list,
    cmd_status,
    cmd_logs,
    cmd_cleanup,
    cmd_save,
)

from .modification import (
    cmd_rename,
    cmd_rename_class,
    cmd_rename_method,
    cmd_rename_field,
    cmd_rename_batch,
    cmd_rename_preview,
    cmd_auto_rename,
    cmd_set_comment,
    cmd_get_comments,
    cmd_undo,
    cmd_bookmark,
)

from .report import (
    cmd_annotations_export,
    cmd_annotations_import,
    cmd_annotations,
    cmd_snapshot_save,
    cmd_snapshot_list,
    cmd_snapshot_restore,
    cmd_snapshot,
    cmd_report,
)

from .security import (
    cmd_entry_points,
    cmd_security_scan,
)

from .recon import (
    cmd_summary,
    cmd_permissions,
    cmd_components,
    cmd_info,
    cmd_main_activity,
    cmd_app_class,
    cmd_resources,
    cmd_resource,
    cmd_manifest,
)

from .search import (
    cmd_search_classes,
    cmd_search_methods,
    cmd_search_code,
    cmd_strings_xrefs,
)

from .tooling import (
    cmd_gen_runner,
    cmd_patch,
    cmd_unpatch,
    cmd_merge,
)

from .xrefs import (
    cmd_xrefs,
    cmd_callers,
    cmd_callees,
    cmd_callgraph,
    cmd_cross_refs,
)

from .utility import (
    cmd_exec,
    cmd_completion,
)
