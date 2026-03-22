"""IDA CLI commands package — re-export all cmd_* for unified dispatch.

All command handlers use the ``CmdContext`` signature (D11).
"""

from .instance import (  # noqa: F401
    cmd_init, cmd_check, cmd_start, cmd_stop, cmd_restart,
    cmd_wait, cmd_list, cmd_status, cmd_logs, cmd_cleanup,
)
from .analysis import (  # noqa: F401
    cmd_proxy_segments, cmd_proxy_decompile, cmd_proxy_decompile_batch,
    cmd_proxy_disasm, cmd_proxy_xrefs, cmd_proxy_callers, cmd_proxy_callees,
    cmd_proxy_find_func, cmd_proxy_func_info, cmd_proxy_imagebase,
    cmd_proxy_bytes, cmd_proxy_find_pattern, cmd_proxy_comments,
    cmd_proxy_methods, cmd_proxy_summary, cmd_proxy_exec, cmd_proxy_save,
    cmd_shell,
)
from .modification import (  # noqa: F401
    cmd_proxy_rename, cmd_proxy_set_type, cmd_proxy_comment,
    cmd_patch, cmd_search_const, cmd_auto_rename, cmd_rename_batch,
)
from .types import (  # noqa: F401
    cmd_structs, cmd_enums, cmd_type_info, cmd_vtables, cmd_sigs,
)
from .diff import cmd_diff, cmd_compare, cmd_code_diff  # noqa: F401
from .advanced import (  # noqa: F401
    cmd_callgraph, cmd_cross_refs, cmd_decompile_all, cmd_search_code,
    cmd_strings_xrefs, cmd_func_similarity, cmd_data_refs,
    cmd_basic_blocks, cmd_stack_frame, cmd_switch_table,
)
from .report import (  # noqa: F401
    cmd_bookmark, cmd_profile, cmd_report, cmd_annotations,
    cmd_snapshot, cmd_export_script,
)
from .batch import cmd_batch  # noqa: F401
from .utility import cmd_update, cmd_completions  # noqa: F401


def _collect_commands():
    """Return a dict of {name: callable} for all cmd_* handlers in this package."""
    import sys
    mod = sys.modules[__name__]
    return {
        name: getattr(mod, name)
        for name in dir(mod)
        if name.startswith("cmd_") and callable(getattr(mod, name))
    }


COMMANDS = _collect_commands()
