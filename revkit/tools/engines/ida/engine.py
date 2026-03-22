"""revkit engines — IDAEngine implementation."""

from __future__ import annotations

import hashlib
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from ..base import CmdContext, EngineBase, SpawnConfig

log = logging.getLogger(__name__)

INSTANCE_ID_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"
INSTANCE_ID_LENGTH = 4

_BATCH_METHODS = frozenset({
    "decompile_batch", "decompile_all", "search_code",
    "exec", "get_strings",
})

# PE / ELF / Mach-O magic bytes
_NATIVE_MAGIC = {
    b"MZ": "PE",
    b"\x7fELF": "ELF",
    b"\xfe\xed\xfa\xce": "Mach-O 32",
    b"\xfe\xed\xfa\xcf": "Mach-O 64",
    b"\xce\xfa\xed\xfe": "Mach-O 32 LE",
    b"\xcf\xfa\xed\xfe": "Mach-O 64 LE",
    b"\xca\xfe\xba\xbe": "FAT Mach-O",
}


class IDAEngine(EngineBase):
    """IDA Pro headless analysis engine."""

    @property
    def engine_name(self) -> str:
        return "ida"

    @property
    def db_extension(self) -> str:
        return ".i64"

    def make_instance_id(self, binary_path: str) -> str:
        raw = f"{binary_path}{time.time()}{os.getpid()}"
        h = int(hashlib.md5(raw.encode()).hexdigest(), 16)
        base = len(INSTANCE_ID_CHARS)
        result = ""
        for _ in range(INSTANCE_ID_LENGTH):
            result = INSTANCE_ID_CHARS[h % base] + result
            h //= base
        return result

    def build_spawn_config(
        self, config: dict, binary_path: str, instance_id: str, **kwargs: Any
    ) -> SpawnConfig:
        log.debug("build_spawn_config: iid=%s binary=%s kwargs=%s",
                  instance_id, os.path.basename(binary_path), list(kwargs.keys()))
        ida_cfg = config.get("ida", {})
        install_dir = ida_cfg.get("install_dir", "")
        server_script = os.path.join(
            os.path.dirname(__file__), "server", "ida_server.py",
        )
        config_path = kwargs.get("config_path") or ""
        idb_path = kwargs.get("idb_path", "")
        log_path = kwargs.get("log_path", "")

        # Fall back to default config path when not explicitly provided
        if not config_path:
            config_path = str(Path.home() / ".revkit" / "config.json")

        cmd = [
            sys.executable, server_script, binary_path,
            "--id", instance_id,
            "--idb", idb_path,
            "--log", log_path,
            "--config", config_path,
        ]
        if kwargs.get("fresh"):
            cmd.append("--fresh")
        if kwargs.get("arch"):
            cmd.extend(["--arch", kwargs["arch"]])

        env = os.environ.copy()
        env["IDADIR"] = install_dir

        from ...core.logging_setup import get_instance_stderr_path
        stderr_path = str(get_instance_stderr_path("ida", instance_id))

        log.debug("build_spawn_config: cmd=%s stderr=%s", cmd[:4], stderr_path)
        return SpawnConfig(
            cmd=cmd,
            env=env,
            log_path=stderr_path,
        )

    def pre_spawn(
        self, config: dict, spawn_config: SpawnConfig, **kwargs: Any
    ) -> None:
        pass

    def get_batch_methods(self) -> frozenset[str]:
        return _BATCH_METHODS

    def build_initial_registry_entry(
        self, instance_id: str, binary_path: str, **kwargs: Any
    ) -> dict:
        return {
            "id": instance_id,
            "engine": self.engine_name,
            "pid": None,
            "port": None,
            "binary": os.path.basename(binary_path),
            "path": os.path.normcase(binary_path),
            "arch": kwargs.get("arch"),
            "bits": kwargs.get("bits"),
            "format": kwargs.get("file_format"),
            "idb_path": kwargs.get("idb_path", ""),
            "log_path": kwargs.get("log_path", ""),
            "state": "initializing",
            "started": time.time(),
            "last_heartbeat": None,
        }

    def register_commands(self, subparsers: Any) -> None:
        from .commands import (
            # instance (local 5)
            cmd_init, cmd_check, cmd_restart, cmd_logs, cmd_cleanup,
            # analysis (RPC proxy 18)
            cmd_proxy_segments, cmd_proxy_decompile, cmd_proxy_decompile_batch,
            cmd_proxy_disasm, cmd_proxy_xrefs, cmd_proxy_callers,
            cmd_proxy_callees, cmd_proxy_find_func, cmd_proxy_func_info,
            cmd_proxy_imagebase, cmd_proxy_bytes, cmd_proxy_find_pattern,
            cmd_proxy_comments, cmd_proxy_methods, cmd_proxy_summary,
            cmd_proxy_exec, cmd_proxy_save, cmd_shell,
            # modification (RPC proxy 7)
            cmd_proxy_rename, cmd_proxy_set_type, cmd_proxy_comment,
            cmd_patch, cmd_search_const, cmd_auto_rename, cmd_rename_batch,
            # types (RPC 5)
            cmd_structs, cmd_enums, cmd_type_info, cmd_vtables, cmd_sigs,
            # diff (3)
            cmd_diff, cmd_compare, cmd_code_diff,
            # advanced (RPC 10)
            cmd_callgraph, cmd_cross_refs, cmd_decompile_all,
            cmd_search_code, cmd_strings_xrefs, cmd_func_similarity,
            cmd_data_refs, cmd_basic_blocks, cmd_stack_frame, cmd_switch_table,
            # report (6)
            cmd_bookmark, cmd_profile, cmd_report, cmd_annotations,
            cmd_snapshot, cmd_export_script,
            # batch (1)
            cmd_batch,
            # utility (local 2)
            cmd_update, cmd_completions,
        )

        # ── instance (local — no _inject_common_options) ──

        p = subparsers.add_parser("init", help="Create revkit directories")
        p.set_defaults(func=cmd_init)

        p = subparsers.add_parser("check", help="Check IDA/Python environment")
        p.set_defaults(func=cmd_check)

        p = subparsers.add_parser("restart", help="Stop and re-start an instance")
        p.add_argument("--fresh", action="store_true", help="Ignore cached database")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_restart)

        p = subparsers.add_parser("logs", help="Show instance log")
        p.add_argument("-f", "--follow", action="store_true", help="Follow log output")
        p.add_argument("--tail", type=int, default=50, help="Number of lines (default: 50)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_logs)

        p = subparsers.add_parser("cleanup", help="Remove stale logs and tokens")
        p.add_argument("--dry-run", action="store_true", help="Show what would be deleted")
        p.set_defaults(func=cmd_cleanup)

        # ── analysis (RPC — _inject_common_options) ──

        p = subparsers.add_parser("segments", help="List binary segments")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_segments)

        p = subparsers.add_parser("decompile", help="Decompile function at address")
        p.add_argument("addr", help="Function address")
        p.add_argument("--with-xrefs", action="store_true", help="Include xref info")
        p.add_argument("--raw", action="store_true", help="Raw output without header")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        p.add_argument("--markdown", action="store_true", help="Markdown format output")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_decompile)

        p = subparsers.add_parser("decompile-batch", help="Decompile multiple functions")
        p.add_argument("addrs", nargs="+", help="Function addresses")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        p.add_argument("--markdown", action="store_true", help="Markdown format output")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_decompile_batch)

        p = subparsers.add_parser("disasm", help="Disassemble at address")
        p.add_argument("addr", help="Start address")
        p.add_argument("--count", type=int, help="Number of instructions")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_disasm)

        p = subparsers.add_parser("xrefs", help="Cross-references for address")
        p.add_argument("addr", help="Target address")
        p.add_argument("--direction", choices=["to", "from", "both"], default="to",
                        help="Xref direction (default: to)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_xrefs)

        p = subparsers.add_parser("callers", help="Who calls this function")
        p.add_argument("addr", help="Function address")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_callers)

        p = subparsers.add_parser("callees", help="What this function calls")
        p.add_argument("addr", help="Function address")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_callees)

        p = subparsers.add_parser("find-func", help="Search functions by name")
        p.add_argument("name", help="Function name or pattern")
        p.add_argument("--regex", action="store_true", help="Use regex matching")
        p.add_argument("--max", type=int, help="Max results")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_find_func)

        p = subparsers.add_parser("func-info", help="Function detail info")
        p.add_argument("addr", help="Function address")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_func_info)

        p = subparsers.add_parser("imagebase", help="Show image base address")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_imagebase)

        p = subparsers.add_parser("bytes", help="Read raw bytes at address")
        p.add_argument("addr", help="Start address")
        p.add_argument("--size", type=int, default=16, help="Number of bytes (default: 16)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_bytes)

        p = subparsers.add_parser("find-pattern", help="Search hex byte pattern")
        p.add_argument("pattern", help="Hex byte pattern (e.g. 'CC CC 90')")
        p.add_argument("--max", type=int, help="Max results")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_find_pattern)

        p = subparsers.add_parser("comments", help="Get comments at address")
        p.add_argument("addr", help="Target address")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_comments)

        p = subparsers.add_parser("methods", help="List available RPC methods")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_methods)

        p = subparsers.add_parser("summary", help="Binary analysis summary")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_summary)

        p = subparsers.add_parser("exec", help="Execute IDA Python code or script file")
        p.add_argument("code", help="Inline code or .py path (short: analysis/find_crypto.py)")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_exec)

        p = subparsers.add_parser("save", help="Save IDA database")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_save)

        p = subparsers.add_parser("shell", help="Interactive IDA Python REPL")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_shell)

        # ── modification (RPC — _inject_common_options) ──

        p = subparsers.add_parser("rename", help="Rename symbol at address")
        p.add_argument("addr", help="Symbol address")
        p.add_argument("name", help="New name")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_rename)

        p = subparsers.add_parser("set-type", help="Set type at address (full IDA declaration)")
        p.add_argument("addr", help="Target address")
        p.add_argument("type_str", help="Full IDA type: 'int __fastcall func(int a1, char *a2)'")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_set_type)

        p = subparsers.add_parser("comment", help="Set comment at address")
        p.add_argument("addr", help="Target address")
        p.add_argument("text", help="Comment text")
        p.add_argument("--repeatable", action="store_true", help="Repeatable comment")
        p.add_argument("--type", help="Comment type")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_proxy_comment)

        p = subparsers.add_parser("patch", help="Patch bytes at address")
        p.add_argument("addr", help="Target address")
        p.add_argument("hex_bytes", nargs="+", help="Hex bytes (e.g. 90 90 CC)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_patch)

        p = subparsers.add_parser("search-const", help="Search constant/immediate values")
        p.add_argument("value", help="Value to search")
        p.add_argument("--max", type=int, help="Max results")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_search_const)

        p = subparsers.add_parser("auto-rename", help="Heuristic auto-rename sub_ functions")
        p.add_argument("--apply", action="store_true", help="Actually rename (default: dry run)")
        p.add_argument("--max-funcs", type=int, default=200, help="Max functions to process")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_auto_rename)

        p = subparsers.add_parser("rename-batch", help="Batch rename from CSV/JSON file")
        p.add_argument("--file", required=True, dest="input_file", help="CSV or JSON file with addr,name pairs")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_rename_batch)

        # ── types (RPC — _inject_common_options) ──

        p = subparsers.add_parser("structs", help="Manage structs and unions")
        p.add_argument("--action", choices=["list", "show", "create"], default="list",
                        help="Action (default: list)")
        p.add_argument("--name", help="Struct name (for show/create)")
        p.add_argument("--filter", help="Name filter pattern")
        p.add_argument("--offset", type=int, help="List offset")
        p.add_argument("--count", type=int, help="Number to show")
        p.add_argument("--union", action="store_true", help="Create as union")
        p.add_argument("--members", nargs="+", help="Members (name:size ...)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_structs)

        p = subparsers.add_parser("enums", help="Manage enums")
        p.add_argument("--action", choices=["list", "show", "create"], default="list",
                        help="Action (default: list)")
        p.add_argument("--name", help="Enum name (for show/create)")
        p.add_argument("--filter", help="Name filter pattern")
        p.add_argument("--offset", type=int, help="List offset")
        p.add_argument("--count", type=int, help="Number to show")
        p.add_argument("--members", nargs="+", help="Members (name=value ...)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_enums)

        p = subparsers.add_parser("type-info", help="Query local types")
        p.add_argument("--action", choices=["list", "show"], default="list",
                        help="Action (default: list)")
        p.add_argument("--name", help="Type name (for show)")
        p.add_argument("--filter", help="Name filter pattern")
        p.add_argument("--kind", help="Type kind filter")
        p.add_argument("--offset", type=int, help="List offset")
        p.add_argument("--count", type=int, help="Number to show")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_type_info)

        p = subparsers.add_parser("vtables", help="Detect virtual function tables")
        p.add_argument("--max", type=int, help="Max results")
        p.add_argument("--min-entries", type=int, help="Min vtable entries")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_vtables)

        p = subparsers.add_parser("sigs", help="Manage FLIRT signatures")
        p.add_argument("--action", choices=["list", "apply"], default="list",
                        help="Action (default: list)")
        p.add_argument("sig_name", nargs="?", help="Signature name (for apply)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_sigs)

        # ── diff (mixed local+RPC) ──

        p = subparsers.add_parser("diff", help="Compare functions between two instances")
        p.add_argument("instance_a", help="First instance ID or binary hint")
        p.add_argument("instance_b", help="Second instance ID or binary hint")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_diff)

        p = subparsers.add_parser("compare", help="Patch diff two binary versions")
        p.add_argument("binary_a", help="First binary path")
        p.add_argument("binary_b", help="Second binary path")
        p.add_argument("--idb-dir", help="IDB storage directory")
        p.add_argument("--out", metavar="PATH", help="Save diff report to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_compare)

        p = subparsers.add_parser("code-diff", help="Compare decompiled code between instances")
        p.add_argument("instance_a", help="First instance ID or binary hint")
        p.add_argument("instance_b", help="Second instance ID or binary hint")
        p.add_argument("--functions", nargs="+", help="Function names to compare")
        p.add_argument("--out", metavar="PATH", help="Save diff to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_code_diff)

        # ── advanced (RPC — _inject_common_options) ──

        p = subparsers.add_parser("callgraph", help="Generate function call graph")
        p.add_argument("addr", help="Root function address")
        p.add_argument("--format", choices=["mermaid", "dot"], default="mermaid",
                        help="Output format (default: mermaid)")
        p.add_argument("--depth", type=int, default=3, help="Max depth (default: 3)")
        p.add_argument("--direction", choices=["callers", "callees"], default="callees",
                        help="Graph direction (default: callees)")
        p.add_argument("--out", metavar="PATH", help="Save graph to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_callgraph)

        p = subparsers.add_parser("cross-refs", help="Multi-level xref chain tracing")
        p.add_argument("addr", help="Target address")
        p.add_argument("--depth", type=int, default=3, help="Max depth (default: 3)")
        p.add_argument("--direction", choices=["to", "from"], default="to",
                        help="Direction (default: to)")
        p.add_argument("--format", choices=["mermaid", "dot"], help="Graph output format")
        p.add_argument("--out", metavar="PATH", help="Save to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_cross_refs)

        p = subparsers.add_parser("decompile-all", help="Decompile all functions to file")
        p.add_argument("--out", required=True, help="Output file or directory")
        p.add_argument("--split", action="store_true", help="One file per function")
        p.add_argument("--filter", help="Function name filter")
        p.add_argument("--include-thunks", action="store_true", help="Include thunk functions")
        p.add_argument("--include-libs", action="store_true", help="Include library functions")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_decompile_all)

        p = subparsers.add_parser("search-code", help="Search within decompiled pseudocode")
        p.add_argument("query", help="Search query string")
        p.add_argument("--max", type=int, help="Max results")
        p.add_argument("--max-funcs", type=int, help="Max functions to scan")
        p.add_argument("--case-sensitive", action="store_true", help="Case-sensitive search")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_search_code)

        p = subparsers.add_parser("strings-xrefs", help="Strings with referencing functions")
        p.add_argument("--filter", help="String value filter")
        p.add_argument("--max", type=int, help="Max results")
        p.add_argument("--min-refs", type=int, help="Min reference count")
        p.add_argument("--out", metavar="PATH", help="Save to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_strings_xrefs)

        p = subparsers.add_parser("func-similarity", help="Compare two functions by similarity")
        p.add_argument("addr_a", help="First function address")
        p.add_argument("addr_b", help="Second function address")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_func_similarity)

        p = subparsers.add_parser("data-refs", help="Data segment reference analysis")
        p.add_argument("--filter", help="Name filter")
        p.add_argument("--segment", help="Segment name filter")
        p.add_argument("--max", type=int, help="Max results")
        p.add_argument("--out", metavar="PATH", help="Save to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_data_refs)

        p = subparsers.add_parser("basic-blocks", help="Basic blocks and CFG for a function")
        p.add_argument("addr", help="Function address")
        p.add_argument("--format", choices=["mermaid", "dot"], default="mermaid",
                        help="Graph format (default: mermaid)")
        p.add_argument("--graph-only", action="store_true", help="Only output graph, no block details")
        p.add_argument("--out", metavar="PATH", help="Save graph to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_basic_blocks)

        p = subparsers.add_parser("stack-frame", help="Show stack frame layout")
        p.add_argument("addr", help="Function address")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_stack_frame)

        p = subparsers.add_parser("switch-table", help="Analyze switch/jump tables")
        p.add_argument("addr", help="Function address")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_switch_table)

        # ── report (mixed) ──

        p = subparsers.add_parser("bookmark", help="Manage analysis bookmarks")
        p.add_argument("--action", choices=["add", "remove", "list"], default="list",
                        help="Action (default: list)")
        p.add_argument("addr", nargs="?", help="Address (for add/remove)")
        p.add_argument("tag", nargs="?", help="Tag name (for add)")
        p.add_argument("--note", help="Bookmark note")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_bookmark)

        p = subparsers.add_parser("profile", help="Run analysis profile")
        p.add_argument("--action", choices=["list", "run"], default="list",
                        help="Action (default: list)")
        p.add_argument("profile_name", nargs="?", help="Profile name (for run)")
        p.add_argument("--out-dir", help="Output directory for results")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_profile)

        p = subparsers.add_parser("report", help="Generate analysis report (Markdown/HTML)")
        p.add_argument("output", nargs="?", default=None, help="Output file path (.md or .html)")
        p.add_argument("--report-out", dest="output", help="Output file path (alias)")
        p.add_argument("--functions", nargs="+", help="Function addresses to decompile")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_report)

        p = subparsers.add_parser("annotations", help="Export/import analysis annotations")
        p.add_argument("--action", choices=["export", "import"], default="export",
                        help="Action (default: export)")
        p.add_argument("--out", metavar="PATH", help="Output file (for export)")
        p.add_argument("input_file", nargs="?", help="Input file (for import)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_annotations)

        p = subparsers.add_parser("snapshot", help="Manage IDB snapshots")
        p.add_argument("--action", choices=["save", "list", "restore"], default="list",
                        help="Action (default: list)")
        p.add_argument("--description", help="Snapshot description (for save)")
        p.add_argument("filename", nargs="?", help="Snapshot filename (for restore)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_snapshot)

        p = subparsers.add_parser("export-script", help="Generate IDAPython script from modifications")
        p.add_argument("--out", default="analysis.py", help="Output file (default: analysis.py)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_export_script)

        # ── batch (local+RPC) ──

        p = subparsers.add_parser("batch", help="Analyze all binaries in a directory")
        p.add_argument("directory", help="Directory with binary files")
        p.add_argument("--idb-dir", help="IDB storage directory")
        p.add_argument("--fresh", action="store_true", help="Ignore cached databases")
        p.add_argument("--timeout", type=int, default=300, help="Timeout per instance (default: 300)")
        p.add_argument("--keep", action="store_true", help="Keep instances running after analysis")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_batch)

        # ── utility (local — no _inject_common_options) ──

        p = subparsers.add_parser("update", help="Self-update from git repository")
        p.set_defaults(func=cmd_update)

        p = subparsers.add_parser("completions", help="Generate shell completion scripts")
        p.add_argument("--shell", choices=["bash", "zsh", "powershell"], default="bash",
                        help="Shell type (default: bash)")
        p.set_defaults(func=cmd_completions)

    def validate_installation(self) -> bool:
        ida_dir = os.environ.get("IDADIR", "")
        if not ida_dir or not os.path.isdir(ida_dir):
            return False
        try:
            import importlib
            importlib.import_module("idalib")
            return True
        except ImportError:
            return False

    def detect_binary(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                header = f.read(4)
            return any(header.startswith(magic) for magic in _NATIVE_MAGIC)
        except OSError:
            return False
