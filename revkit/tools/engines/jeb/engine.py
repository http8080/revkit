"""revkit engines — JEBEngine implementation."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from ..base import CmdContext, EngineBase, SpawnConfig

log = logging.getLogger(__name__)

INSTANCE_ID_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"
INSTANCE_ID_LENGTH = 4

_BATCH_METHODS = frozenset({
    "decompile_all", "search_code", "security_scan",
    "get_strings", "get_imports", "get_exports",
    "get_all_classes", "get_all_methods",
})

_APK_MAGIC = b"PK\x03\x04"
_DEX_MAGIC = b"dex\n"


class JEBEngine(EngineBase):
    """JEB headless analysis engine."""

    @property
    def engine_name(self) -> str:
        return "jeb"

    @property
    def db_extension(self) -> str:
        return ".jdb2"

    def make_instance_id(self, binary_path: str) -> str:
        basename = os.path.splitext(os.path.basename(binary_path))[0]
        clean = re.sub(r"[^a-z0-9-]", "-", basename.lower())
        clean = re.sub(r"-+", "-", clean).strip("-")
        if len(clean) > 20:
            clean = clean[:20].rstrip("-")

        raw = f"{binary_path}{time.time()}{os.getpid()}"
        h = int(hashlib.md5(raw.encode()).hexdigest(), 16)
        base = len(INSTANCE_ID_CHARS)
        suffix = ""
        for _ in range(INSTANCE_ID_LENGTH):
            suffix = INSTANCE_ID_CHARS[h % base] + suffix
            h //= base
        return f"{clean}_{suffix}" if clean else suffix

    def build_spawn_config(
        self, config: dict, binary_path: str, instance_id: str, **kwargs: Any
    ) -> SpawnConfig:
        log.debug("build_spawn_config: iid=%s binary=%s kwargs=%s",
                  instance_id, os.path.basename(binary_path), list(kwargs.keys()))
        jeb_cfg = config.get("jeb", {})
        jeb_dir = jeb_cfg.get("install_dir", "")
        server_script = os.path.join(
            os.path.dirname(__file__), "server", "jeb_server.py",
        )
        config_path = kwargs.get("config_path") or ""
        project_path = kwargs.get("project_path", "")
        log_path = kwargs.get("log_path", "")
        fresh = kwargs.get("fresh", False)
        xmx = kwargs.get("xmx")

        # Fall back to default config path when not explicitly provided
        if not config_path:
            config_path = str(Path.home() / ".revkit" / "config.json")

        extra_args = [
            binary_path, instance_id, project_path,
            log_path, config_path,
        ]
        if fresh:
            extra_args.append("--fresh")

        heap = self._compute_xmx(binary_path, config, xmx)
        spawn_method = jeb_cfg.get("spawn_method", "wrapper")
        cp_sep = ";" if sys.platform == "win32" else ":"

        if spawn_method == "bat":
            launcher = self._get_launcher_name()
            cmd = [
                os.path.join(jeb_dir, launcher),
                "-c", f"--script={server_script}", "--",
            ] + extra_args
        else:
            java_path = self._resolve_java(config, jeb_dir)
            jvm_opts = list(jeb_cfg.get("jvm_opts", []))
            jvm_opts = [o for o in jvm_opts if not o.startswith("-Xmx")]
            if heap:
                jvm_opts.insert(0, f"-Xmx{heap}")
            cmd = [java_path] + jvm_opts + [
                "-cp",
                os.path.join(jeb_dir, "bin", "app", "*") + cp_sep + ".",
                "JebScriptRunner", server_script, "--",
            ] + extra_args

        from ...core.logging_setup import get_instance_stderr_path
        stderr_path = str(get_instance_stderr_path("jeb", instance_id))

        log.debug("build_spawn_config: spawn_method=%s heap=%s cmd=%s",
                  spawn_method, heap, cmd[:4])
        return SpawnConfig(
            cmd=cmd,
            cwd=jeb_dir,
            log_path=stderr_path,
        )

    def pre_spawn(
        self, config: dict, spawn_config: SpawnConfig, **kwargs: Any
    ) -> None:
        jeb_cfg = config.get("jeb", {})
        if jeb_cfg.get("spawn_method") == "bat":
            heap = kwargs.get("xmx") or self._compute_xmx(
                kwargs.get("binary_path", ""), config
            )
            if heap:
                self._update_jvmopt_xmx(jeb_cfg.get("install_dir", ""), heap)

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
            "project_path": kwargs.get("project_path", ""),
            "log_path": kwargs.get("log_path", ""),
            "state": "initializing",
            "started": time.time(),
            "last_heartbeat": None,
        }

    def register_commands(self, subparsers: Any) -> None:
        from .commands import (
            # instance (local 5 + RPC 1)
            cmd_init, cmd_check, cmd_restart, cmd_logs, cmd_cleanup,
            cmd_save,
            # analysis (RPC proxy 13)
            cmd_method, cmd_decompile, cmd_decompile_diff,
            cmd_decompile_batch, cmd_decompile_all,
            cmd_smali, cmd_strings, cmd_classes,
            cmd_methods_of_class, cmd_fields_of_class,
            cmd_method_info, cmd_methods, cmd_native_methods,
            # recon (RPC proxy 9)
            cmd_summary, cmd_permissions, cmd_components,
            cmd_info, cmd_main_activity, cmd_app_class,
            cmd_resources, cmd_resource, cmd_manifest,
            # search (RPC proxy 4)
            cmd_search_classes, cmd_search_methods,
            cmd_search_code, cmd_strings_xrefs,
            # modification (RPC proxy 11)
            cmd_rename, cmd_rename_class, cmd_rename_method,
            cmd_rename_field, cmd_rename_batch, cmd_rename_preview,
            cmd_auto_rename, cmd_set_comment, cmd_get_comments,
            cmd_undo, cmd_bookmark,
            # xrefs (RPC proxy 5)
            cmd_xrefs, cmd_callers, cmd_callees,
            cmd_callgraph, cmd_cross_refs,
            # report (mixed 8)
            cmd_annotations_export, cmd_annotations_import, cmd_annotations,
            cmd_snapshot_save, cmd_snapshot_list, cmd_snapshot_restore,
            cmd_snapshot, cmd_report,
            # security (RPC proxy 2)
            cmd_entry_points, cmd_security_scan,
            # tooling (local 4)
            cmd_gen_runner, cmd_patch, cmd_unpatch, cmd_merge,
            # config (local 2)
            cmd_config_show, cmd_config_set,
            # batch (1)
            cmd_batch,
            # utility (mixed 2)
            cmd_exec, cmd_completion,
        )

        # ── instance — local (no _inject_common_options) ─────

        p = subparsers.add_parser("init", help="Create JEB data directories")
        p.set_defaults(func=cmd_init)

        p = subparsers.add_parser("check", help="Verify JEB environment")
        p.set_defaults(func=cmd_check)

        p = subparsers.add_parser("restart", help="Restart a JEB instance")
        p.add_argument("--fresh", action="store_true", help="Force fresh analysis")
        p.add_argument("--wait", action="store_true", help="Wait for ready after restart")
        p.add_argument("--xmx", metavar="SIZE", help="JVM heap size (e.g. 4G)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_restart)

        p = subparsers.add_parser("logs", help="Show instance log output")
        p.add_argument("-f", "--follow", action="store_true", help="Follow log output")
        p.add_argument("--tail", type=int, default=50, help="Number of lines (default: 50)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_logs)

        p = subparsers.add_parser("cleanup", help="Clean stale logs and tokens")
        p.add_argument("--dry-run", action="store_true", help="Preview without deleting")
        p.add_argument("--all", action="store_true", help="Stop and clean all instances")
        p.set_defaults(func=cmd_cleanup)

        # ── instance — RPC (needs _inject_common_options) ────

        p = subparsers.add_parser("save", help="Save JEB project database")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_save)

        # ── analysis — RPC proxy ─────────────────────────────

        p = subparsers.add_parser("method", help="Decompile a single method")
        p.add_argument("method_sig", help="Method DEX signature (e.g. Lcom/example/Foo;->bar()V)")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        p.add_argument("--with-xrefs", action="store_true", help="Include xref info")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_method)

        p = subparsers.add_parser("decompile", help="Decompile class or method")
        p.add_argument("sig", help="DEX signature (class or method)")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        p.add_argument("--auto-out", action="store_true", help="Auto-generate output filename")
        p.add_argument("--with-xrefs", action="store_true", help="Include xref info")
        p.add_argument("--line-numbers", action="store_true", help="Show line numbers")
        p.add_argument("--no-limit", action="store_true", help="Bypass inline truncation")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_decompile)

        p = subparsers.add_parser("decompile-diff", help="Compare decompile with saved file or previous version")
        p.add_argument("sig", help="DEX signature")
        p.add_argument("diff_file", nargs="?", default=None, help="File to diff against (local mode). Omit for server-side previous version comparison (remote mode).")
        p.add_argument("--out", metavar="PATH", help="Save diff to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_decompile_diff)

        p = subparsers.add_parser("decompile-batch", help="Decompile multiple classes/methods")
        p.add_argument("sigs", nargs="+", help="DEX signatures")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        p.add_argument("--md-out", action="store_true", help="Markdown format output")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_decompile_batch)

        p = subparsers.add_parser("decompile-all", help="Decompile all classes to file(s)")
        p.add_argument("--out", required=True, help="Output path")
        p.add_argument("--split", action="store_true", help="Split into per-class files")
        p.add_argument("--package", metavar="PKG", help="Filter by package (e.g. com.example)")
        p.add_argument("--filter", metavar="PATTERN", help="Filter pattern")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_decompile_all)

        p = subparsers.add_parser("smali", help="Get Smali bytecode for class/method")
        p.add_argument("class_sig", help="Class or method DEX signature")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_smali)

        p = subparsers.add_parser("strings", help="List strings")
        p.add_argument("--offset", type=int, help="Start offset")
        p.add_argument("--limit", type=int, help="Max results")
        p.add_argument("--min-len", type=int, help="Minimum string length")
        p.add_argument("--regex", metavar="PATTERN", help="Filter by regex")
        p.add_argument("--encoding", help="Filter by encoding (e.g. utf-8, ascii)")
        p.add_argument("--count-only", action="store_true", help="Show count only")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_strings)

        p = subparsers.add_parser("classes", help="List classes")
        p.add_argument("--offset", type=int, help="Start offset")
        p.add_argument("--limit", type=int, help="Max results")
        p.add_argument("--count-only", action="store_true", help="Show count only")
        p.add_argument("--tree", action="store_true", help="Show as package tree")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_classes)

        p = subparsers.add_parser("methods-of-class", help="List methods of a class")
        p.add_argument("class_sig", help="Class DEX signature (e.g. Lcom/example/Foo;)")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_methods_of_class)

        p = subparsers.add_parser("fields-of-class", help="List fields of a class")
        p.add_argument("class_sig", help="Class DEX signature")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_fields_of_class)

        p = subparsers.add_parser("method-info", help="Show method details")
        p.add_argument("method_sig", help="Method DEX signature")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_method_info)

        p = subparsers.add_parser("methods", help="List methods (RPC or of a class)")
        p.add_argument("class_sig", nargs="?", help="Class DEX signature (optional)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_methods)

        p = subparsers.add_parser("native-methods", help="List native method declarations")
        p.add_argument("--filter", metavar="PATTERN", help="Filter pattern")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_native_methods)

        # ── recon — RPC proxy ────────────────────────────────

        p = subparsers.add_parser("summary", help="Display binary overview")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        p.add_argument("--md-out", action="store_true", help="Markdown format output")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_summary)

        p = subparsers.add_parser("permissions", help="List Android permissions")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_permissions)

        p = subparsers.add_parser("components", help="List Android components")
        p.add_argument("--type", choices=["activity", "service", "receiver", "provider"],
                        help="Filter by component type")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_components)

        p = subparsers.add_parser("info", help="Show APK metadata")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_info)

        p = subparsers.add_parser("main-activity", help="Show main activity class")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_main_activity)

        p = subparsers.add_parser("app-class", help="Show Application class")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_app_class)

        p = subparsers.add_parser("resources", help="List APK resource files")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_resources)

        p = subparsers.add_parser("resource", help="Get content of a resource file")
        p.add_argument("path", help="Resource path within APK")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_resource)

        p = subparsers.add_parser("manifest", help="Show AndroidManifest.xml")
        p.add_argument("--component", metavar="NAME", help="Filter by component name or tag")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_manifest)

        # ── search — RPC proxy ───────────────────────────────

        p = subparsers.add_parser("search-classes", help="Search classes by keyword")
        p.add_argument("keyword", help="Search keyword")
        p.add_argument("--max", type=int, help="Max results")
        p.add_argument("--regex", action="store_true", help="Use regex matching")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_search_classes)

        p = subparsers.add_parser("search-methods", help="Search methods by name")
        p.add_argument("name", help="Method name to search")
        p.add_argument("--max", type=int, help="Max results")
        p.add_argument("--regex", action="store_true", help="Use regex matching")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_search_methods)

        p = subparsers.add_parser("search-code", help="Search within decompiled source")
        p.add_argument("query", help="Search query")
        p.add_argument("--max-results", type=int, help="Max results")
        p.add_argument("--case-sensitive", action="store_true", help="Case-sensitive search")
        p.add_argument("--context", type=int, help="Context lines around match")
        p.add_argument("--regex", action="store_true", help="Use regex matching")
        p.add_argument("--package", metavar="PKG", help="Filter by package")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_search_code)

        p = subparsers.add_parser("strings-xrefs", help="List strings with cross-references")
        p.add_argument("--filter", metavar="PATTERN", help="Filter pattern")
        p.add_argument("--max", type=int, help="Max results")
        p.add_argument("--min-refs", type=int, help="Minimum reference count")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_strings_xrefs)

        # ── modification — RPC proxy ─────────────────────────

        p = subparsers.add_parser("rename", help="Rename class/method/field (auto-detect)")
        p.add_argument("sig", help="DEX signature to rename")
        p.add_argument("new_name", help="New name")
        p.add_argument("--preview", action="store_true", help="Preview impact without applying")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_rename)

        p = subparsers.add_parser("rename-class", help="Rename a class")
        p.add_argument("class_sig", help="Class DEX signature")
        p.add_argument("new_name", help="New class name")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_rename_class)

        p = subparsers.add_parser("rename-method", help="Rename a method")
        p.add_argument("method_sig", help="Method DEX signature")
        p.add_argument("new_name", help="New method name")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_rename_method)

        p = subparsers.add_parser("rename-field", help="Rename a field")
        p.add_argument("field_sig", help="Field DEX signature")
        p.add_argument("new_name", help="New field name")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_rename_field)

        p = subparsers.add_parser("rename-batch", help="Batch rename from JSON file")
        p.add_argument("--file", required=True, dest="json_file", help="JSON file with rename entries")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_rename_batch)

        p = subparsers.add_parser("rename-preview", help="Preview rename impact")
        p.add_argument("sig", help="DEX signature")
        p.add_argument("new_name", help="New name")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_rename_preview)

        p = subparsers.add_parser("auto-rename", help="Heuristic auto-rename obfuscated names")
        p.add_argument("--max-classes", type=int, default=100, help="Max classes to process")
        p.add_argument("--apply", action="store_true", help="Apply renames (default: preview)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_auto_rename)

        p = subparsers.add_parser("set-comment", help="Set comment at address/signature")
        p.add_argument("addr", help="Address or signature")
        p.add_argument("text", help="Comment text")
        p.add_argument("--type", metavar="TYPE", help="Comment type")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_set_comment)

        p = subparsers.add_parser("get-comments", help="Get comments")
        p.add_argument("addr", nargs="?", help="Address (optional, all if omitted)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_get_comments)

        p = subparsers.add_parser("undo", help="Undo last rename or comment")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_undo)

        p = subparsers.add_parser("bookmark", help="Manage bookmarks")
        p.add_argument("--action", choices=["add", "list", "remove"], default="list",
                        help="Bookmark action (default: list)")
        p.add_argument("sig", nargs="?", help="DEX signature (for add/remove)")
        p.add_argument("--note", metavar="TEXT", help="Bookmark note (for add)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_bookmark)

        # ── xrefs — RPC proxy ────────────────────────────────

        p = subparsers.add_parser("xrefs", help="Show cross-references")
        p.add_argument("sig", help="DEX signature")
        p.add_argument("--direction", choices=["to", "from", "both"], default="to",
                        help="Xref direction (default: to)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_xrefs)

        p = subparsers.add_parser("callers", help="Show who calls this (xrefs to)")
        p.add_argument("sig", help="DEX signature")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_callers)

        p = subparsers.add_parser("callees", help="Show what this calls (xrefs from)")
        p.add_argument("sig", help="DEX signature")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_callees)

        p = subparsers.add_parser("callgraph", help="Generate call graph")
        p.add_argument("class_sig", help="Class DEX signature")
        p.add_argument("--depth", type=int, default=3, help="Graph depth (default: 3)")
        p.add_argument("--direction", choices=["callers", "callees"], help="Graph direction")
        p.add_argument("--exclude", metavar="PATTERN", help="Exclude pattern")
        p.add_argument("--format", choices=["mermaid", "dot", "svg", "png"],
                        default="mermaid", help="Output format (default: mermaid)")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_callgraph)

        p = subparsers.add_parser("cross-refs", help="Multi-level xref chain tracing")
        p.add_argument("sig", help="DEX signature")
        p.add_argument("--depth", type=int, default=3, help="Trace depth (default: 3)")
        p.add_argument("--direction", choices=["to", "from", "both"], default="to", help="Trace direction (default: to)")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_cross_refs)

        # ── report — mixed ───────────────────────────────────

        p = subparsers.add_parser("annotations-export", help="Export annotations to JSON")
        p.add_argument("--out", metavar="PATH", help="Output file (default: annotations.json)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_annotations_export)

        p = subparsers.add_parser("annotations-import", help="Import annotations from JSON")
        p.add_argument("file", help="JSON file to import")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_annotations_import)

        p = subparsers.add_parser("annotations", help="Export or import annotations")
        p.add_argument("--action", choices=["export", "import"], default="export",
                        help="Action (default: export)")
        p.add_argument("--out", metavar="PATH", help="Output file (for export)")
        p.add_argument("file", nargs="?", help="Input file (for import)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_annotations)

        p = subparsers.add_parser("snapshot-save", help="Save project snapshot")
        p.add_argument("--description", metavar="TEXT", help="Snapshot description")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_snapshot_save)

        p = subparsers.add_parser("snapshot-list", help="List project snapshots")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_snapshot_list)

        p = subparsers.add_parser("snapshot-restore", help="Restore from snapshot")
        p.add_argument("filename", help="Snapshot filename")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_snapshot_restore)

        p = subparsers.add_parser("snapshot", help="Manage snapshots")
        p.add_argument("--action", choices=["save", "list", "restore"], default="list",
                        help="Action (default: list)")
        p.add_argument("--description", metavar="TEXT", help="Description (for save)")
        p.add_argument("filename", nargs="?", help="Snapshot filename (for restore)")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_snapshot)

        p = subparsers.add_parser("report", help="Generate markdown analysis report")
        p.add_argument("--out", metavar="PATH", required=True, help="Output file path")
        p.add_argument("--decompile", nargs="*", metavar="SIG",
                        help="DEX signatures to include decompiled source")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_report)

        # ── security — RPC proxy ─────────────────────────────

        p = subparsers.add_parser("entry-points", help="Analyze attack surface")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_entry_points)

        p = subparsers.add_parser("security-scan", help="Automated security issue detection")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_security_scan)

        # ── tooling — local (no _inject_common_options) ──────

        p = subparsers.add_parser("gen-runner", help="Generate JebScriptRunner.java")
        p.add_argument("--force", action="store_true", help="Regenerate even if up-to-date")
        p.add_argument("--no-compile", action="store_true", help="Skip compilation")
        p.set_defaults(func=cmd_gen_runner)

        p = subparsers.add_parser("patch", help="Patch jeb.jar for --script= support")
        p.add_argument("--status", action="store_true", help="Show patch status only")
        p.add_argument("--force", action="store_true", help="Force re-patch")
        p.set_defaults(func=cmd_patch)

        p = subparsers.add_parser("unpatch", help="Restore original jeb.jar from backup")
        p.set_defaults(func=cmd_unpatch)

        p = subparsers.add_parser("merge", help="Merge split APKs into single APK")
        p.add_argument("input", help="Input directory or XAPK/APKS file")
        p.add_argument("--out", metavar="PATH", help="Output APK path")
        p.add_argument("--start", action="store_true", help="Auto-start JEB analysis after merge")
        p.add_argument("--xmx", metavar="SIZE", help="JVM heap size for analysis")
        p.set_defaults(func=cmd_merge)

        # ── config — local ───────────────────────────────────

        p = subparsers.add_parser("config-show", help="Display current configuration")
        p.set_defaults(func=cmd_config_show)

        p = subparsers.add_parser("config-set", help="Set a config value")
        p.add_argument("key", help="Config key (dot-separated, e.g. jeb.heap.default)")
        p.add_argument("value", help="New value")
        p.set_defaults(func=cmd_config_set)

        # ── batch ────────────────────────────────────────────

        p = subparsers.add_parser("batch", help="Batch-analyze APK/DEX files in directory")
        p.add_argument("directory", help="Directory containing APK/DEX files")
        p.add_argument("--ext", default="apk", help="File extension to match (default: apk)")
        p.add_argument("--keep", action="store_true", help="Keep instances after analysis")
        p.add_argument("--timeout", type=int, default=300, help="Per-file timeout (default: 300s)")
        p.set_defaults(func=cmd_batch)

        # ── utility ──────────────────────────────────────────

        p = subparsers.add_parser("exec", help="Execute Jython code or script file")
        p.add_argument("code", help="Inline code or .py path (short: security/check_webview.py)")
        p.add_argument("--out", metavar="PATH", help="Save output to file")
        self._inject_common_options(p)
        p.set_defaults(func=cmd_exec)

        p = subparsers.add_parser("completion", help="Generate shell completion script")
        p.add_argument("--shell", choices=["bash", "zsh"], default="bash",
                        help="Shell type (default: bash)")
        p.add_argument("--out", metavar="PATH", help="Save to file")
        p.set_defaults(func=cmd_completion)

    def validate_installation(self) -> bool:
        jeb_cfg = self._find_jeb_config()
        if not jeb_cfg:
            return False
        java = self._resolve_java({"jeb": jeb_cfg}, jeb_cfg.get("install_dir", ""))
        if java == "java":
            try:
                subprocess.run(
                    ["java", "-version"],
                    capture_output=True, timeout=5,
                )
            except (OSError, subprocess.TimeoutExpired):
                return False
        return True

    def detect_binary(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                header = f.read(4)
            return header.startswith(_APK_MAGIC) or header.startswith(_DEX_MAGIC)
        except OSError:
            return False

    def compute_resource_opts(
        self,
        binary_path: str,
        config: dict,
        override: dict | None = None,
    ) -> dict:
        xmx = self._compute_xmx(binary_path, config, override and override.get("xmx"))
        return {"xmx": xmx} if xmx else {}

    # ── internal helpers ─────────────────────────────────

    @staticmethod
    def _find_jeb_config() -> dict | None:
        """Locate JEB config from common paths."""
        for env_key in ("JEB_DIR", "JEB_HOME"):
            d = os.environ.get(env_key)
            if d and os.path.isdir(d):
                return {"install_dir": d}
        return None

    @staticmethod
    def _get_launcher_name() -> str:
        if sys.platform == "win32":
            return "jeb_wincon.bat"
        if sys.platform == "darwin":
            return "jeb_macos.sh"
        return "jeb_linux.sh"

    @staticmethod
    def _resolve_java(config: dict, jeb_dir: str) -> str:
        ext = ".exe" if sys.platform == "win32" else ""
        candidates = []
        java_home = config.get("jeb", {}).get("java_home")
        if java_home:
            candidates.append(os.path.join(java_home, "bin", "java" + ext))
        candidates.append(os.path.join(jeb_dir, "bin", "runtime", "bin", "java" + ext))
        env_home = os.environ.get("JAVA_HOME")
        if env_home:
            candidates.append(os.path.join(env_home, "bin", "java" + ext))
        for c in candidates:
            if os.path.isfile(c):
                return c
        return "java"

    @staticmethod
    def _compute_xmx(
        binary_path: str, config: dict, override: str | None = None
    ) -> str:
        if override:
            return override
        heap_cfg = config.get("jeb", {}).get("heap", {})
        if not heap_cfg.get("auto", False):
            return heap_cfg.get("default", "4G")

        try:
            size_mb = os.path.getsize(binary_path) / (1024 * 1024)
        except OSError:
            size_mb = 0

        xmx = heap_cfg.get("default", "4G")
        for rule in sorted(heap_cfg.get("rules", []), key=lambda r: r["max_mb"]):
            if size_mb <= rule["max_mb"]:
                xmx = rule["xmx"]
                break

        ram_gb = JEBEngine._get_system_ram_gb()
        max_cap = heap_cfg.get("max", "16G")
        xmx_gb = min(
            _parse_mem_gb(xmx),
            int(ram_gb * 0.5),
            _parse_mem_gb(max_cap),
        )
        xmx_gb = max(xmx_gb, 2)
        return f"{xmx_gb}G"

    @staticmethod
    def _get_system_ram_gb() -> float:
        # cgroup v2
        try:
            mem_max = Path("/sys/fs/cgroup/memory.max").read_text().strip()
            if mem_max != "max":
                return int(mem_max) / (1024**3)
        except (OSError, ValueError):
            pass
        # cgroup v1
        try:
            limit = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes").read_text().strip()
            gb = int(limit) / (1024**3)
            if gb < 1024:
                return gb
        except (OSError, ValueError):
            pass
        # Linux /proc/meminfo
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / (1024**2)
        except (OSError, ValueError):
            pass
        # psutil (cross-platform, already a dependency)
        try:
            import psutil
            return psutil.virtual_memory().total / (1024**3)
        except ImportError:
            pass
        # Windows fallback (wmic removed in Win11)
        if sys.platform == "win32":
            try:
                out = subprocess.check_output(
                    ["powershell", "-Command",
                     "(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize"],
                    text=True, timeout=10,
                )
                val = out.strip()
                if val.isdigit():
                    return int(val) / (1024**2)
            except (OSError, subprocess.TimeoutExpired):
                pass
        return 8.0  # fallback

    @staticmethod
    def _update_jvmopt_xmx(jeb_dir: str, heap: str) -> None:
        path = os.path.join(jeb_dir, "jvmopt.txt")
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
        except FileNotFoundError:
            lines = []

        out = []
        found = False
        for raw in lines:
            stripped = raw.strip()
            if stripped and not stripped.startswith("#"):
                tokens = [t for t in stripped.split() if not t.startswith("-Xmx")]
                if not found:
                    tokens.insert(0, f"-Xmx{heap}")
                    found = True
                out.append(" ".join(tokens))
            else:
                out.append(raw.rstrip("\n"))

        if not found:
            out.insert(0, f"-Xmx{heap}")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out) + "\n")


def _parse_mem_gb(s: str) -> int:
    """Parse memory string like '4G', '512M' to GB (int)."""
    s = s.strip().upper()
    if s.endswith("G"):
        return int(s[:-1])
    if s.endswith("M"):
        return max(1, int(s[:-1]) // 1024)
    return int(s)
