"""revkit CLI — unified command-line interface for IDA + JEB headless analysis.

Usage:
    revkit ida start sample.exe
    revkit jeb start sample.apk
    revkit ida decompile 0x401000 --json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

from ..core.config import load_config
from ..core.logging_setup import (
    init_logging, get_engine_logger, log_command,
    generate_trace_id, log_with_data,
)
from ..core.output import (
    init_json_mode,
    json_error,
    json_success,
    log_err,
    log_info,
    log_ok,
    log_verbose,
    set_output_mode,
)
from ..core.rpc import RpcError
from ..engines.base import CmdContext
from ..engines.ida.engine import IDAEngine
from ..engines.jeb.engine import JEBEngine
from .commands.common import TIER1_HANDLERS

_ENGINES = {
    "ida": IDAEngine,
    "jeb": JEBEngine,
}

DEFAULT_CONFIG_PATH = Path.home() / ".revkit" / "config.json"

# CLI command name → RPC method name (only for mismatches)
_CLI_TO_RPC_IDA = {
    "segments": "get_segments",
    "bytes": "get_bytes",
    "find-pattern": "find_bytes",
    "func-info": "get_func_info",
    "imagebase": "get_imagebase",
    "callers": "get_xrefs_to",
    "callees": "get_xrefs_from",
    "xrefs": "get_xrefs_to",  # default direction=to
    "comments": "get_comments",
    "comment": "set_comment",
    "rename": "set_name",
    "patch": "patch_bytes",
    "save": "save_db",
    "methods": "get_functions",
    "structs": "list_structs",
    "enums": "list_enums",
    "type-info": "get_type",
    "vtables": "detect_vtables",
    "sigs": "list_sigs",
    "annotations": "export_annotations",
    "snapshot": "snapshot_list",
    "report": "summary",  # report builds from summary
    "profile": "summary",
}

_CLI_TO_RPC_JEB = {
    "decompile": "get_class_source",
    "classes": "get_classes",
    "methods-of-class": "get_methods_of_class",
    "fields-of-class": "get_fields_of_class",
    "method-info": "get_method_info",
    "method": "get_method_by_name",
    "smali": "get_smali",
    "strings": "get_strings",
    "native-methods": "native_methods",
    "callers": "get_xrefs",
    "callees": "get_xrefs",
    "xrefs": "get_xrefs",
    "permissions": "get_manifest",  # extracted from manifest
    "components": "get_manifest",
    "manifest": "get_manifest",
    "main-activity": "get_main_activity",
    "app-class": "get_app_classes",
    "info": "info",
    "resources": "get_resources_list",
    "resource": "get_resource",
    "rename-class": "rename_class",
    "rename-method": "rename_method",
    "rename-field": "rename_field",
    "rename": "rename",
    "set-comment": "set_comment",
    "get-comments": "get_comments",
    "search-classes": "search_classes",
    "search-methods": "search_methods",
    "entry-points": "entry_points",
    "security-scan": "security_scan",
    "annotations": "export_annotations",
    "annotations-export": "export_annotations",
    "annotations-import": "import_annotations",
    "snapshot": "snapshot_list",
    "snapshot-save": "snapshot_save",
    "snapshot-list": "snapshot_list",
    "snapshot-restore": "snapshot_restore",
    "save": "save",
    "comment": "set_comment",
    "comments": "get_comments",
    "decompile-diff": "decompile_diff",
    "rename-preview": "rename_preview",
    "report": "report",
}


def _cli_to_rpc(engine: str, command: str) -> str:
    """Map CLI command name to RPC method name."""
    table = _CLI_TO_RPC_IDA if engine == "ida" else _CLI_TO_RPC_JEB
    if command in table:
        return table[command]
    return command.replace("-", "_")


def _run_remote(args, gateway_url: str) -> int:
    """Proxy all commands through the Gateway API."""
    import time as _time
    import urllib.request
    from .remote import post_rpc_remote, upload_binary, remote_start, remote_list

    api_key = getattr(args, 'api_key', None)
    engine_name = args.engine
    command = args.command
    t0 = _time.time()
    config = {}
    try:
        config = load_config(getattr(args, 'config', str(DEFAULT_CONFIG_PATH)))
    except Exception:
        pass

    # Gateway management commands
    if engine_name == "gateway":
        return _run_gateway_command(args, gateway_url, api_key, command)

    # H7/H11/H12: Local-only commands — not available in remote mode
    LOCAL_ONLY = {"cleanup", "init", "check", "logs", "completions", "completion",
                  "update", "shell", "compare", "code-diff", "batch", "bookmark"}
    if command in LOCAL_ONLY:
        log_err(f"'{command}' is a local-only command, not available in remote mode")
        return 1

    def _resolve_instance(iid_arg):
        """Resolve instance ID: explicit -i, or auto-select from engine-filtered list."""
        iid = iid_arg
        if iid:
            return iid
        # H1/M3/M4: filter by engine_name
        instances = [i for i in remote_list(gateway_url, api_key=api_key)
                     if i.get("engine") == engine_name]
        if len(instances) == 1:
            return instances[0].get("id")
        elif len(instances) > 1:
            log_err(f"Multiple {engine_name} instances. Use -i <id>:")
            for inst in instances:
                log_info(f"  {inst.get('id')}  {inst.get('state',''):12s}  {inst.get('binary','')}")
            return None
        else:
            log_err(f"No active {engine_name} instances.")
            return None

    def _output_result(result):
        """C4: Handle --out (save to local file). C5: Handle --json."""
        if getattr(args, 'json_mode', False):
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return

        # --out: save to local file
        out_path = getattr(args, 'out', None)
        if out_path and result:
            content = ""
            if isinstance(result, dict):
                for key in ("code", "output", "data", "content", "script"):
                    if key in result and isinstance(result[key], str):
                        content = result[key]
                        break
                if not content:
                    content = json.dumps(result, indent=2, ensure_ascii=False)
            else:
                content = str(result)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            log_ok(f"Saved to: {out_path}")
            return

        # Default: print to terminal
        if isinstance(result, dict):
            for k, v in result.items():
                if isinstance(v, str) and len(v) > 200:
                    print(v)
                else:
                    print(f"  {k}: {v}")
        elif isinstance(result, list):
            for item in result:
                print(f"  {item}")
        elif result is not None:
            print(result)

    try:
        # Tier 1: start
        if command == "start":
            binary = args.binary
            if not Path(binary).exists():
                log_err(f"File not found: {binary}")
                return 1
            log_info(f"Uploading {Path(binary).name}...")
            # H2: pass start flags
            result = remote_start(gateway_url, engine_name, binary,
                                  api_key=api_key,
                                  fresh=getattr(args, 'fresh', False),
                                  force=getattr(args, 'force', False),
                                  xmx=getattr(args, 'xmx', None))
            iid = result.get("instance_id", "")
            log_ok(f"Remote start: {iid}")
            # H8: advise wait
            log_info(f"Run 'revkit -R {engine_name} wait -i {iid}' to wait for ready")
            _output_result(result)
            return 0

        # Tier 1: list
        elif command == "list":
            all_instances = remote_list(gateway_url, api_key=api_key)
            # H1: filter by engine
            instances = [i for i in all_instances if i.get("engine") == engine_name]
            if not instances:
                log_info(f"No active {engine_name} instances.")
                return 0
            if getattr(args, 'json_mode', False):
                print(json.dumps(instances, indent=2, ensure_ascii=False))
                return 0
            from ..core.output import md_table_header
            print(md_table_header("ID", "State", "PID", "Port", "Binary"))
            for inst in instances:
                print(f"| {inst.get('id','')} | {inst.get('state','')} | "
                      f"{inst.get('pid','')} | {inst.get('port','')} | "
                      f"{inst.get('binary','')} |")
            return 0

        # Tier 1: stop
        elif command == "stop":
            iid = _resolve_instance(getattr(args, 'instance', None))
            if not iid:
                return 1
            # C2: save_db before stop
            try:
                post_rpc_remote(gateway_url, iid, "save_db", api_key=api_key)
                log_info(f"Database saved for {iid}")
            except Exception:
                pass  # save failure shouldn't block stop
            post_rpc_remote(gateway_url, iid, "stop", api_key=api_key)
            # C3: cleanup registry via DELETE
            try:
                del_url = f"{gateway_url.rstrip('/')}/api/v1/instances/{iid}"
                headers = {}
                if api_key:
                    headers["Authorization"] = f"Bearer {api_key}"
                req = urllib.request.Request(del_url, headers=headers, method="DELETE")
                with urllib.request.urlopen(req, timeout=10):
                    pass  # response consumed and closed
            except Exception:
                pass
            log_ok(f"Stopped {iid}")
            return 0

        # Tier 1: status
        elif command == "status":
            iid = _resolve_instance(getattr(args, 'instance', None))
            if not iid:
                return 1
            result = post_rpc_remote(gateway_url, iid, "status", api_key=api_key)
            _output_result(result)
            return 0

        # Tier 1: wait
        elif command == "wait":
            iid = _resolve_instance(getattr(args, 'instance', None))
            if not iid:
                return 1
            timeout = getattr(args, 'timeout', 120)
            # L14: use config poll interval
            poll = config.get("analysis", {}).get("wait_poll_interval", 2.0)
            deadline = _time.time() + timeout
            while _time.time() < deadline:
                try:
                    result = post_rpc_remote(gateway_url, iid, "status", api_key=api_key)
                    if result.get("state") == "ready":
                        log_ok(f"{iid} is ready")
                        return 0
                except Exception:
                    pass
                _time.sleep(poll)
            log_err(f"Timeout waiting for {iid}")
            return 1

        # Tier 2/3: proxy as RPC
        else:
            # diff: requires two instance IDs — special handling
            if command == "diff":
                iid_a = getattr(args, 'instance_a', None)
                iid_b = getattr(args, 'instance_b', None)
                if not iid_a or not iid_b:
                    log_err("diff requires two instance IDs: revkit -R ida diff <iid_a> <iid_b>")
                    return 1
                # Get functions from both instances and compare client-side
                funcs_a = post_rpc_remote(gateway_url, iid_a, "get_functions",
                                          params={"count": 5000}, api_key=api_key)
                funcs_b = post_rpc_remote(gateway_url, iid_b, "get_functions",
                                          params={"count": 5000}, api_key=api_key)
                # _paginate returns {"data": [...], "total": N} — NOT "functions"
                names_a = {f.get("name", "") for f in funcs_a.get("data", funcs_a.get("functions", []))}
                names_b = {f.get("name", "") for f in funcs_b.get("data", funcs_b.get("functions", []))}
                only_a = sorted(names_a - names_b)
                only_b = sorted(names_b - names_a)
                common = sorted(names_a & names_b)
                result = {"only_in_a": only_a, "only_in_b": only_b,
                          "common": len(common), "total_a": len(names_a), "total_b": len(names_b)}
                _output_result(result)
                return 0

            iid = _resolve_instance(getattr(args, 'instance', None))
            if not iid:
                return 1

            # Build RPC params from args
            # C4: 'out' removed from skip_keys (handled client-side by _output_result)
            params = {}
            skip_keys = {'func', 'engine', 'command', 'config', 'json_mode',
                         'quiet', 'verbose', 'out', 'remote', 'api_key',
                         'instance', 'binary_hint', '_trace_id', 'diff_file'}
            for k, v in vars(args).items():
                if k.startswith('_') or k in skip_keys or v is None:
                    continue
                # M11: include bool False values (explicit flags)
                params[k] = v

            # RPC param name translation (CLI arg name → server expected name)
            _PARAM_REMAP = {
                "type_str": "type",        # set-type: CLI "type_str" → RPC "type"
                "hex_bytes": "bytes",      # patch: CLI "hex_bytes" list → RPC "bytes" string
                "text": "comment",         # comment: CLI "text" → RPC "comment"
                "sig_name": "name",        # sigs --action apply: CLI "sig_name" → RPC "name"
            }
            for cli_key, rpc_key in _PARAM_REMAP.items():
                if cli_key in params:
                    val = params.pop(cli_key)
                    if isinstance(val, list):
                        val = " ".join(str(v) for v in val)  # hex_bytes: ['90','90'] → "90 90"
                    params[rpc_key] = val

            # rename-batch: read file content and send entries array
            if command == "rename-batch" and "input_file" in params:
                import json as _json
                fpath = params.pop("input_file")
                try:
                    with open(fpath, encoding="utf-8") as fp:
                        data = _json.load(fp)
                    params["entries"] = data.get("entries", data) if isinstance(data, dict) else data
                except Exception as e:
                    log_err(f"Cannot read rename file: {fpath}: {e}")
                    return 1

            # annotations import: read file content and send as data
            if command in ("annotations", "annotations-import") and "file" in params:
                import json as _json
                fpath = params.pop("file")
                if fpath and os.path.isfile(fpath):
                    try:
                        with open(fpath, encoding="utf-8") as fp:
                            params["data"] = _json.load(fp)
                    except Exception as e:
                        log_err(f"Cannot read annotations file: {fpath}: {e}")
                        return 1
            # Annotations import: read file content (IDA uses "input_file", JEB uses "file")
            if command in ("annotations", "annotations-import"):
                import json as _json
                fpath = params.pop("input_file", None) or params.pop("file", None)
                if fpath and os.path.isfile(fpath):
                    try:
                        with open(fpath, encoding="utf-8") as fp:
                            params["data"] = _json.load(fp)
                    except Exception as e:
                        log_err(f"Cannot read annotations file: {fpath}: {e}")
                        return 1

            # decompile-all/decompile-batch: ensure 'output' param not required
            # Server should return code; CLI saves locally via --out
            if command in ("decompile-all",) and "output" not in params:
                params["output"] = "__remote__"  # signal server to return code in result

            # Action-based RPC method resolution for snapshot/sigs/structs/enums
            action = params.pop("action", None)
            _ACTION_RPC_MAP = {
                "snapshot": {"save": "snapshot_save", "list": "snapshot_list", "restore": "snapshot_restore"},
                "sigs": {"list": "list_sigs", "apply": "apply_sig"},
                "structs": {"list": "list_structs", "show": "get_struct", "create": "create_struct"},
                "enums": {"list": "list_enums", "show": "get_enum", "create": "create_enum"},
                "annotations": {"export": "export_annotations", "import": "import_annotations"},
                "bookmark": {"add": "bookmark_add", "list": "bookmark_list", "remove": "bookmark_remove"},
            }
            if command in _ACTION_RPC_MAP and action:
                rpc_method = _ACTION_RPC_MAP[command].get(action, _cli_to_rpc(engine_name, command))
            else:
                rpc_method = _cli_to_rpc(engine_name, command)
            result = post_rpc_remote(gateway_url, iid, rpc_method, params,
                                     api_key=api_key)
            _output_result(result)
            return 0

    except Exception as e:
        # H9: log remote commands
        elapsed = (_time.time() - t0) * 1000
        log_command(engine_name, command, args=vars(args),
                    result_ok=False, elapsed_ms=elapsed, error=str(e))
        log_err(f"Remote error: {e}")
        return 1


def _run_gateway_command(args, gateway_url: str, api_key: str | None, command: str) -> int:
    """Handle gateway management commands."""
    import urllib.request

    def _gw_get(path: str) -> dict:
        url = f"{gateway_url.rstrip('/')}{path}"
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def _gw_post(path: str, body: dict | None = None) -> dict:
        url = f"{gateway_url.rstrip('/')}{path}"
        data = json.dumps(body or {}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def _gw_delete(path: str) -> dict:
        url = f"{gateway_url.rstrip('/')}{path}"
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(url, headers=headers, method="DELETE")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    try:
        if command == "info":
            r = _gw_get("/api/v1/gateway/info")
            for k, v in r.items():
                print(f"  {k}: {v}")

        elif command == "config":
            r = _gw_get("/api/v1/gateway/config")
            print(json.dumps(r, indent=2, ensure_ascii=False))

        elif command == "config-set":
            key = args.key
            # Auto-convert value types
            value = args.value
            if value.lower() == "true":
                value = True
            elif value.lower() == "false":
                value = False
            elif value.lower() == "null":
                value = None
            else:
                try:
                    value = int(value)
                except ValueError:
                    try:
                        value = float(value)
                    except ValueError:
                        pass
            r = _gw_post("/api/v1/gateway/config", {"key": key, "value": value})
            log_ok(f"Updated {r.get('updated')}: {r.get('value')}")

        elif command == "stop-all":
            r = _gw_post("/api/v1/gateway/stop-all")
            log_ok(f"Stopped: {len(r.get('stopped', []))} instances")
            if r.get("failed"):
                for f in r["failed"]:
                    log_err(f"  Failed: {f.get('id')} — {f.get('error')}")

        elif command == "uploads":
            r = _gw_get("/api/v1/gateway/uploads")
            print(f"  Directory: {r.get('dir')}")
            print(f"  Files: {r.get('count')}, Total: {r.get('total_size_mb')} MB")
            for f in r.get("files", []):
                size_mb = round(f["size"] / (1024*1024), 2) if f["size"] > 1024*1024 else f"{f['size']} B"
                print(f"    {f['name']:40s}  {size_mb}  {f['modified']}")

        elif command == "uploads-clean":
            r = _gw_delete("/api/v1/gateway/uploads")
            log_ok(f"Removed {r.get('removed')} files, freed {r.get('freed_mb')} MB")

        elif command == "audit":
            tail = getattr(args, 'tail', 20)
            r = _gw_get(f"/api/v1/gateway/audit?tail={tail}")
            print(f"  Total entries: {r.get('total')}, showing last {r.get('count')}")
            for entry in r.get("entries", []):
                if isinstance(entry, dict):
                    ts = entry.get("timestamp", entry.get("ts", ""))
                    method = entry.get("method", "")
                    path = entry.get("path", "")
                    status = entry.get("status", "")
                    ip = entry.get("source_ip", entry.get("ip", ""))
                    print(f"  {ts}  {method:6s}  {path:40s}  {status}  {ip}")
                else:
                    print(f"  {entry}")

        elif command == "system":
            r = _gw_get("/api/v1/gateway/system")
            for k, v in r.items():
                print(f"  {k}: {v}")

        elif command == "disk":
            r = _gw_get("/api/v1/gateway/disk")
            for name, info in r.items():
                print(f"  {name}:")
                print(f"    Path: {info.get('path')}")
                print(f"    Used: {info.get('used_gb')}GB / {info.get('total_gb')}GB ({info.get('percent')}%)")
                print(f"    Free: {info.get('free_gb')}GB")

        elif command == "cleanup":
            r = _gw_post("/api/v1/gateway/cleanup")
            for eng, info in r.items():
                print(f"  {eng}: {info.get('active')} active, {info.get('cleaned')} cleaned")

        elif command == "rotate-key":
            r = _gw_post("/api/v1/gateway/rotate-key")
            log_ok(f"New API key: {r.get('api_key')}")
            log_info("Update client config with the new key")

        elif command == "allow-ip":
            action = args.action
            ip = getattr(args, 'ip', None)
            r = _gw_post("/api/v1/gateway/allow-ip", {"action": action, "ip": ip or ""})
            if action == "list":
                print(f"  Allowed IPs: {r.get('allowed_ips')}")
            else:
                log_ok(f"{action}: {ip}")
                print(f"  Current: {r.get('allowed_ips')}")

        elif command == "connections":
            tail = getattr(args, 'tail', 50)
            r = _gw_get(f"/api/v1/gateway/connections?tail={tail}")
            print(f"  Total: {r.get('total')}, showing last {r.get('count')}")
            for c in r.get("connections", []):
                print(f"  {c.get('time')}  {c.get('ip'):15s}  {c.get('method'):6s}  {c.get('path')}")

        elif command == "download":
            file_id = args.file_id
            out_path = getattr(args, 'out', None) or file_id
            url = f"{gateway_url.rstrip('/')}/api/v1/gateway/download/{file_id}"
            headers = {}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = resp.read()
                with open(out_path, "wb") as f:
                    f.write(data)
            log_ok(f"Downloaded {file_id} → {out_path} ({len(data)} bytes)")

        elif command == "logs":
            iid = args.instance
            tail = getattr(args, 'tail', 50)
            r = _gw_get(f"/api/v1/instances/{iid}/logs?tail={tail}")
            print(f"  Instance: {r.get('instance_id')}, entries: {r.get('count')}")
            for entry in r.get("entries", []):
                if isinstance(entry, dict):
                    ts = entry.get("ts", entry.get("timestamp", ""))
                    level = entry.get("level", "")
                    msg = entry.get("msg", entry.get("message", ""))
                    print(f"  {ts}  [{level}]  {msg}")
                else:
                    print(f"  {entry}")

        elif command == "progress":
            iid = args.instance
            r = _gw_get(f"/api/v1/instances/{iid}/progress")
            for k, v in r.items():
                print(f"  {k}: {v}")

        else:
            log_err(f"Unknown gateway command: {command}")
            return 1

        if getattr(args, 'json_mode', False):
            # Re-fetch for JSON output
            pass  # Already printed above; for full JSON wrap, would need refactor

        return 0

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        log_err(f"Gateway error {e.code}: {body}")
        return 1
    except urllib.error.URLError as e:
        log_err(f"Gateway unreachable: {e}")
        return 1
    except Exception as e:
        log_err(f"Gateway error: {e}")
        return 1


def get_engine(name: str):
    cls = _ENGINES.get(name)
    if not cls:
        log_err(f"Unknown engine: {name}")
        sys.exit(2)
    return cls()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="revkit",
        description="Unified headless binary analysis CLI",
    )
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH),
                        help="Config file path")
    parser.add_argument("--json", action="store_true", dest="json_mode",
                        help="JSON output")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--out", help="Save output to file")
    parser.add_argument("--remote", metavar="URL", nargs="?", const="__CONFIG__",
                        default=None,
                        help="Remote gateway mode. URL optional — uses config gateway.url if omitted")
    parser.add_argument("-R", action="store_const", const="__CONFIG__", dest="remote",
                        help="Short for --remote (uses config gateway.url)")
    parser.add_argument("--api-key", metavar="KEY", help="Gateway API key")

    engine_sub = parser.add_subparsers(dest="engine", help="Analysis engine")

    for engine_name, engine_cls in _ENGINES.items():
        eng_parser = engine_sub.add_parser(engine_name)
        cmd_sub = eng_parser.add_subparsers(dest="command")

        # Tier 1: start
        p_start = cmd_sub.add_parser("start", help="Start analysis server")
        p_start.add_argument("binary", help="Binary file to analyze")
        p_start.add_argument("--force", action="store_true",
                             help="Force start even if already running")
        p_start.add_argument("--fresh", action="store_true",
                             help="Ignore cached database")
        p_start.add_argument("--xmx", help="JVM heap size (JEB only)")

        # Tier 1: list
        cmd_sub.add_parser("list", help="List active instances")

        # Tier 1: stop
        p_stop = cmd_sub.add_parser("stop", help="Stop an instance")
        p_stop.add_argument("-i", "--instance", help="Instance ID")
        p_stop.add_argument("-b", "--binary-hint", help="Binary name hint")

        # Tier 1: status
        p_status = cmd_sub.add_parser("status", help="Show instance status")
        p_status.add_argument("-i", "--instance", help="Instance ID")
        p_status.add_argument("-b", "--binary-hint", help="Binary name hint")

        # Tier 1: wait
        p_wait = cmd_sub.add_parser("wait", help="Wait for instance ready")
        p_wait.add_argument("-i", "--instance", help="Instance ID")
        p_wait.add_argument("-b", "--binary-hint", help="Binary name hint")
        p_wait.add_argument("--timeout", type=float, default=120.0)

        # Tier 2/3: engine-specific commands (Phase 3b)
        engine_cls().register_commands(cmd_sub)

    # Gateway management commands (remote only)
    gw_parser = engine_sub.add_parser("gateway", help="Gateway server management (remote)")
    gw_sub = gw_parser.add_subparsers(dest="command")

    gw_sub.add_parser("info", help="Gateway status + uptime")
    gw_sub.add_parser("config", help="Show server config")

    p_cs = gw_sub.add_parser("config-set", help="Set config key")
    p_cs.add_argument("key", help="Config key (e.g. gateway.port)")
    p_cs.add_argument("value", help="New value")

    gw_sub.add_parser("stop-all", help="Stop all engine instances")
    gw_sub.add_parser("uploads", help="List uploaded files")

    p_uc = gw_sub.add_parser("uploads-clean", help="Clean upload directory")

    p_audit = gw_sub.add_parser("audit", help="View audit log")
    p_audit.add_argument("--tail", type=int, default=20, help="Number of entries")

    gw_sub.add_parser("system", help="Server system info")
    gw_sub.add_parser("disk", help="Disk usage")
    gw_sub.add_parser("cleanup", help="Clean stale instances")
    gw_sub.add_parser("rotate-key", help="Generate new API key")

    p_ip = gw_sub.add_parser("allow-ip", help="Manage allowed IPs")
    p_ip.add_argument("action", choices=["add", "remove", "list"], help="Action")
    p_ip.add_argument("ip", nargs="?", help="IP or CIDR range")

    p_conn = gw_sub.add_parser("connections", help="Recent connections")
    p_conn.add_argument("--tail", type=int, default=50, help="Number of entries")

    p_dl = gw_sub.add_parser("download", help="Download file from server")
    p_dl.add_argument("file_id", help="File ID or name pattern")
    p_dl.add_argument("--out", help="Local save path")

    p_logs = gw_sub.add_parser("logs", help="Instance logs")
    p_logs.add_argument("-i", "--instance", required=True, help="Instance ID")
    p_logs.add_argument("--tail", type=int, default=50, help="Number of entries")

    p_prog = gw_sub.add_parser("progress", help="Analysis progress")
    p_prog.add_argument("-i", "--instance", required=True, help="Instance ID")

    return parser


# ── auto-detect & output helpers ─────────────────────────

def auto_detect_engine(file_path: str):
    """Auto-detect engine based on magic bytes and extension."""
    p = Path(file_path)
    for engine_cls in _ENGINES.values():
        engine = engine_cls()
        if engine.detect_binary(str(p)):
            return engine
    ext = p.suffix.lower()
    if ext in ('.apk', '.dex', '.jar'):
        return JEBEngine()
    if ext in ('.exe', '.dll', '.so', '.dylib', '.bin', '.elf'):
        return IDAEngine()
    raise ValueError(f"Cannot detect engine for {file_path}")


def _write_output(args, result):
    """Write result to --out file if specified."""
    if not getattr(args, 'out', None):
        return
    if result is None:
        return
    out_path = Path(args.out)
    if isinstance(result, dict):
        content = json.dumps(result, ensure_ascii=False, indent=2)
    elif isinstance(result, str):
        content = result
    else:
        content = str(result)
    out_path.write_text(content, encoding="utf-8")
    log_info(f"Output saved to {out_path}")


# ── main entry point ─────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    # SIGINT handler — prevent orphan processes on Ctrl+C
    import signal
    def _sigint_handler(signum, frame):
        sys.exit(130)  # Standard Ctrl+C exit code
    signal.signal(signal.SIGINT, _sigint_handler)

    # Force UTF-8 stdout/stderr on Windows to avoid cp949 encoding errors
    import io
    if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") != "utf8":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if sys.stderr.encoding and sys.stderr.encoding.lower().replace("-", "") != "utf8":
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.engine:
        parser.print_help()
        return 2
    if not args.command:
        parser.parse_args([args.engine, "--help"])
        return 2

    set_output_mode(quiet=args.quiet, verbose=args.verbose)
    if args.json_mode:
        init_json_mode()

    init_logging(verbose=args.verbose)
    _log = get_engine_logger(args.engine)

    _log.debug("CLI entry: engine=%s command=%s verbose=%s json=%s",
               args.engine, args.command, args.verbose, args.json_mode)

    try:
        config = load_config(args.config)
        _log.debug("Config loaded: %d top-level keys", len(config))
    except FileNotFoundError:
        _log.warning("Config file not found: %s, using empty config", args.config)
        config = {}
    except (ValueError, KeyError) as exc:
        _log.warning("Config file invalid: %s (%s), using empty config", args.config, exc)
        config = {}

    # --remote fallback: CLI arg > config gateway.url
    # gateway.mode: "auto" (default) = use url if present, "manual" = require -R/--remote
    remote_val = getattr(args, 'remote', None)
    gw_config = config.get("gateway", {})
    gw_url = gw_config.get("url") or ""
    gw_mode = gw_config.get("mode", "auto")

    if remote_val == "__CONFIG__":
        # -R or --remote (no URL) — use config url
        if gw_url and gw_url.startswith("http"):
            args.remote = gw_url
            _log.debug("Using gateway URL from config: %s", gw_url)
        else:
            log_err("--remote used but no gateway.url in config")
            sys.exit(1)
    elif remote_val and remote_val.startswith("http"):
        # --remote http://... — explicit URL
        pass
    elif not remote_val and gw_mode == "auto" and gw_url and gw_url.startswith("http"):
        # auto mode: config has url → auto remote
        args.remote = gw_url
        _log.debug("Auto-remote from config gateway.url: %s", gw_url)
    else:
        # local mode
        args.remote = None

    # --api-key fallback: CLI arg > config gateway.api_key
    if not getattr(args, 'api_key', None):
        gw_key = config.get("gateway", {}).get("api_key") or ""
        if gw_key:
            args.api_key = gw_key

    # Remote mode: proxy ALL commands through Gateway
    remote_url = getattr(args, 'remote', None)
    if remote_url and remote_url not in (None, "__CONFIG__"):
        return _run_remote(args, remote_url)

    # Gateway commands require remote mode
    if args.engine == "gateway":
        log_err("Gateway commands require remote mode. Use: revkit -R gateway <command>")
        return 1

    engine = get_engine(args.engine)

    trace_id = generate_trace_id()
    _log.debug("Generated trace_id=%s for cmd=%s", trace_id, args.command)
    args._trace_id = trace_id  # P4: available to Tier 1 handlers for RPC calls
    handler = TIER1_HANDLERS.get(args.command)
    if handler:
        t0 = time.time()
        log_with_data(_log, logging.INFO, f"Tier1 cmd={args.command}", {
            "cmd": args.command, "engine": args.engine, "trace_id": trace_id,
        })
        try:
            result = handler(args, config, engine)
            elapsed = (time.time() - t0) * 1000
            _write_output(args, result)
            # P1: extract instance_id from Tier 1 results
            iid = None
            if isinstance(result, dict):
                iid = result.get("instance_id")
            if not iid:
                iid = getattr(args, "instance", None)
            log_command(args.engine, args.command, args=vars(args),
                        result_ok=True, elapsed_ms=elapsed, instance_id=iid)
            log_with_data(_log, logging.INFO, f"Tier1 cmd={args.command} OK ({elapsed:.1f}ms)", {
                "cmd": args.command, "engine": args.engine, "iid": iid,
                "elapsed_ms": round(elapsed, 2), "trace_id": trace_id,
            })
            if args.json_mode and result is not None:
                resp = json_success(
                    engine.engine_name, args.command, result,
                    elapsed_ms=elapsed,
                )
                print(json.dumps(resp, ensure_ascii=False, indent=2))
            return 0
        except (RpcError, RuntimeError) as e:
            elapsed = (time.time() - t0) * 1000
            iid = getattr(args, "instance", None)
            log_command(args.engine, args.command, args=vars(args),
                        result_ok=False, elapsed_ms=elapsed, error=str(e),
                        instance_id=iid)
            log_with_data(_log, logging.ERROR, f"Tier1 cmd={args.command} FAIL: {e}", {
                "cmd": args.command, "engine": args.engine, "iid": iid,
                "error": str(e), "trace_id": trace_id,
            })
            if args.json_mode:
                code = e.code if isinstance(e, RpcError) else "ERROR"
                resp = json_error(engine.engine_name, args.command, code, str(e))
                print(json.dumps(resp, ensure_ascii=False, indent=2))
            else:
                log_err(str(e))
            return 1

    # Tier 2/3: engine-registered command
    func = getattr(args, "func", None)
    if func:
        ctx = CmdContext(
            args=args, config=config,
            config_path=args.config, engine=engine,
            trace_id=trace_id,
        )
        t0 = time.time()
        iid = getattr(args, "instance", None)
        log_with_data(_log, logging.INFO, f"cmd={args.command}", {
            "cmd": args.command, "engine": args.engine,
            "iid": iid, "trace_id": trace_id,
        })
        try:
            result = func(ctx)
            elapsed = (time.time() - t0) * 1000
            _write_output(args, result)
            iid = getattr(args, "instance", None)
            log_command(args.engine, args.command, args=vars(args),
                        result_ok=True, elapsed_ms=elapsed, instance_id=iid)
            log_with_data(_log, logging.INFO, f"cmd={args.command} OK ({elapsed:.1f}ms)", {
                "cmd": args.command, "engine": args.engine,
                "iid": iid, "elapsed_ms": round(elapsed, 2), "trace_id": trace_id,
            })
            if args.json_mode and result is not None:
                resp = json_success(
                    engine.engine_name, args.command, result,
                    elapsed_ms=elapsed,
                )
                print(json.dumps(resp, ensure_ascii=False, indent=2))
            return 0
        except Exception as e:
            elapsed = (time.time() - t0) * 1000
            iid = getattr(args, "instance", None)
            log_command(args.engine, args.command, args=vars(args),
                        result_ok=False, elapsed_ms=elapsed,
                        error=str(e), instance_id=iid)
            log_with_data(_log, logging.ERROR, f"cmd={args.command} FAIL: {e}", {
                "cmd": args.command, "engine": args.engine,
                "iid": iid, "error": str(e), "trace_id": trace_id,
            })
            if args.json_mode:
                resp = json_error(engine.engine_name, args.command, "ERROR", str(e))
                print(json.dumps(resp, ensure_ascii=False, indent=2))
            else:
                log_err(str(e))
            return 1

    log_err(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
