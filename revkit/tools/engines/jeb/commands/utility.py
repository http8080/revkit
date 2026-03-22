"""Utility commands -- exec, completion."""

import logging
import os

from ..core import (
    _rpc_call, _opt, _log_ok, _log_err, _log_info,
    _save_local, _maybe_output_param,
)
from ...base import CmdContext
from ....core.utils import resolve_script_path

log = logging.getLogger(__name__)


def cmd_exec(ctx: CmdContext):
    """Execute Jython code on the JEB instance (requires security.exec_enabled)."""
    args, config = ctx.args, ctx.config
    code = args.code
    # Resolve .py script path (supports short paths like "security/check_webview.py")
    resolved = resolve_script_path(code, "jeb", config)
    if resolved:
        with open(resolved, "r", encoding="utf-8") as f:
            code = f.read()
        _log_info(f"Loaded script: {code.count(chr(10))+1} lines from {resolved}")
    else:
        log.debug("cmd_exec: inline code (%d chars)", len(code))
    p = {"code": code}
    _maybe_output_param(args, p)
    r = _rpc_call(args, config, "exec", p)
    if not r:
        log.warning("cmd_exec: RPC returned None")
        return
    log.debug("cmd_exec: completed, has_stdout=%s has_stderr=%s", bool(r.get('stdout')), bool(r.get('stderr')))
    if r.get("stdout"):
        print(r["stdout"], end="")
    if r.get("stderr"):
        print(f"[stderr] {r['stderr']}", end="")
    if r.get("result") is not None and r["result"] != "":
        print(f"  Result: {r['result']}")


def cmd_completion(ctx: CmdContext):
    """#43: Generate shell completion scripts."""
    args, config = ctx.args, ctx.config
    log.debug("cmd_completion: shell=%s", _opt(args, 'shell', 'bash'))
    shell = _opt(args, 'shell', 'bash')
    commands = [
        "check", "init", "start", "stop", "restart", "wait", "list", "status",
        "logs", "cleanup", "save", "config-show", "config-set",
        "summary", "permissions", "components", "info", "classes", "strings",
        "imports", "exports", "methods", "methods-of-class", "fields-of-class",
        "method-info", "strings-xrefs",
        "decompile", "decompile-diff", "method", "decompile-batch",
        "decompile-all", "smali",
        "search-class", "search-method", "search-code", "grep",
        "xrefs", "callers", "callees", "callgraph", "cross-refs",
        "manifest", "resources", "resource", "main-activity", "app-class",
        "native-methods",
        "rename", "rename-class", "rename-method", "rename-field",
        "rename-batch", "comment", "get-comments", "auto-rename",
        "undo", "bookmark",
        "annotations", "snapshot", "exec", "rpc-methods", "report",
        "batch", "gen-runner", "merge", "patch", "unpatch",
        "completion", "entry-points", "security-scan",
    ]
    global_opts = ["--json", "--config", "-i", "-b", "-q", "--quiet",
                   "-v", "--verbose", "--timeout-override"]

    if shell == "bash":
        script = _gen_bash_completion(commands, global_opts)
    elif shell == "zsh":
        script = _gen_zsh_completion(commands, global_opts)
    else:
        _log_err(f"Unsupported shell: {shell}")
        return

    out = _opt(args, 'out')
    if out:
        _save_local(out, script)
    else:
        print(script)


def _gen_bash_completion(commands, global_opts):
    cmds = " ".join(commands)
    opts = " ".join(global_opts)
    return f'''# jeb-cli bash completion
# Add to ~/.bashrc: eval "$(jeb-cli completion bash)"
_jeb_cli_completions() {{
    local cur prev commands global_opts
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    commands="{cmds}"
    global_opts="{opts}"

    if [[ ${{COMP_CWORD}} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${{commands}}" -- "${{cur}}") )
    elif [[ "${{cur}}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${{global_opts}}" -- "${{cur}}") )
    else
        COMPREPLY=( $(compgen -f -- "${{cur}}") )
    fi
}}
complete -F _jeb_cli_completions jeb-cli
'''


def _gen_zsh_completion(commands, global_opts):
    cmds = " ".join(commands)
    return f'''#compdef jeb-cli
# Add to ~/.zshrc: eval "$(jeb-cli completion zsh)"
_jeb_cli() {{
    local -a commands
    commands=({cmds})
    _arguments \\
        '1:command:($commands)' \\
        '*:file:_files'
}}
compdef _jeb_cli jeb-cli
'''
