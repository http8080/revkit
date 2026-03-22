"""Utility commands — update, completions."""

import os
import subprocess

from ..core import _log_ok, _log_err, _log_info, _opt
from ...base import CmdContext

import logging
log = logging.getLogger(__name__)


def cmd_update(ctx: CmdContext):
    """Self-update from git repository."""
    log.debug("cmd_update: searching for git root")
    args = ctx.args
    # Walk up from tools/ to find the git root
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    while repo_dir != os.path.dirname(repo_dir):  # stop at filesystem root
        if os.path.isdir(os.path.join(repo_dir, ".git")):
            break
        repo_dir = os.path.dirname(repo_dir)
    else:
        _log_err("Not inside a git repository")
        return
    log.debug("cmd_update: repo_dir=%s", repo_dir)
    _log_info(f"Updating from: {repo_dir}")
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "pull", "--ff-only"],
            capture_output=True, text=True, timeout=30,
        )
        print(result.stdout.strip())
        if result.returncode != 0:
            _log_err(result.stderr.strip())
    except FileNotFoundError:
        _log_err("git not found in PATH")
    except subprocess.TimeoutExpired:
        _log_err("git pull timed out")


def cmd_completions(ctx: CmdContext):
    """Generate shell completion scripts."""
    args = ctx.args
    shell = _opt(args, 'shell', 'bash')
    log.debug("cmd_completions: shell=%s", shell)
    commands = [
        "start", "stop", "status", "wait", "list", "logs", "cleanup",
        "functions", "strings", "imports", "exports", "segments",
        "decompile", "decompile_batch", "disasm", "xrefs",
        "find_func", "func_info", "imagebase", "bytes", "find_pattern",
        "comments", "methods", "rename", "set_type", "comment",
        "save", "exec", "summary", "diff", "batch", "bookmark",
        "profile", "report", "shell", "annotations", "callgraph",
        "patch", "search-const", "structs", "snapshot", "compare",
        "enums", "search-code", "code-diff", "auto-rename",
        "export-script", "vtables", "sigs", "cross-refs",
        "decompile-all", "type-info", "strings-xrefs",
        "func-similarity", "data-refs", "basic-blocks",
        "stack-frame", "switch-table", "rename-batch",
        "update", "completions",
    ]
    if shell == "bash":
        print("""# ida-cli bash completion
# Add to ~/.bashrc: eval "$(ida-cli completions --shell bash)"
_ida_cli() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="%s"
    local opts="--json --config -i -b --init --check"
    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$commands $opts" -- "$cur") )
    else
        case "${COMP_WORDS[1]}" in
            start)  COMPREPLY=( $(compgen -f -- "$cur") $(compgen -W "--fresh --force --idb-dir --arch" -- "$cur") ) ;;
            decompile) COMPREPLY=( $(compgen -W "--out --with-xrefs" -- "$cur") ) ;;
            functions|strings|imports|exports) COMPREPLY=( $(compgen -W "--offset --count --filter --out" -- "$cur") ) ;;
            *)  COMPREPLY=( $(compgen -W "$opts" -- "$cur") ) ;;
        esac
    fi
}
complete -F _ida_cli ida-cli""" % " ".join(commands))
    elif shell == "zsh":
        print("""# ida-cli zsh completion
# Add to ~/.zshrc: eval "$(ida-cli completions --shell zsh)"
_ida_cli() {
    local commands=(%s)
    local opts=(--json --config -i -b --init --check)
    if (( CURRENT == 2 )); then
        _describe 'command' commands
        _describe 'option' opts
    else
        case $words[2] in
            start)  _files; _arguments '--fresh' '--force' '--idb-dir' '--arch' ;;
            decompile) _arguments '--out' '--with-xrefs' ;;
            functions|strings|imports|exports) _arguments '--offset' '--count' '--filter' '--out' ;;
        esac
    fi
}
compdef _ida_cli ida-cli""" % " ".join(commands))
    elif shell == "powershell":
        cmds_str = "', '".join(commands)
        print(f"""# ida-cli PowerShell completion
# Add to $PROFILE: . <(ida-cli completions --shell powershell)
Register-ArgumentCompleter -CommandName ida-cli -Native -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $commands = @('{cmds_str}')
    $commands | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
}}""")
    else:
        _log_err(f"Unsupported shell: {shell}. Use bash, zsh, or powershell.")
