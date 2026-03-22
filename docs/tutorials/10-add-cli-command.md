# Tutorial 10: Adding a New CLI Command / 새 CLI 명령 추가

Developer guide for adding a new command to the revkit CLI. Covers the full lifecycle from handler function to parser registration.

revkit CLI에 새 명령을 추가하는 개발자 가이드. 핸들러 함수 작성부터 파서 등록까지 전체 라이프사이클을 다룹니다.

> **Prerequisites / 사전 준비**: Familiarity with the revkit codebase and Python argparse / revkit 코드베이스와 Python argparse 숙지

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. Architecture Overview / 아키텍처 개요

Every CLI command follows a 4-step pattern. Understanding this pattern makes adding new commands straightforward.

모든 CLI 명령은 4단계 패턴을 따릅니다. 이 패턴을 이해하면 새 명령 추가가 간단합니다.

```
commands/module.py  →  commands/__init__.py  →  engine.py  →  --help test
   cmd_xxx()             export                  register       verify
```

### Command Types / 명령 유형

| Type / 유형 | Server? / 서버? | `_inject_common_options` | Example / 예시 |
|---|---|---|---|
| RPC command / RPC 명령 | Yes / 예 | Required / 필수 | `decompile`, `rename` |
| Local command / 로컬 명령 | No / 아니오 | Not used / 미사용 | `init`, `cleanup`, `logs` |

---

## 2. Step 1: Write the Handler / 핸들러 작성

All command handlers use the same signature: `cmd_xxx(ctx: CmdContext)`.

모든 명령 핸들러는 동일한 시그니처를 사용합니다: `cmd_xxx(ctx: CmdContext)`.

### CmdContext Fields / CmdContext 필드

```python
@dataclass
class CmdContext:
    args: argparse.Namespace    # Parsed CLI arguments / 파싱된 CLI 인자
    config: dict                # Loaded config / 로드된 설정
    config_path: str            # Config file path / 설정 파일 경로
    trace_id: str               # Correlation ID for RPC / RPC 상관 ID
```

### RPC Command Example / RPC 명령 예시

Create a new handler in the appropriate `commands/` module. For this example, we add `func-stats` to IDA.

적절한 `commands/` 모듈에 새 핸들러를 생성합니다. 이 예시에서는 IDA에 `func-stats`를 추가합니다.

```python
# revkit/tools/engines/ida/commands/analysis.py

def cmd_func_stats(ctx):
    """Show function statistics / 함수 통계 표시"""
    args, config = ctx.args, ctx.config

    # Resolve instance (finds port, token) / 인스턴스 해결 (포트, 토큰 찾기)
    from ...core.instance import resolve_instance
    from ...core.registry import get_registry_path
    inst = resolve_instance(args, get_registry_path("ida"))

    # Make RPC call / RPC 호출
    from ...core.rpc import post_rpc
    result = post_rpc(
        url="http://127.0.0.1:%d/rpc" % inst["port"],
        method="func_stats",
        params={"min_size": getattr(args, "min_size", 0)},
        auth_token=inst.get("token"),
    )

    # Output results / 결과 출력
    from ...core.output import log_ok, log_info
    stats = result.get("result", {})
    log_ok("Function statistics:")
    log_info("  Total:    %d" % stats.get("total", 0))
    log_info("  Named:    %d" % stats.get("named", 0))
    log_info("  Unnamed:  %d" % stats.get("unnamed", 0))
    log_info("  Avg size: %d bytes" % stats.get("avg_size", 0))
```

### Local Command Example / 로컬 명령 예시

Local commands do not contact the server — no RPC needed.

로컬 명령은 서버에 접속하지 않습니다 — RPC 불필요.

```python
# revkit/tools/engines/ida/commands/utility.py

def cmd_show_config(ctx):
    """Display current engine config / 현재 엔진 설정 표시"""
    args, config = ctx.args, ctx.config
    from ...core.output import log_ok, log_info
    import json

    ida_config = config.get("ida", {})
    log_ok("IDA configuration:")
    print(json.dumps(ida_config, indent=2))
```

---

## 3. Step 2: Export in __init__.py / __init__.py에 내보내기

Add the new function to `commands/__init__.py` so `engine.py` can import it.

`engine.py`에서 import할 수 있도록 `commands/__init__.py`에 새 함수를 추가합니다.

```python
# revkit/tools/engines/ida/commands/__init__.py

from .analysis import (
    cmd_decompile,
    cmd_find_func,
    cmd_func_info,
    cmd_func_stats,       # ← ADD THIS / 이것을 추가
    # ... other imports
)
```

---

## 4. Step 3: Register in engine.py / engine.py에 등록

Add a subparser entry in the engine's `register_commands()` method.

엔진의 `register_commands()` 메서드에 subparser 항목을 추가합니다.

### RPC Command Registration / RPC 명령 등록

```python
# revkit/tools/engines/ida/engine.py, inside register_commands()

# --- func-stats (RPC command, needs server) ---
p = subparsers.add_parser(
    "func-stats",
    help="Show function statistics / 함수 통계",
)
p.add_argument(
    "--min-size", type=int, default=0,
    help="Minimum function size in bytes / 최소 함수 크기 (바이트)",
)
self._inject_common_options(p)   # ← Adds -i, --json, -b, --config
p.set_defaults(func=cmd_func_stats)
```

### Local Command Registration / 로컬 명령 등록

```python
# Local commands: NO _inject_common_options / 로컬 명령: _inject_common_options 없음

p = subparsers.add_parser(
    "show-config",
    help="Display engine configuration / 엔진 설정 표시",
)
p.set_defaults(func=cmd_show_config)
```

### Key Details / 핵심 사항

`_inject_common_options(parser)` adds these flags automatically:

`_inject_common_options(parser)`는 이 플래그들을 자동으로 추가합니다:

| Flag / 플래그 | Purpose / 용도 |
|---|---|
| `-i` / `--instance` | Target instance ID / 대상 인스턴스 ID |
| `--json` | JSON output mode / JSON 출력 모드 |
| `-b` / `--binary` | Target binary path / 대상 바이너리 경로 |
| `--config` | Config file override / 설정 파일 오버라이드 |

Only call this for commands that need an RPC connection. Local commands (init, cleanup, logs) do not need it.

RPC 연결이 필요한 명령에만 호출하세요. 로컬 명령(init, cleanup, logs)은 필요 없습니다.

---

## 5. Step 4: Test / 테스트

### Verify help text / 도움말 텍스트 확인

```bash
# Check the command appears in help / 명령이 help에 나타나는지 확인
$RK ida --help | grep func-stats

# Check the command's own help / 명령 자체의 help 확인
$RK ida func-stats --help
# usage: revkit ida func-stats [-h] [--min-size MIN_SIZE] [-i INSTANCE] [--json] ...
```

### Verify import chain / import 체인 확인

```bash
# Quick import test / 빠른 import 테스트
python -c "from revkit.tools.engines.ida.commands import cmd_func_stats; print('OK')"
```

### Test with a running instance / 실행 중인 인스턴스로 테스트

```bash
$RK ida start Samples/EXE/notepad.exe
$RK ida wait
$RK ida func-stats --min-size 100
$RK ida stop
```

---

## 6. Adding to JEB — Same Pattern / JEB에 추가 — 동일 패턴

The JEB engine follows the same 4-step pattern. Key differences:

JEB 엔진도 동일한 4단계 패턴을 따릅니다. 주요 차이점:

| Aspect / 측면 | IDA | JEB |
|---|---|---|
| Positional args / 위치 인자 | `addr` (hex address) | `sig` (Java signature) |
| RPC endpoint | `/rpc` | `/jsonrpc` |
| Commands dir / 명령 디렉토리 | `engines/ida/commands/` | `engines/jeb/commands/` |
| Engine file / 엔진 파일 | `engines/ida/engine.py` | `engines/jeb/engine.py` |

```python
# JEB example / JEB 예시
p = subparsers.add_parser("class-stats", help="Show class statistics")
p.add_argument("--package", help="Filter by package / 패키지 필터")
self._inject_common_options(p)
p.set_defaults(func=cmd_class_stats)
```

---

## 7. Common Patterns / 공통 패턴

### Using _opt for Optional Arguments / 선택적 인자에 _opt 사용

```python
def cmd_example(ctx):
    args = ctx.args
    # Safe optional arg access / 안전한 선택적 인자 접근
    max_count = getattr(args, "max_count", 50)
    package = getattr(args, "package", None)
```

### JSON Output Mode / JSON 출력 모드

```python
def cmd_example(ctx):
    args = ctx.args
    result = {"total": 42, "items": [...]}

    if getattr(args, "json", False):
        import json
        print(json.dumps(result, indent=2))
    else:
        from ...core.output import log_ok
        log_ok("Total: %d" % result["total"])
```

### Error Handling / 에러 처리

```python
from ...core.rpc import post_rpc, RpcError
from ...core.output import log_err

def cmd_example(ctx):
    try:
        result = post_rpc(url, "method", params, auth_token=token)
    except RpcError as e:
        log_err("RPC failed: %s" % e)
        return
```

---

## 8. Checklist / 체크리스트

Before submitting your new command, verify:

새 명령을 제출하기 전에 확인하세요:

- [ ] `cmd_xxx(ctx: CmdContext)` signature / 시그니처
- [ ] Exported in `commands/__init__.py` / `__init__.py`에 export
- [ ] Registered in `engine.py` with `add_parser` + `set_defaults` / `engine.py`에 등록
- [ ] `_inject_common_options` for RPC commands only / RPC 명령에만 사용
- [ ] `--help` shows correct usage / `--help`가 올바른 사용법 표시
- [ ] Import test passes / import 테스트 통과
- [ ] Works with `--json` flag (if applicable) / `--json` 플래그와 동작 (해당 시)

---

**Next / 다음**: [11-add-rpc-handler.md](11-add-rpc-handler.md) — Adding a new RPC handler / 새 RPC 핸들러 추가
