# CLAUDE.md — revkit-private 작업 지침

> 이 파일은 Claude Code가 자동으로 읽는 프로젝트 지침.
> 새 세션·새 PC에서도 이 파일을 읽으면 전체 맥락 파악 가능.

---

## 1. 프로젝트 개요

**revkit** = IDA Pro + JEB 통합 headless 분석 CLI.
아키텍처: `CLI (argparse) → JSON-RPC/HTTP → Headless IDA/JEB Server`

```
revkit-private/                          ← 프로젝트 루트
├── CLAUDE.md                            ← 이 파일
├── README.md
├── requirements.txt
├── docs/
│   ├── README-IDA.md
│   ├── README-JEB.md
│   ├── README-Config.md
│   ├── README-Logging.md
│   ├── README-Setup.md
│   ├── README-Gateway.md                ← Gateway 아키텍처 + 관리 API + 16개 명령
│   └── README-Security.md              ← 보안 설정 (인증/IP/exec/업로드/감사)
├── guide/design/                        ← impl-sessions 가이드 (session 1-5)
├── Samples/                             ← 테스트용 바이너리/APK
├── revkit/
│   ├── __init__.py
│   ├── pyproject.toml
│   ├── bin/                             ← 실행 스크립트
│   │   ├── ida-cli.py
│   │   ├── jeb-cli
│   │   └── revkit
│   ├── tests/                           ← 테스트 스위트
│   │   ├── conftest.py
│   │   ├── test_cli/
│   │   ├── test_core/
│   │   ├── test_engines/
│   │   ├── test_gateway/
│   │   ├── test_integration/
│   │   └── test_security/
│   └── tools/
│       ├── __init__.py
│       ├── core/                        ← 엔진 공통 코어 (아래 §3 참조)
│       │   ├── __init__.py
│       │   ├── audit.py                 ← 감사 로깅
│       │   ├── config.py               ← load_config(path) → dict
│       │   ├── instance.py             ← is_process_alive, make_instance_id, resolve_instance, wait_for_start
│       │   ├── output.py               ← log_ok/err/info/warn, md_table_header
│       │   ├── process.py              ← SpawnConfig, detach_spawn, force_kill
│       │   ├── registry.py             ← get_registry_path, load_registry, save_registry, cleanup_stale
│       │   ├── logging_setup.py        ← JSONL 로깅 (JsonFormatter, init_logging, get_*_logger)
│       │   ├── rpc.py                  ← post_rpc, RpcError
│       │   └── utils.py                ← file_md5, truncate
│       ├── cli/                         ← CLI 엔트리포인트
│       │   ├── __init__.py
│       │   ├── main.py                 ← argparse 루트. Tier 1 등록 + engine.register_commands()
│       │   ├── remote.py               ← 원격 연결 유틸
│       │   └── commands/
│       │       ├── __init__.py
│       │       └── common.py           ← Tier 1 핸들러 + _load_token_for_instance, _wait_for_exit
│       ├── gateway/                     ← API 게이트웨이 레이어
│       │   ├── __init__.py
│       │   ├── audit.py                ← 게이트웨이 감사
│       │   ├── auth.py                 ← 인증 처리
│       │   ├── config.py               ← 게이트웨이 설정
│       │   ├── daemon.py               ← 데몬 프로세스 관리
│       │   ├── router.py               ← 요청 라우팅
│       │   └── upload.py               ← 파일 업로드 처리
│       ├── libs/
│       │   └── APKEditor-1.4.7.jar     ← APK 편집 라이브러리
│       ├── scripts/                     ← 마이그레이션/검증 스크립트
│       │   ├── __init__.py
│       │   ├── migrate.py
│       │   └── verify_migration.py
│       └── engines/
│           ├── __init__.py
│           ├── base.py                 ← EngineBase ABC, CmdContext dataclass, _inject_common_options()
│           ├── ida/
│           │   ├── engine.py           ← IDAEngine. register_commands() 57개 subparser
│           │   ├── core.py             ← IDA adapter. shared core → IDA-specific wrappers
│           │   ├── commands/           ← 9 모듈, 62 cmd_* 함수
│           │   │   ├── __init__.py, instance.py, analysis.py, modification.py
│           │   │   ├── types.py, diff.py, advanced.py, report.py
│           │   │   └── batch.py, utility.py
│           │   └── server/             ← IDA headless RPC server
│           │       ├── __init__.py, ida_server.py  ← sys.path에 tools/ 추가, core 직접 import
│           │       ├── framework.py, context.py, exceptions.py
│           │       └── handlers/       ← RPC 핸들러 모듈
│           │           ├── __init__.py, dispatch.py
│           │           ├── analysis.py, advanced.py, listing.py
│           │           ├── modification.py, types.py
│           │           ├── graph.py, annotations.py, snapshot.py
│           └── jeb/
│               ├── engine.py           ← JEBEngine. register_commands() 67개 subparser
│               ├── core.py             ← JEB adapter. shared core → JEB-specific wrappers
│               ├── commands/           ← 13 모듈, 73 cmd_* 함수
│               │   ├── __init__.py, instance.py, analysis.py, recon.py, search.py
│               │   ├── modification.py, xrefs.py, report.py, security.py
│               │   └── tooling.py, config.py, batch.py, utility.py
│               └── server/             ← JEB headless RPC server
│                   ├── __init__.py, jeb_server.py
│                   ├── framework.py, constants.py, exceptions.py
│                   └── handlers/       ← RPC 핸들러 모듈
│                       ├── __init__.py, helpers.py
│                       ├── analysis.py, advanced.py, listing.py
│                       ├── modification.py, search.py
│                       ├── graph.py, annotations.py
│                       ├── security.py, snapshot.py
```

---

## 2. 핵심 아키텍처 규칙

### 명령 3-Tier 분류

| 계층 | 정의 | 등록 위치 |
|------|------|----------|
| **Tier 1** | 진짜 공통. 엔진 무관, 인터페이스 동일 | `cli/main.py` |
| **Tier 2** | 이름 공통 + 엔진별 구현. IDA는 `addr`, JEB는 `sig` | `engine.register_commands()` |
| **Tier 3** | 엔진 고유. 해당 엔진에서만 존재 | `engine.register_commands()` |

> ⚠️ **Tier 1은 절대 register_commands()에서 건드리지 않음**

#### Tier 1 — 공통 (cli/main.py, 5개)
```
start, list, stop, status, wait
```

#### Tier 2 — 이름 공통, 구현 엔진별 (IDA/JEB 양쪽 존재)
```
decompile        IDA: addr → C코드          JEB: class_sig → Java코드
xrefs            IDA: addr --direction       JEB: sig --direction
callers          IDA: addr                   JEB: sig
callees          IDA: addr                   JEB: sig
rename           IDA: addr name              JEB: sig name [--preview]
search-code      IDA: query --max-funcs      JEB: query --package --context
strings-xrefs   IDA: (addr 기반)            JEB: (sig 기반)
callgraph        IDA: addr --direction       JEB: class_sig --exclude
auto-rename      IDA: --max-funcs            JEB: --max-classes
methods          IDA: native binary methods  JEB: class methods
annotations      IDA: addr 기반              JEB: sig 기반
report           IDA: IDA 포맷              JEB: JEB 포맷
exec             IDA: exec(code)             JEB: exec(code, JEB API)
batch            IDA/JEB 동일 구조
summary          IDA/JEB 동일 구조
decompile-all    IDA/JEB 동일 구조
decompile-batch  IDA/JEB 동일 구조
cross-refs       IDA/JEB 동일 구조
bookmark         IDA/JEB 동일 구조
rename-batch     IDA/JEB 동일 구조
snapshot         IDA/JEB 동일 구조
patch            IDA: byte-level             JEB: launcher patch
```

#### Tier 3 — IDA 고유 (IDA에만 존재하는 명령)
```
Instance(5):    init, check, restart, logs, cleanup
Analysis(8):    segments, disasm, bytes, find-func, func-info, imagebase, find-pattern, shell
                comments, save
Modification(3): set-type, comment, search-const
Types(5):       structs, enums, type-info, vtables, sigs
Diff(3):        diff, compare, code-diff
Advanced(5):    func-similarity, data-refs, basic-blocks, stack-frame, switch-table
Report(3):      profile, export-script
Utility(2):     update, completions
```

#### Tier 3 — JEB 고유 (JEB에만 존재하는 명령)
```
Instance(6):    init, check, restart, logs, cleanup, save
Analysis(8):    method, decompile-diff, smali, classes, methods-of-class,
                fields-of-class, method-info, native-methods, strings
Recon(9):       permissions, components, info, main-activity, app-class,
                resources, resource, manifest
Search(3):      search-classes, search-methods
Modification(8): rename-class, rename-method, rename-field, rename-preview,
                  set-comment, get-comments, undo
Xrefs:          (Tier 2와 겹침 — callers/callees/xrefs/callgraph/cross-refs)
Report(6):      annotations-export, annotations-import,
                snapshot-save, snapshot-list, snapshot-restore
Security(2):    entry-points, security-scan
Tooling(3):     gen-runner, unpatch, merge
Config(2):      config-show, config-set
Utility(1):     completion
```

### D8: `_inject_common_options(parser)`
RPC 필요 명령에만 호출. 자동으로 `-i`, `--json`, `-b`, `--config` 추가.
```python
# RPC 명령 (서버 필요)
p = subparsers.add_parser("decompile", ...)
p.add_argument("addr", ...)
self._inject_common_options(p)        # ← 이거
p.set_defaults(func=cmd_proxy_decompile)

# 로컬 명령 (서버 불필요) → _inject_common_options 없음
p = subparsers.add_parser("init", ...)
p.set_defaults(func=cmd_init)
```

### D11: 모든 cmd_*는 동일 시그니처
```python
def cmd_xxx(ctx: CmdContext):
    args, config = ctx.args, ctx.config
    # config_path = ctx.config_path (start/restart 등에서 사용)
    # trace_id = ctx.trace_id (RPC 호출 상관 ID)
```

### J4 (JEB 전용): `--sig` 사용 (IDA의 `--addr` 아님)
```
클래스:  Lcom/example/Foo;
메서드:  Lcom/example/Foo;->bar()V
필드:    Lcom/example/Foo;->field:I
```
positional 인자명: `sig`, `class_sig`, `method_sig`, `field_sig`

---

## 3. Shared Core API (core/*.py)

| 모듈 | 주요 심볼 |
|------|----------|
| `config.py` | `load_config(path=None) → dict` (path=None → `~/.revkit/config.json` fallback) |
| `instance.py` | `is_process_alive(pid)`, `make_instance_id(path)`, `resolve_instance(args, reg_path, stale)`, `wait_for_start(reg_path, iid, timeout, poll)` |
| `output.py` | `log_ok`, `log_err`, `log_info`, `log_warn`, `md_table_header` |
| `process.py` | `SpawnConfig`, `detach_spawn(cfg) → pid`, `force_kill(pid)` |
| `registry.py` | `get_registry_path(engine)`, `registry_locked(path)`, `load_registry(path) → list[dict]`, `save_registry(path, entries)`, `cleanup_stale(path, threshold)`, `register_instance(path, entry, max)` |
| `rpc.py` | `post_rpc(url, method, params, *, timeout, auth_token) → dict`, `RpcError` |
| `utils.py` | `file_md5(path)`, `truncate(s, max_len)` |
| `logging_setup.py` | `JsonFormatter`, `init_logging(config)`, `get_engine_logger(engine)`, `get_instance_log_path(engine, iid)`, `get_instance_stderr_path(engine, iid)`, `get_gateway_logger()`, `log_command(engine, command, args)`, `generate_trace_id()`, `log_with_data(logger, level, msg, data)`, `log_lifecycle(engine, event, iid, **extra)` |

### 3-1. 로깅 시스템 (core/logging_setup.py)

모든 로그는 **JSONL** (JSON Lines) 형식. `RotatingFileHandler` 기반 (10 MB × 3 backups).

```
~/.revkit/logs/
├── revkit.jsonl                    ← 글로벌 로그
├── commands.jsonl                  ← CLI 명령 실행 기록
├── ida/
│   ├── engine.jsonl                ← IDA 엔진 로그
│   └── instances/
│       ├── {iid}.jsonl             ← 인스턴스별 로그
│       └── {iid}.stderr            ← 인스턴스별 stderr 캡처
├── jeb/
│   ├── engine.jsonl                ← JEB 엔진 로그
│   └── instances/
│       ├── {iid}.jsonl
│       └── {iid}.stderr
└── gateway/
    └── gateway.jsonl               ← 게이트웨이 로그
```

### 3-2. config.json 전체 구조

```json
{
  "paths": {
    "idb_dir": "~/.revkit/ida/idb",
    "log_dir": "~/.revkit/logs",
    "project_dir": "~/.revkit/jeb/projects",
    "output_dir": "~/.revkit/output",
    "scripts_dir": "~/.revkit/scripts"
  },
  "analysis": {
    "max_instances": 3,
    "wait_poll_interval": 1.0,
    "wait_timeout": 120,
    "stale_threshold": 86400,
    "open_db_timeout": 300,
    "heartbeat_interval": 30,
    "auto_save": true,
    "stop_timeout": 30
  },
  "security": {
    "auth_token_file": "~/.revkit/auth_tokens.json",
    "exec_enabled": false
  },
  "server": { "host": "127.0.0.1" },
  "log": { "max_size_mb": 10, "backup_count": 3, "stderr_capture": true },
  "output": {
    "default_count": 50,
    "max_count": 500,
    "encoding": "utf-8"
  },
  "ida": {
    "install_dir": "C:/Program Files/IDA Professional 9.3",  // Win | Linux: "/opt/ida"
    "registry": "~/.revkit/ida/registry.json",
    "security": { "exec_enabled": true }
  },
  "jeb": {
    "install_dir": "C:/WorkSpace/bin/JEB-5.38",              // Win | Linux: "/opt/jeb"
    "registry": "~/.revkit/jeb/registry.json",
    "spawn_method": "wrapper",
    "java_home": "C:/Program Files/Java/jdk-21.0.10",        // Win | Linux: "/usr/lib/jvm/java-21"
    "jvm_opts": ["-XX:+UseG1GC", "-Dfile.encoding=UTF-8"],
    "security": { "exec_enabled": true },
    "heap": {
      "auto": true, "default": "4G", "max": "16G",
      "rules": [
        {"max_mb": 50, "xmx": "2G"},
        {"max_mb": 200, "xmx": "4G"},
        {"max_mb": 500, "xmx": "8G"}
      ]
    }
  },
  "gateway": {
    "host": "0.0.0.0", "port": 8080,
    "max_upload_size_mb": 500, "upload_dir": "~/.revkit/uploads",
    "api_key": null, "allowed_ips": [], "trusted_proxies": [],
    "request_timeout": 60, "batch_timeout": 300,
    "log_rpc_params": false,
    "audit_path": "~/.revkit/logs/gateway/audit.jsonl",
    "audit_max_size_mb": 100
  }
}
```

### Engine Adapter (ida/core.py, jeb/core.py)

shared core는 `load_registry(path) → list[dict]` 인데 commands는 `load_registry() → dict[id, info]` 를 기대.
adapter가 이 변환을 처리:
```python
def load_registry() -> dict:
    entries = _load_registry_raw(_ENGINE_REGISTRY_PATH)
    return {e["id"]: e for e in entries if "id" in e}
```

**IDA core.py 고유**: `arch_detect()`, `get_idb_path()`, `_load_idb_metadata()`, `_md_decompile_batch()`
**JEB core.py 고유**: `_cleanup_instance()`, `_get_launcher_name()`, `_LIST_PARAM_MAP`, `STRING_DISPLAY_LIMIT`

---

## 4. 등록된 CLI 명령 전체 목록 (Tier별)

### 공통 Tier 1 (5개) — `cli/main.py`에서 등록
```
start    서버 인스턴스 시작 (IDA: binary, JEB: APK)
list     활성 인스턴스 목록
stop     인스턴스 종료 (save_db RPC → stop RPC → _wait_for_exit polling → process tree kill on timeout, analysis.stop_timeout=30s). JEB: System.exit(0)으로 즉시 종료 (~3초).
status   인스턴스 상태 조회 (서버 ready 시 RPC status 쿼리: func_count, ida/jeb_version, decompiler_available, uptime, binary_md5, spawn_method, java_home, jvm_opts)
wait     서버 준비 대기
```

### IDA 명령 (57개 in register_commands + 5 Tier1 = 62개)

**Tier 2 — JEB에도 동일 이름 존재 (22개)**
```
decompile, decompile-batch, decompile-all, xrefs, callers, callees,
callgraph, cross-refs, rename, rename-batch, auto-rename, search-code,
strings-xrefs, methods, annotations, report, bookmark, snapshot,
batch, summary, exec, patch
```

**Tier 3 — IDA 고유 (35개)**
```
Instance(5):     init, check, restart, logs, cleanup
Analysis(10):    segments, disasm, bytes, find-func, func-info, imagebase,
                 find-pattern, comments, save, shell
Modification(3): set-type, comment, search-const
Types(5):        structs, enums, type-info, vtables, sigs
Diff(3):         diff, compare, code-diff
Advanced(5):     func-similarity, data-refs, basic-blocks, stack-frame, switch-table
Report(2):       profile, export-script
Utility(2):      update, completions
```

### JEB 명령 (67개 in register_commands + 5 Tier1 = 72개)

**Tier 2 — IDA에도 동일 이름 존재 (22개)**
```
decompile, decompile-batch, decompile-all, xrefs, callers, callees,
callgraph, cross-refs, rename, rename-batch, auto-rename, search-code,
strings-xrefs, methods, annotations, report, bookmark, snapshot,
batch, summary, exec, patch
```

**Tier 3 — JEB 고유 (45개)**
```
Instance(6):     init, check, restart, logs, cleanup, save
Analysis(10):    method, decompile-diff, smali, strings, classes,
                 methods-of-class, fields-of-class, method-info, native-methods
Recon(9):        permissions, components, info, main-activity, app-class,
                 resources, resource, manifest
Search(2):       search-classes, search-methods
Modification(8): rename-class, rename-method, rename-field, rename-preview,
                 set-comment, get-comments, undo
Report(6):       annotations-export, annotations-import,
                 snapshot-save, snapshot-list, snapshot-restore
Security(2):     entry-points, security-scan
Tooling(3):      gen-runner, unpatch, merge
Config(2):       config-show, config-set
Utility(1):      completion
```

---

## 5. 컨텍스트 절약 규칙 (필수)

### 5-1. 파일 읽기 최소화 — 가장 큰 낭비 원인

```bash
# ❌ BAD: 파일 전체 Read (한 파일당 100~450줄 컨텍스트 소모)
Read commands/analysis.py     # 450줄
Read commands/instance.py     # 490줄

# ✅ GOOD: grep으로 필요한 줄만
grep "args\.\|_opt(args" commands/*.py           # args 사용 패턴 전부
grep "from.*import" commands/*.py                # import 의존성
grep -n "^def cmd_" commands/*.py                # cmd_* 함수 목록+위치
grep -c "set_defaults" engine.py                 # 등록된 명령 수
grep "add_parser" engine.py | sed 's/.*"\(.*\)".*/\1/'  # 명령 이름 목록
```

**규칙: Read는 "수정할 파일"에만. "참조할 파일"은 grep으로.**

### 5-2. 반복 패턴 재학습 금지

IDA/JEB는 구조가 동일하다:
- `register_commands()` 패턴: `add_parser → add_argument → _inject_common_options → set_defaults`
- `core.py` adapter: registry path + engine class만 다르고 나머지 동일
- commands 구조: `from ..core import ...` + `cmd_xxx(ctx: CmdContext)`

→ **첫 엔진 작업에서 패턴 1회 학습 → 두 번째 엔진은 Read 없이 바로 작성**

### 5-3. 검증은 묶어서

```bash
# ❌ BAD: 10개 명령 × 각각 실행 = 10 왕복
# ✅ GOOD: 3-4개씩 && 로 묶기 = 3 왕복
echo "=== init ===" && python -m revkit.tools.cli.main jeb init --help && \
echo "=== decompile ===" && python -m revkit.tools.cli.main jeb decompile --help && \
echo "=== rename ===" && python -m revkit.tools.cli.main jeb rename --help
```

### 5-4. Explore 에이전트 남용 금지

| 상황 | 도구 |
|------|------|
| 파일 경로 알고 있음 | `Read` 직접 호출 |
| 키워드 검색 | `grep` 직접 호출 |
| 파일 이름 패턴 | `Glob` 직접 호출 |
| 어디에 있는지 전혀 모름 | 그때만 `Explore` 에이전트 |

### 5-5. 병렬 에이전트 적극 활용

독립 작업이면 Agent 2개 동시 실행:
- IDA core.py 수정 + JEB core.py 수정 → 병렬 OK
- 같은 파일 수정 → 순차 필수

---

## 6. 자주 발생하는 버그 패턴

| 증상 | 원인 | 해결 |
|------|------|------|
| `No module named 'revkit.tools.engines.engines'` | JEB에서 `from ...engines.base` | `from ...base` (3 dots = engines 레벨) |
| `No module named 'shared'` | 레거시 import | `from ..core import` |
| `ModuleNotFoundError: ...core` | adapter 미생성 | `ida/core.py` 또는 `jeb/core.py` 확인 |
| `cp949 codec can't decode` | Windows Python open() | `encoding='utf-8'` 명시 |
| `push declined due to email privacy` | GitHub noreply 설정 | `git config user.email "http8080@users.noreply.github.com"` |
| `_is_process_alive` returns wrong result on Windows | `os.kill(pid, 0)` fails for detached processes on Windows | `registry.py` now uses `psutil.pid_exists(pid)` instead |
| `from shared import` in server/ | 레거시 server 코드가 shared 패키지 참조 | `from core.xxx import` + `ida_server.py`에서 `sys.path`에 `tools/` 추가 |
| `log_path` hardcoded in common.py | 로그 경로가 고정값 | `get_instance_log_path()` 사용으로 변경 |
| `idb_path` empty in Tier1 start | start 명령에서 idb 경로 누락 | `config["paths"]["idb_dir"]`에서 자동 계산 |
| `SyntaxError: flush=True` in JEB server | Jython 2.7은 `print(flush=True)` 미지원 | `print(); sys.stdout.flush()` |
| `TypeError: list indices must be integers` in JEB registry | CLI는 `[]` list, 서버는 `{}` dict 기대 | `_load_registry()`에서 list→dict 변환 |
| JEB server PID/port always None | `config.paths.registry`가 IDA 경로(`ida/registry.json`) | JEB server에서 `~/.revkit/jeb/registry.json` 강제 |
| JEB process dies immediately on start | `DETACHED_PROCESS` flag on Windows | `CREATE_NO_WINDOW` 사용 (레거시 동일) |
| em dash cp949 에러 (Windows) | `tooling.py`에서 `"— up to date"` 출력 | ASCII hyphen `"-"` 으로 교체 |
| cp949 stdout 에러 (Windows CLI 전반) | `print()`가 유니코드 문자를 cp949 stdout에 출력 | `cli/main.py` 진입점에서 stdout/stderr UTF-8 강제 |
| `resource` 명령 빈 출력 | 서버는 `content_b64` 반환, CLI는 `content` 키 참조 | `recon.py cmd_resource`에서 base64 디코딩 추가 |
| `decompile-diff` utf-8 디코딩 에러 | 리다이렉트 파일이 cp949로 저장, `open(encoding="utf-8")` 실패 | `errors="replace"` fallback 추가 |
| `decompile-all` timeout + Permission denied | 대용량 APK (9553 cls)에서 60s timeout 초과 + `--out` 디렉토리를 파일로 열려 시도 | `--out`에 파일 경로 사용 필요 (디렉토리 불가). 대용량은 `--filter` 병용 권장 |
| JEB stop 후 프로세스 안 죽음 (30초 force-kill) | `http_server.stop(0)` 후 JVM 비데몬 스레드 잔류 | `System.exit(0)` 명시 호출 추가 |
| RAM 감지 실패 → 8GB fallback | Windows 11에서 `wmic` 삭제됨 | `psutil.virtual_memory()` 우선 사용 |
| `force_kill`이 자식 프로세스 안 죽임 | `proc.kill()`은 부모만 종료 | `psutil.children(recursive=True)` + `taskkill /T` |
| stderr 파일 핸들 누수 (`process.py`) | `detach_spawn`에서 `open()` 후 close 안 함 | Popen 후 `stderr_file.close()` |
| 존재하지 않는 파일로 `start` → 좀비 | `cmd_start`에서 파일 존재 체크 누락 | `Path(binary).exists()` 추가 (09baf22) |
| 잘못된 config.json → traceback 노출 | `load_config`에서 JSONDecodeError 미처리 | `main.py`에 `ValueError` catch 추가 (09baf22) |
| `max_instances=0`인데 start 허용 | start에서 인스턴스 수 제한 미체크 | `cleanup_stale` 후 len 비교 (09baf22) |
| JEB `wait` → "No active instances" | start 직후 wait 호출 시 레지스트리 미등록 | `cmd_wait`에 30초 재시도 루프 (09baf22) |
| JEB manifest/entry-points 서버 crash | `_handle_get_manifest` 등에서 Java NPE | `bare except` 추가로 crash 방지 (256ca5b), 기능은 미동작 |
| `jar` not found in `patch`/`gen-runner` | `java_home` 빈값 + PATH에 Java 없음 | `FileNotFoundError` 시 `jeb.java_home` 설정 힌트 |
| `merge`에 개별 APK 파일 넘기면 에러만 | split-APK 디렉토리/XAPK 필요 | 디렉토리 사용 힌트 메시지 추가 |
| `_write_output`이 실패해도 "Output saved" | result가 None일 때도 출력 | `result is None` 체크 추가 |
| IDA 서버 `config["analysis"]` KeyError | `open_db_timeout`, `auto_save`, `heartbeat_interval` 등 하드 접근 | `.get()` with defaults로 변경 (framework.py, 6곳) |
| IDA/JEB CLI `config["analysis"]` KeyError | `wait_poll_interval`, `stale_threshold`, `max_instances` 하드 접근 | `.get()` with defaults (instance.py, batch.py, 7곳) |
| IDA 서버 `config["output"]`, `["log"]`, `["server"]` KeyError | 서버 시작 시 config 섹션 누락되면 crash | `.get()` with defaults |
| JEB launcher 이름 Linux 오류 | `_get_launcher_name()` → `"jeb"` 반환, 실제는 `jeb_linux.sh` | Linux: `jeb_linux.sh`, macOS: `jeb_macos.sh` 분기 |
| JEB `get_resource` 이름 불일치 | resources 목록 "Manifest" vs 접근 "AndroidManifest.xml" | fuzzy name matching 추가 (exact → case-insensitive → partial) |
| JEB `import_annotations` RPC crash | comments가 list `[]`일 때 `.items()` 호출 | `isinstance(comments, list)` 체크 |
| JEB `undo` RPC 미구현 | `UNKNOWN_METHOD` 에러 | 서버 히스토리 기반 undo 핸들러 추가 |
| JEB RPC 빈 `{}` params 파싱 실패 | Jython 2.7 JSON 파서 특성 | `params` None/비dict 시 빈 dict fallback |
| JEB RPC 파라미터 이름 혼동 | `class` vs `class_sig`, `target` vs `sig` | `_PARAM_ALIASES` 확장 (양쪽 이름 모두 허용) |
| Linux symlink 미생성 (`migrate.py`) | Windows junction만 있고 Linux 대응 없음 | `_create_symlink()` 추가 |
| `handlers_old.py` 레거시 파일 잔존 | IDA/JEB 양쪽에 미사용 레거시 핸들러 | 삭제 (import 없음 확인) |
| 원격 모드 positional 인자 미전달 | `type_str`, `hex_bytes`, `text` 등이 RPC params에 미포함 | `cli/main.py` `_PARAM_REMAP` 딕셔너리로 키 변환 |
| 원격 모드 action 기반 RPC 무시 | `snapshot --action save` → `snapshot_list` 호출 | `_ACTION_RPC_MAP`으로 action별 RPC 메서드 분기 |
| 원격 모드 `rename-batch --file` 미전달 | 파일 경로만 전송, 내용 미전송 | 로컬 JSON 읽어서 `entries` 배열로 전달 |
| Gateway `exec_enabled` 영구 차단 | `GATEWAY_DEFAULTS`에 키 누락 → config에서 항상 strip | `gateway/config.py`에 `"exec_enabled": False` 추가 |
| Gateway `_log_connection()` 미호출 | 정의만 되어있고 호출 없음 (dead code) | `route_request` 완료 후 호출 추가 |
| Gateway stop-all JEB 카운트 누락 | JEB `System.exit(0)` → 연결 끊김 → "failed" 카운트 | 프로세스 종료 확인 후 stopped에 포함 |
| Gateway audit 항상 200 기록 | 예외 발생 시에도 `_audit(200)` 호출 | `_response_status` 추적 후 실제 코드 기록 |
| Gateway 포트 바인딩 에러 크래시 | 포트 사용 중 `OSError` 미처리 | try/except + 깔끔한 에러 메시지 + sys.exit(1) |
| auth token 콜론 잘림 | `split(":")` → 토큰 내 콜론 이후 소실 | `split(":", 2)` maxsplit 사용 |
| JEB server `open()` encoding 누락 (7곳) | Jython 2.7에서 `open()`은 encoding 미지원 | `io.open(..., encoding="utf-8")` 사용 |
| `wait_for_start` 타임아웃 시 프로세스 미종료 | start 후 wait 실패해도 프로세스 영원히 생존 | 타임아웃 시 `force_kill(pid)` 호출 |
| `cleanup_stale` 레이스 컨디션 | 락 없이 load→save → 동시 register 유실 | `registry_locked()` 보호 추가 |
| `cmd_start` spawn 실패 시 유령 엔트리 | register 후 spawn → spawn 실패 시 엔트리 잔존 | spawn 후 register 순서 역전 |
| `cmd_wait` Ctrl+C 시 고아 프로세스 | KeyboardInterrupt 미처리 → 프로세스 방치 | except KeyboardInterrupt → force_kill |
| `detach_spawn` Popen 실패 시 FD 누수 | stderr 파일 open 후 Popen 실패 → close 미호출 | try/except 추가, `"ab"` 바이너리 모드 |
| config `["key"]["key"]` 직접 접근 (18곳) | 빈 config 시 KeyError 크래시 | `.get("key", {}).get("key", "")` 패턴 |
| `_handle_rename_preview` 시그니처 오류 | `_resolve_dex_item(self, sig)` → 첫 인자는 dex | `_resolve_dex_item(dex, sig)` |
| `_write_output` NameError (jeb/analysis.py) | 미정의 함수 호출 | `_save_local()` 사용 |
| `int(params.get("size"))` ValueError | 비정수 입력 시 크래시 | try/except + 기본값 fallback |
| HTTP 스레드에서 `sleep(1)` 블로킹 | stop-all, delete에서 sleep → 스레드 풀 고갈 | 백그라운드 daemon 스레드로 이동 |

> **⚠️ JEB server (`engines/jeb/server/`) = Jython 2.7 전용**
> f-string, type hint, walrus operator, `flush=True` 등 Python 3 문법 절대 사용 금지.
> CLI 코드(`commands/`, `engine.py`, `core.py`)는 Python 3.10+ OK.

### 상대 import 경로 기준표

```
commands/xxx.py 에서:
  from ..core import ...     → engines/{ida|jeb}/core.py     ✅
  from ...base import ...    → engines/base.py               ✅
  from ...core.xxx import .. → tools/core/xxx.py             ✅
  from ...engines.base       → engines/engines/base (없음)   ❌
```

---

## 7. 새 기능 추가 최소 절차

```
1. grep "def cmd_새기능" commands/              # 이미 있는지 확인
2. 없으면 → commands/적절한모듈.py에 cmd_xxx(ctx: CmdContext) 추가
3. commands/__init__.py에 export 추가
4. engine.py register_commands()에 subparser 등록
5. python -m revkit.tools.cli.main {ida|jeb} 새기능 --help
```

새 모듈을 추가하는 경우 (드묾):
```
1. commands/새모듈.py 생성
2. commands/__init__.py에서 from .새모듈 import cmd_xxx
3. engine.py에서 from .commands import cmd_xxx
4. subparser 등록
```

---

## 8. 테스트 실행

```bash
# CLI 전체 확인
python -m revkit.tools.cli.main --help
python -m revkit.tools.cli.main ida --help
python -m revkit.tools.cli.main jeb --help

# 명령 수 카운트
python -m revkit.tools.cli.main ida --help 2>&1 | grep -E "^    \w" | wc -l  # → 62
python -m revkit.tools.cli.main jeb --help 2>&1 | grep -E "^    \w" | wc -l  # → 72

# 개별 명령 검증
python -m revkit.tools.cli.main ida decompile --help
python -m revkit.tools.cli.main jeb rename --help

# Tier 1 비파괴 확인
python -m revkit.tools.cli.main ida list   # → "No active instances" (정상)
python -m revkit.tools.cli.main jeb list   # → "No active instances" (정상)
```

---

## 9. 원격 모드 (Gateway)

`~/.revkit/config.json`에 `gateway.url`이 설정되어 있으면 **모든 CLI 명령이 자동으로 원격 서버에서 실행됨**. 명령 형식 변경 없음.

```bash
# 로컬이든 리모트든 동일한 명령
python -m revkit.tools.cli.main ida decompile 0x401000
python -m revkit.tools.cli.main jeb classes

# 1회성 오버라이드
python -m revkit.tools.cli.main --remote http://other:9090 ida list
```

- 서버 설정: `gateway.host` + `gateway.port` → 게이트웨이 데몬 바인드
- 클라이언트 설정: `gateway.url` → 원격 서버 주소 (비어있으면 로컬)
- 우선순위: `--remote` CLI > `gateway.url` config > 로컬 모드
- 상세: `docs/README-Remote.md`

---

## 10. Git / GitHub

```bash
# 리포
https://github.com/http8080/PrivateProject

# push 전 이메일 설정 (GitHub privacy)
git config user.email "http8080@users.noreply.github.com"

# 83MB APK warning은 무시 가능 (push 됨)
```
