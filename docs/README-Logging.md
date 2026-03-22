# revkit — Logging System

Detailed documentation for the revkit logging system, log formats, and troubleshooting.

revkit 로깅 시스템, 로그 포맷, 트러블슈팅에 대한 상세 문서.

---

## Table of Contents

- [Overview / 개요](#overview--개요)
- [Directory Structure / 디렉토리 구조](#directory-structure--디렉토리-구조)
- [Log Types / 로그 유형](#log-types--로그-유형)
  - [Global Log / 글로벌 로그](#global-log--글로벌-로그)
  - [Command Log / 명령어 로그](#command-log--명령어-로그)
  - [Engine Log / 엔진 로그](#engine-log--엔진-로그)
  - [Instance Log / 인스턴스 로그](#instance-log--인스턴스-로그)
  - [Instance Stderr / 인스턴스 Stderr](#instance-stderr--인스턴스-stderr)
  - [Gateway Log / 게이트웨이 로그](#gateway-log--게이트웨이-로그)
- [Audit Logs / 감사 로그](#audit-logs--감사-로그)
- [API Reference / API 레퍼런스](#api-reference--api-레퍼런스)
- [Configuration / 설정](#configuration--설정)
- [Troubleshooting / 트러블슈팅](#troubleshooting--트러블슈팅)

---

## Overview / 개요

The revkit logging system records all CLI operations, engine activity, and server events in structured JSONL format.

revkit 로깅 시스템은 모든 CLI 작업, 엔진 활동, 서버 이벤트를 구조화된 JSONL 형식으로 기록한다.

| Feature / 기능 | Value / 값 |
| -------------- | ---------- |
| Log format / 로그 포맷 | JSONL (one JSON object per line / 한 줄에 JSON 객체 하나) |
| Log directory / 로그 디렉토리 | `~/.revkit/logs/` |
| Rotation handler / 로테이션 핸들러 | `RotatingFileHandler` |
| Max file size / 최대 파일 크기 | 10 MB (configurable / 설정 가능) |
| Backup count / 백업 수 | 3 (configurable / 설정 가능) |
| Module / 모듈 | `revkit/tools/core/logging_setup.py` |

### How It Works / 동작 방식

```text
revkit {ida|jeb} <command>
       │
       ▼
  init_logging(verbose)          ← called once at CLI startup / CLI 시작 시 한 번 호출
       │
       ├── revkit.jsonl          ← global log (all events)
       ├── commands.jsonl        ← command execution record
       ├── {engine}/engine.jsonl ← engine-specific events
       └── {engine}/instances/   ← per-instance server logs
```

All log files use **JSONL** (JSON Lines) format: one self-contained JSON object per line. This makes logs easy to parse with standard tools like `jq`, `python -m json.tool`, or simple line-by-line readers.

모든 로그 파일은 **JSONL** (JSON Lines) 형식을 사용한다: 한 줄에 하나의 독립된 JSON 객체. `jq`, `python -m json.tool`, 또는 단순 라인 단위 리더로 쉽게 파싱할 수 있다.

---

## Directory Structure / 디렉토리 구조

```text
~/.revkit/logs/
├── revkit.jsonl            ← global log (all engines, all commands)
│                              글로벌 로그 (모든 엔진, 모든 명령어)
├── commands.jsonl           ← CLI command execution log
│                              CLI 명령어 실행 로그
├── ida/
│   ├── engine.jsonl        ← IDA engine operations
│   │                          IDA 엔진 작업 로그
│   └── instances/
│       ├── {iid}.jsonl     ← per-instance server log
│       │                      인스턴스별 서버 로그
│       └── {iid}.stderr    ← per-instance stderr (raw text)
│                              인스턴스별 stderr (원문 텍스트)
├── jeb/
│   ├── engine.jsonl        ← JEB engine operations
│   │                          JEB 엔진 작업 로그
│   └── instances/
│       └── ...             ← same structure as ida/instances/
│                              ida/instances/와 동일 구조
└── gateway/
    └── gateway.jsonl       ← gateway HTTP request log
                               게이트웨이 HTTP 요청 로그
```

> Directories are created lazily on first write. If you never use the JEB engine, `jeb/` will not exist.
>
> 디렉토리는 최초 기록 시 자동 생성된다. JEB 엔진을 사용하지 않으면 `jeb/` 디렉토리는 생성되지 않는다.

---

## Log Types / 로그 유형

### Global Log / 글로벌 로그

**File / 파일**: `~/.revkit/logs/revkit.jsonl`

The global log captures all events across all engines and commands. It is the single source of truth for what happened in revkit.

글로벌 로그는 모든 엔진과 명령어의 이벤트를 기록한다. revkit에서 발생한 모든 일의 단일 진실 소스(single source of truth)이다.

**Format / 포맷**:

```json
{"ts": "2026-03-20T14:32:01.123Z", "level": "INFO", "logger": "revkit.ida", "msg": "Tier1 cmd=list", "data": {"cmd": "list", "engine": "ida", "trace_id": "030f73ac93ef"}}
{"ts": "2026-03-20T14:32:05.456Z", "level": "INFO", "logger": "revkit.ida", "msg": "lifecycle: instance.start", "data": {"iid": "a3f2", "event": "instance.start", "binary": "/path/to/sample.exe", "pid": 12345, "spawn_method": "default"}}
```

| Field / 필드 | Type / 타입 | Description / 설명 |
| ------------ | ----------- | ------------------ |
| `ts` | string (ISO 8601) | Timestamp / 타임스탬프 |
| `level` | string | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `logger` | string | Logger name (e.g. `revkit.ida`) / 로거 이름 |
| `msg` | string | Log message / 로그 메시지 |
| `data` | object (optional) | Structured data (P8) / 구조화된 데이터. Contains `trace_id`, `iid`, `cmd`, `elapsed_ms`, etc. |

---

### Command Log / 명령어 로그

**File / 파일**: `~/.revkit/logs/commands.jsonl`

Records every CLI command execution with timing and result status. Useful for auditing and performance analysis.

모든 CLI 명령어 실행을 시간 및 결과 상태와 함께 기록한다. 감사 및 성능 분석에 유용하다.

**Format / 포맷**:

```json
{"ts": "2026-03-20T14:32:01.123Z", "engine": "ida", "cmd": "start", "ok": true, "ms": 1500.2, "iid": "a3f2", "args": {"engine": "ida", "command": "start", "binary": "sample.exe"}}
{"ts": "2026-03-20T14:32:05.456Z", "engine": "jeb", "cmd": "decompile", "ok": false, "ms": 3200.1, "iid": "b7c1", "args": {"sig": "Lcom/example/Foo;"}, "error": "RPC timeout"}
```

| Field / 필드 | Type / 타입 | Description / 설명 |
| ------------ | ----------- | ------------------ |
| `ts` | string | Timestamp / 타임스탬프 |
| `engine` | string | `ida` or `jeb` / `ida` 또는 `jeb` |
| `cmd` | string | Command name / 명령어 이름 |
| `ok` | boolean | `true` if succeeded / 성공 시 `true` |
| `ms` | number | Elapsed time in milliseconds / 경과 시간 (밀리초) |
| `iid` | string | Instance ID (P1: now included for all Tier 1 commands) / 인스턴스 ID (P1: 모든 Tier 1 명령어에 포함) |
| `args` | object | Sanitized CLI arguments / 정제된 CLI 인자 |
| `error` | string | Error message (only on failure) / 에러 메시지 (실패 시만) |

---

### Engine Log / 엔진 로그

**File / 파일**: `~/.revkit/logs/{engine}/engine.jsonl`

Engine-specific log. Same format as the global log, but filtered to only contain events from one engine. Includes **lifecycle events** (P3) for instance start/ready/error/stop.

엔진별 로그. 글로벌 로그와 동일한 포맷이지만 해당 엔진의 이벤트만 포함한다. 인스턴스 start/ready/error/stop **라이프사이클 이벤트**(P3)를 포함한다.

**Format / 포맷**:

```json
{"ts": "2026-03-20T14:32:01.123Z", "level": "INFO", "logger": "revkit.ida", "msg": "lifecycle: instance.start", "data": {"iid": "a3f2", "event": "instance.start", "binary": "/path/sample.exe", "pid": 12345, "spawn_method": "default"}}
{"ts": "2026-03-20T14:32:30.456Z", "level": "INFO", "logger": "revkit.ida", "msg": "lifecycle: instance.ready", "data": {"iid": "a3f2", "event": "instance.ready", "port": 18100}}
{"ts": "2026-03-20T14:35:00.789Z", "level": "INFO", "logger": "revkit.ida", "msg": "lifecycle: instance.stop", "data": {"iid": "a3f2", "event": "instance.stop"}}
```

**Lifecycle events / 라이프사이클 이벤트**:

| Event / 이벤트 | Description / 설명 |
| -------------- | ------------------ |
| `instance.start` | CLI dispatched a start command. Includes `spawn_method` (`wrapper`, `bat`, or `default`). / CLI에서 시작 명령 디스패치. `spawn_method` 포함 (`wrapper`, `bat`, 또는 `default`). |
| `instance.db_open` | Database opened successfully / 데이터베이스 열기 성공 |
| `instance.metadata` | Analysis metadata (arch, func_count, decompiler) / 분석 메타데이터 |
| `instance.ready` | Server is ready for RPC / 서버가 RPC 준비 완료 |
| `instance.error` | Fatal error occurred / 치명적 에러 발생 |
| `instance.stop` | Instance stopped / 인스턴스 종료 |
| `instance.shutdown` | Server process exiting / 서버 프로세스 종료 |

---

### Instance Log / 인스턴스 로그

**File / 파일**: `~/.revkit/logs/{engine}/instances/{iid}.jsonl`

Per-instance server log. Captures server startup, RPC call details, lifecycle events, and errors. Now uses **JSONL format** (P2) with `iid` field for traceability.

인스턴스별 서버 로그. 서버 시작, RPC 호출 세부 정보, 라이프사이클 이벤트, 에러를 기록한다. 추적성을 위해 `iid` 필드가 포함된 **JSONL 형식**(P2)을 사용한다.

**Format / 포맷**:

```json
{"ts": "2026-03-20T14:32:01.123Z", "level": "INFO", "iid": "a3f2", "msg": "lifecycle: instance.start", "data": {"iid": "a3f2", "event": "instance.start", "binary": "/path/sample.exe", "spawn_method": "default"}}
{"ts": "2026-03-20T14:32:02.456Z", "level": "INFO", "iid": "a3f2", "msg": "RPC decompile -> OK (120ms)", "data": {"method": "decompile", "elapsed_ms": 120, "trace_id": "030f73ac93ef"}}
{"ts": "2026-03-20T14:32:03.789Z", "level": "WARNING", "iid": "a3f2", "msg": "RPC decompile -> NOT_A_FUNCTION: No function at 0xDEAD", "data": {"method": "decompile", "error_code": "NOT_A_FUNCTION"}}
```

| Field / 필드 | Type / 타입 | Description / 설명 |
| ------------ | ----------- | ------------------ |
| `ts` | string | Timestamp (UTC ISO 8601) / 타임스탬프 (UTC) |
| `level` | string | Log level / 로그 레벨 |
| `iid` | string | Instance ID / 인스턴스 ID |
| `msg` | string | Log message / 로그 메시지 |
| `data` | object (optional) | Structured data: `method`, `elapsed_ms`, `trace_id`, `event`, etc. |

---

### Instance Stderr / 인스턴스 Stderr

**File / 파일**: `~/.revkit/logs/{engine}/instances/{iid}.stderr`

Raw text output from the server process's stderr. Contains Python/Jython tracebacks, library warnings, and other unstructured output. Not JSONL.

서버 프로세스의 stderr 원문 텍스트 출력. Python/Jython 트레이스백, 라이브러리 경고, 기타 비구조화 출력을 포함한다. JSONL이 아니다.

**Example / 예시**:

```text
Traceback (most recent call last):
  File "/opt/ida/python/3/ida_kernwin.py", line 42, in _dispatch
    result = handler(params)
  File "server/handlers/analysis.py", line 15, in handle_decompile
    raise ValueError(f"Invalid address: {addr}")
ValueError: Invalid address: 0xdeadbeef
```

> This file is not rotated. It grows until the instance is stopped. Clean up manually or via `revkit {engine} cleanup`.
>
> 이 파일은 로테이션되지 않는다. 인스턴스가 종료될 때까지 계속 증가한다. 수동 삭제 또는 `revkit {engine} cleanup`으로 정리한다.

---

### Gateway Log / 게이트웨이 로그

**File / 파일**: `~/.revkit/logs/gateway/gateway.jsonl`

HTTP request log for the gateway daemon. Records all incoming API requests.

게이트웨이 데몬의 HTTP 요청 로그. 모든 수신 API 요청을 기록한다.

**Format / 포맷**:

```json
{"ts": "2026-03-20T14:32:01.123Z", "level": "INFO", "method": "POST", "path": "/api/ida/decompile", "status": 200, "ms": 150.3, "client": "127.0.0.1"}
{"ts": "2026-03-20T14:32:02.456Z", "level": "WARNING", "method": "POST", "path": "/api/jeb/decompile", "status": 401, "ms": 2.1, "client": "192.168.1.10", "error": "Invalid token"}
```

---

## Audit Logs / 감사 로그

Audit logs are **separate** from the logging system. They track every RPC method call and gateway HTTP request for security and compliance purposes.

감사 로그는 로깅 시스템과 **별개**이다. 보안 및 규정 준수 목적으로 모든 RPC 메서드 호출과 게이트웨이 HTTP 요청을 추적한다.

### Engine Audit / 엔진 감사 로그

**File / 파일**: `~/.revkit/{engine}/audit.jsonl`

```json
{"ts": "2026-03-20T14:32:02.456Z", "method": "decompile", "args": {"addr": "0x401000"}, "ok": true, "ms": 120.5, "instance": "a3f2"}
{"ts": "2026-03-20T14:32:05.789Z", "method": "exec_code", "args": {"code": "[REDACTED]"}, "ok": true, "ms": 50.2, "instance": "a3f2"}
```

### Gateway Audit / 게이트웨이 감사 로그

**File / 파일**: `~/.revkit/logs/gateway/audit.jsonl`

```json
{"ts": "2026-03-20T14:32:01.123Z", "method": "POST", "path": "/api/ida/decompile", "client": "127.0.0.1", "user": "admin", "status": 200}
```

### Redacted Fields / 자동 삭제 필드

The following fields are automatically redacted in audit logs to prevent sensitive data leakage:

다음 필드는 민감 데이터 유출 방지를 위해 감사 로그에서 자동으로 삭제(redact)된다:

| Field / 필드 | Reason / 사유 |
| ------------ | ------------- |
| `code` | Arbitrary Python/Jython code execution / 임의 Python/Jython 코드 실행 |
| `script` | Script file contents / 스크립트 파일 내용 |
| `exec_code` | Dynamic code execution payload / 동적 코드 실행 페이로드 |

Redacted values are replaced with `"[REDACTED]"`.

삭제된 값은 `"[REDACTED]"`로 대체된다.

---

## API Reference / API 레퍼런스

Module: `revkit/tools/core/logging_setup.py`

모듈: `revkit/tools/core/logging_setup.py`

### `JsonFormatter`

Custom `logging.Formatter` that outputs JSON objects. Produces one JSON line per log record with `ts`, `level`, `logger`, and `msg` fields.

JSON 객체를 출력하는 커스텀 `logging.Formatter`. 로그 레코드마다 `ts`, `level`, `logger`, `msg` 필드를 가진 JSON 한 줄을 생성한다.

### `init_logging(verbose=False)`

Initialize the logging system. Must be called **once** at CLI startup before any commands execute.

로깅 시스템을 초기화한다. 명령어 실행 전에 CLI 시작 시 **한 번** 호출해야 한다.

| Parameter / 매개변수 | Type / 타입 | Description / 설명 |
| -------------------- | ----------- | ------------------ |
| `verbose` | `bool` | If `True`, set root logger to `DEBUG`. Default `INFO`. / `True`이면 루트 로거를 `DEBUG`로 설정. 기본값 `INFO`. |

```python
from revkit.tools.core.logging_setup import init_logging
init_logging(verbose=True)  # enable debug output / 디버그 출력 활성화
```

### `get_engine_logger(engine_name) -> logging.Logger`

Return a logger scoped to the given engine. Writes to both the global log and the engine-specific log.

지정된 엔진에 한정된 로거를 반환한다. 글로벌 로그와 엔진별 로그 모두에 기록한다.

```python
logger = get_engine_logger("ida")
logger.info("Instance started on port 18100")
# writes to: revkit.jsonl AND ida/engine.jsonl
```

### `get_instance_log_path(engine_name, instance_id) -> Path`

Return the path to the JSONL log file for a specific instance.

특정 인스턴스의 JSONL 로그 파일 경로를 반환한다.

```python
path = get_instance_log_path("ida", "a3f2")
# -> ~/.revkit/logs/ida/instances/a3f2.jsonl
```

### `get_instance_stderr_path(engine_name, instance_id) -> Path`

Return the path to the stderr capture file for a specific instance.

특정 인스턴스의 stderr 캡처 파일 경로를 반환한다.

```python
path = get_instance_stderr_path("ida", "a3f2")
# -> ~/.revkit/logs/ida/instances/a3f2.stderr
```

### `get_gateway_logger() -> logging.Logger`

Return a logger for the gateway daemon. Writes to both the global log and `gateway/gateway.jsonl`.

게이트웨이 데몬용 로거를 반환한다. 글로벌 로그와 `gateway/gateway.jsonl` 모두에 기록한다.

```python
logger = get_gateway_logger()
logger.info("Request received", extra={"method": "POST", "path": "/api/ida/decompile"})
```

### `log_command(engine, command, args, result_ok, elapsed_ms, error=None, instance_id=None)`

Write a structured entry to `commands.jsonl`. Called automatically by the CLI dispatcher after each command completes. Instance ID is now included for **all** Tier 1 commands (P1).

`commands.jsonl`에 구조화된 항목을 기록한다. 각 명령어 완료 후 CLI 디스패처가 자동으로 호출한다. 이제 **모든** Tier 1 명령어에 인스턴스 ID가 포함된다 (P1).

| Parameter / 매개변수 | Type / 타입 | Description / 설명 |
| -------------------- | ----------- | ------------------ |
| `engine` | `str` | Engine name (`"ida"` or `"jeb"`) / 엔진 이름 |
| `command` | `str` | Command name / 명령어 이름 |
| `args` | `dict` | Sanitized arguments / 정제된 인자 |
| `result_ok` | `bool` | Whether the command succeeded / 명령어 성공 여부 |
| `elapsed_ms` | `float` | Elapsed time in ms / 경과 시간 (밀리초) |
| `error` | `str \| None` | Error message if failed / 실패 시 에러 메시지 |
| `instance_id` | `str \| None` | Instance ID if applicable / 해당 시 인스턴스 ID |

### `generate_trace_id() -> str`

Generate a 12-character trace ID for correlating CLI commands with server-side RPC calls (P4). Automatically included in all RPC requests as `_trace_id` parameter.

CLI 명령과 서버 RPC 호출을 상관시키기 위한 12자 trace ID를 생성한다 (P4). 모든 RPC 요청에 `_trace_id` 파라미터로 자동 포함된다.

```python
from revkit.tools.core.logging_setup import generate_trace_id
tid = generate_trace_id()  # e.g. "030f73ac93ef"
```

### `log_with_data(logger, level, msg, data=None)`

Log a message with structured `extra_data` (P8). The `data` dict appears as the `"data"` field in JSONL output.

구조화된 `extra_data`와 함께 메시지를 로깅한다 (P8). `data` 딕셔너리는 JSONL 출력의 `"data"` 필드로 표시된다.

```python
from revkit.tools.core.logging_setup import log_with_data, get_engine_logger
import logging

logger = get_engine_logger("ida")
log_with_data(logger, logging.INFO, "command executed", {
    "cmd": "decompile", "iid": "a3f2", "trace_id": "030f73ac93ef",
})
# -> {"ts": "...", "level": "INFO", "logger": "revkit.ida", "msg": "command executed", "data": {"cmd": "decompile", "iid": "a3f2", "trace_id": "030f73ac93ef"}}
```

### `log_lifecycle(engine_name, event, instance_id, **extra)`

Log an instance lifecycle event to the engine logger (P3). Events are prefixed with `instance.` (e.g., `instance.start`, `instance.ready`, `instance.stop`).

인스턴스 라이프사이클 이벤트를 엔진 로거에 기록한다 (P3). 이벤트에 `instance.` 접두사가 붙는다.

```python
from revkit.tools.core.logging_setup import log_lifecycle
log_lifecycle("ida", "instance.start", "a3f2", binary="/path/sample.exe", pid=12345, spawn_method="default")
# JEB example with spawn_method:
log_lifecycle("jeb", "instance.start", "b7c1", binary="sample.apk", pid=5678, spawn_method="wrapper")
```

---

## Configuration / 설정

Logging configuration is stored in `~/.revkit/config.json` under the `log` key.

로깅 설정은 `~/.revkit/config.json`의 `log` 키 아래에 저장된다.

```json
{
    "paths": {
        "log_dir": "~/.revkit/logs"
    },
    "log": {
        "max_size_mb": 10,
        "backup_count": 3,
        "stderr_capture": true
    }
}
```

| Key / 키 | Type / 타입 | Default / 기본값 | Description / 설명 |
| --------- | ----------- | ---------------- | ------------------ |
| `log.max_size_mb` | `int` | `10` | Maximum log file size before rotation (MB) / 로테이션 전 최대 로그 파일 크기 (MB) |
| `log.backup_count` | `int` | `3` | Number of rotated backup files to keep / 보관할 로테이션 백업 파일 수 |
| `log.stderr_capture` | `bool` | `true` | Capture engine process stderr to per-instance `.stderr` files. When enabled, stderr from IDA/JEB server processes is redirected to `~/.revkit/logs/{engine}/instances/{iid}.stderr`. Disable to let stderr go to the parent process console instead. / 엔진 프로세스 stderr를 인스턴스별 `.stderr` 파일로 캡처. 활성화 시 IDA/JEB 서버 프로세스의 stderr가 `~/.revkit/logs/{engine}/instances/{iid}.stderr`로 리디렉션됨. 비활성화하면 stderr가 부모 프로세스 콘솔로 출력됨. |

When a log file exceeds `max_size_mb`, it is renamed with a `.1`, `.2`, `.3` suffix (newest = `.1`). The oldest backup (`.3`) is deleted when a new rotation occurs.

로그 파일이 `max_size_mb`를 초과하면 `.1`, `.2`, `.3` 접미사가 붙은 이름으로 변경된다 (최신 = `.1`). 새 로테이션 시 가장 오래된 백업(`.3`)이 삭제된다.

**Example / 예시**:

```text
revkit.jsonl        ← current (active) / 현재 (활성)
revkit.jsonl.1      ← previous rotation / 이전 로테이션
revkit.jsonl.2      ← two rotations ago / 2회 전 로테이션
revkit.jsonl.3      ← oldest (deleted on next rotation) / 가장 오래된 (다음 로테이션 시 삭제)
```

---

## Log Levels / 로그 레벨

revkit uses Python's standard logging levels. Each core module has its own logger (`logging.getLogger(__name__)`).

revkit은 Python 표준 로깅 레벨을 사용한다. 각 코어 모듈은 자체 로거(`logging.getLogger(__name__)`)를 가진다.

| Level / 레벨 | Count / 수 | When used / 사용 시점 | Examples / 예시 |
| ------------ | ---------- | -------------------- | -------------- |
| `DEBUG` | ~270 | Internal operations — config loading, instance resolution tiers, registry I/O, stale cleanup, process spawn, auth token lookup, RPC calls (method/params/elapsed), cmd_* entry/result, gateway routing / 내부 작업 — 설정 로딩, 인스턴스 해석 단계, 레지스트리 I/O, stale 정리, 프로세스 생성, auth 토큰 조회, RPC 호출 (메서드/파라미터/경과 시간), cmd_* 진입/결과, 게이트웨이 라우팅 | `cmd_decompile: addr=0x401000`, `_rpc_call: method=decompile -> result keys=['code', 'sig']`, `post_rpc: method=decompile -> OK (120.5ms)` |
| `INFO` | ~16 | Normal operations — command execution, lifecycle events / 정상 작업 — 명령 실행, 라이프사이클 이벤트 | `lifecycle: instance.start`, `Tier1 cmd=list` |
| `WARNING` | ~60 | Recoverable issues — corrupt registry JSON, stale lock removal, failed config merge, auth token file read errors, RPC failures during stop, process exit timeout, empty results, silent exception handlers / 복구 가능한 문제 — 손상된 레지스트리 JSON, stale 잠금 제거, 설정 병합 실패, auth 토큰 파일 읽기 오류, stop 시 RPC 실패, 프로세스 종료 타임아웃, 빈 결과, 무시된 예외 처리 | `Corrupt registry JSON at ...`, `cmd_stop: PID 1234 did not exit gracefully`, `Failed to read auth token file` |
| `ERROR` | ~6 | Command failures, RPC errors, gateway config errors / 명령 실패, RPC 에러, 게이트웨이 설정 오류 | `RPC error: NOT_A_FUNCTION`, `Instance 'xxx' not found` |

### Module loggers / 모듈별 로거

| Layer / 계층 | Module / 모듈 | Logger name / 로거 이름 | DEBUG events / DEBUG 이벤트 |
| ------------ | ------------- | ---------------------- | -------------------------- |
| Core | `core/config.py` | `revkit.tools.core.config` | Config load path, default fallback, project-local merge |
| Core | `core/instance.py` | `revkit.tools.core.instance` | Resolve tier (1/2/3), stale cleanup count, wait_for_start polling |
| Core | `core/registry.py` | `revkit.tools.core.registry` | Load/save entry counts, stale cleanup details (reason per entry), lock warnings |
| Core | `core/process.py` | `revkit.tools.core.process` | Spawn command + PID, force-kill PID |
| Core | `core/rpc.py` | `revkit.tools.core.rpc` | RPC retry attempts with error details |
| CLI | `cli/main.py` | `revkit.{engine}` (engine logger) | CLI entry (engine/command/verbose/json), config load, trace_id generation |
| CLI | `cli/commands/common.py` | `revkit.tools.cli.commands.common` | Tier 1 cmd_* entry/args, stop RPC flow, wait timeouts, start spawn details |
| Engine | `engines/ida/engine.py` | `revkit.tools.engines.ida.engine` | build_spawn_config cmd/stderr, spawn method details |
| Engine | `engines/jeb/engine.py` | `revkit.tools.engines.jeb.engine` | build_spawn_config cmd/heap/method, Java resolution |
| Engine | `engines/ida/core.py` | `revkit.tools.engines.ida.core` | Auth token load/remove, post_rpc method/elapsed, _rpc_call params/result |
| Engine | `engines/jeb/core.py` | `revkit.tools.engines.jeb.core` | Auth token load/remove, post_rpc method/elapsed, _rpc_call params/result |
| Commands | `engines/ida/commands/*.py` | `revkit.tools.engines.ida.commands.*` | cmd_* entry with key args, RPC result counts, file I/O paths, cleanup actions |
| Commands | `engines/jeb/commands/*.py` | `revkit.tools.engines.jeb.commands.*` | cmd_* entry with key args, RPC result counts, file I/O paths, cleanup actions |
| Gateway | `gateway/router.py` | `revkit.tools.gateway.router` | Route matching, RPC proxy forwarding, engine errors |
| Gateway | `gateway/auth.py` | `revkit.tools.gateway.auth` | Client IP extraction, auth success/failure |
| Gateway | `gateway/upload.py` | `revkit.tools.gateway.upload` | Upload file save (id/name/size/path) |
| Gateway | `gateway/daemon.py` | `revkit.gateway` | Server bind, signal handling, shutdown |

### Enabling DEBUG output / DEBUG 출력 활성화

```bash
# CLI verbose mode: stderr에 DEBUG 출력
revkit -v ida list

# Or in code: / 또는 코드에서:
from revkit.tools.core.logging_setup import init_logging
init_logging(verbose=True)
```

---

## Troubleshooting / 트러블슈팅

### Common Issues / 자주 발생하는 문제

| Symptom / 증상 | Cause / 원인 | Solution / 해결 |
| -------------- | ------------ | --------------- |
| `PermissionError` on log write | Log directory owned by root or another user / 로그 디렉토리 소유자가 root 또는 다른 사용자 | `chmod -R u+rw ~/.revkit/logs/` or recreate the directory / 디렉토리 재생성 |
| Logs not appearing | `init_logging()` not called / `init_logging()` 미호출 | Ensure `init_logging()` is called before any command / 명령어 전에 `init_logging()` 호출 확인 |
| Disk full / 디스크 풀 | Too many large log files / 큰 로그 파일이 너무 많음 | Clean up old logs (see below) / 오래된 로그 정리 (아래 참조) |
| `cp949 codec` error on Windows | Python default encoding on Windows / Windows에서 Python 기본 인코딩 | Ensure all `open()` calls use `encoding='utf-8'` / 모든 `open()` 호출에 `encoding='utf-8'` 사용 |
| Log file locked on Windows | Another process holds the file handle / 다른 프로세스가 파일 핸들을 점유 | Stop all revkit instances, then retry / 모든 revkit 인스턴스 종료 후 재시도 |

### Viewing Logs / 로그 조회

**View latest entries / 최근 항목 보기**:

```bash
# last 10 lines of global log / 글로벌 로그 마지막 10줄
tail -10 ~/.revkit/logs/revkit.jsonl

# pretty-print with jq / jq로 보기 좋게 출력
tail -10 ~/.revkit/logs/revkit.jsonl | jq .

# follow live (real-time) / 실시간 추적
tail -f ~/.revkit/logs/revkit.jsonl | jq .
```

**Filter by level / 레벨로 필터링**:

```bash
# show only errors / 에러만 보기
cat ~/.revkit/logs/revkit.jsonl | jq 'select(.level == "ERROR")'

# show errors and warnings / 에러 + 경고 보기
cat ~/.revkit/logs/revkit.jsonl | jq 'select(.level == "ERROR" or .level == "WARNING")'
```

**Filter by engine / 엔진으로 필터링**:

```bash
# IDA engine events only / IDA 엔진 이벤트만
cat ~/.revkit/logs/revkit.jsonl | jq 'select(.logger | startswith("revkit.ida"))'
```

**Command history / 명령어 히스토리**:

```bash
# failed commands only / 실패한 명령어만
cat ~/.revkit/logs/commands.jsonl | jq 'select(.ok == false)'

# slowest commands (> 5 seconds) / 느린 명령어 (5초 초과)
cat ~/.revkit/logs/commands.jsonl | jq 'select(.ms > 5000)'

# commands for a specific instance / 특정 인스턴스 명령어
cat ~/.revkit/logs/commands.jsonl | jq 'select(.iid == "a3f2")'
```

**Trace ID correlation (P4) / Trace ID 상관 분석**:

```bash
# find trace_id in engine log / 엔진 로그에서 trace_id 찾기
cat ~/.revkit/logs/ida/engine.jsonl | jq 'select(.data.trace_id == "030f73ac93ef")'

# find same trace_id in instance log / 인스턴스 로그에서 동일 trace_id 찾기
cat ~/.revkit/logs/ida/instances/a3f2.jsonl | jq 'select(.data.trace_id == "030f73ac93ef")'
```

**Instance lifecycle events / 인스턴스 라이프사이클 이벤트**:

```bash
# all lifecycle events for an engine / 엔진의 모든 라이프사이클 이벤트
cat ~/.revkit/logs/ida/engine.jsonl | jq 'select(.data.event | startswith("instance."))'

# instance start/stop history / 인스턴스 시작/종료 기록
cat ~/.revkit/logs/ida/engine.jsonl | jq 'select(.data.event == "instance.start" or .data.event == "instance.stop")'
```

### Cleaning Up Old Logs / 오래된 로그 정리

**CLI cleanup command (recommended) / CLI 정리 명령 (권장)**:

```bash
# automatic cleanup: orphan instance logs, stale auth tokens, unused IDB/projects
# 자동 정리: 고아 인스턴스 로그, 오래된 auth 토큰, 미사용 IDB/프로젝트
revkit ida cleanup
revkit jeb cleanup

# dry-run to preview what would be deleted / 삭제 대상 미리보기
revkit ida cleanup --dry-run
```

The `cleanup` command (P7) automatically removes orphan instance logs (`.jsonl`, `.stderr`) in `logs/{engine}/instances/` for instances that are no longer active and older than the stale threshold.

`cleanup` 명령 (P7)은 `logs/{engine}/instances/`에서 더 이상 활성이 아니고 stale 임계값보다 오래된 고아 인스턴스 로그(`.jsonl`, `.stderr`)를 자동으로 삭제한다.

**Manual cleanup / 수동 정리**:

```bash
# remove all logs (nuclear option) / 모든 로그 삭제 (전체 초기화)
rm -rf ~/.revkit/logs/

# remove only instance logs / 인스턴스 로그만 삭제
rm -rf ~/.revkit/logs/ida/instances/
rm -rf ~/.revkit/logs/jeb/instances/

# remove logs older than 7 days / 7일 이상 된 로그 삭제
find ~/.revkit/logs/ -name "*.jsonl*" -mtime +7 -delete
find ~/.revkit/logs/ -name "*.stderr" -mtime +7 -delete
```

> After cleanup, directories will be recreated automatically on next use.
>
> 정리 후 디렉토리는 다음 사용 시 자동으로 재생성된다.

---
