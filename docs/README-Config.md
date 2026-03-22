# revkit — Configuration Reference

Detailed documentation for revkit configuration file format, all settings, and override mechanisms.

revkit 설정 파일 형식, 전체 설정 항목, 오버라이드 메커니즘에 대한 상세 문서.

---

## Table of Contents

- [Overview / 개요](#overview--개요)
- [Full Config Reference / 전체 설정 레퍼런스](#full-config-reference--전체-설정-레퍼런스)
  - [paths — File System Paths / 파일 시스템 경로](#paths--file-system-paths--파일-시스템-경로)
  - [analysis — Analysis Behavior / 분석 동작](#analysis--analysis-behavior--분석-동작)
  - [security — Security Settings / 보안 설정](#security--security-settings--보안-설정)
  - [server — RPC Server Settings / RPC 서버 설정](#server--rpc-server-settings--rpc-서버-설정)
  - [log — Log Rotation / 로그 로테이션](#log--log-rotation--로그-로테이션)
  - [output — RPC Output Pagination / RPC 출력 페이지네이션](#output--rpc-output-pagination--rpc-출력-페이지네이션)
  - [ida — IDA Pro Engine / IDA Pro 엔진](#ida--ida-pro-engine--ida-pro-엔진)
  - [jeb — JEB Pro Engine / JEB Pro 엔진](#jeb--jeb-pro-engine--jeb-pro-엔진)
  - [gateway — Gateway Daemon / 게이트웨이 데몬](#gateway--gateway-daemon--게이트웨이-데몬)
- [Environment Variable Expansion / 환경 변수 확장](#environment-variable-expansion--환경-변수-확장)
- [Local Config Override / 로컬 설정 오버라이드](#local-config-override--로컬-설정-오버라이드)
- [Minimal Config Examples / 최소 설정 예시](#minimal-config-examples--최소-설정-예시)

---

## Overview / 개요

revkit reads its configuration from a JSON file at startup. The configuration controls file paths, engine settings, analysis parameters, security, and gateway behavior.

revkit은 시작 시 JSON 설정 파일을 읽는다. 설정은 파일 경로, 엔진 설정, 분석 파라미터, 보안, 게이트웨이 동작을 제어한다.

| Property / 속성 | Value / 값 |
| --- | --- |
| Default path / 기본 경로 | `~/.revkit/config.json` |
| Format / 형식 | JSON (with `~` and env var expansion) |
| Local override / 로컬 오버라이드 | `config.local.json` in project directory |
| Module / 모듈 | `revkit/tools/core/config.py` (`load_config(path)` accepts `None`, falls back to `~/.revkit/config.json`) |
| CLI flag / CLI 플래그 | `--config <path>` on any command |

### Loading Order / 로딩 순서

```text
1. ~/.revkit/config.json          ← global defaults / 전역 기본값
2. ./config.local.json            ← project override (deep merge) / 프로젝트 오버라이드 (깊은 병합)
3. --config <path>                ← CLI override (replaces global) / CLI 오버라이드 (전역 교체)
```

---

## Full Config Reference / 전체 설정 레퍼런스

### `paths` — File System Paths / 파일 시스템 경로

Controls where revkit stores databases, logs, and output files. All paths support `~` expansion.

revkit이 데이터베이스, 로그, 출력 파일을 저장하는 위치를 제어한다. 모든 경로는 `~` 확장을 지원한다.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `idb_dir` | `string` | `~/.revkit/ida/idb` | IDA database (`.i64`) storage directory. Used by `start`, `init`, `cleanup`. / IDA 데이터베이스 (`.i64`) 저장 디렉토리. `start`, `init`, `cleanup`에서 사용. |
| `log_dir` | `string` | `~/.revkit/logs` | Base log directory. Engine-specific subdirectories (`ida/instances/`, `jeb/instances/`) are created automatically. / 기본 로그 디렉토리. 엔진별 하위 디렉토리 (`ida/instances/`, `jeb/instances/`)가 자동 생성됨. |
| `project_dir` | `string` | `~/.revkit/jeb/projects` | JEB project (`.jdb2`) storage directory. Used by JEB `start`, `init`. / JEB 프로젝트 (`.jdb2`) 저장 디렉토리. JEB `start`, `init`에서 사용. |
| `output_dir` | `string` | `~/.revkit/output` | Default directory for file output (`-o` flag, `decompile-all`, `report`). / 파일 출력 기본 디렉토리 (`-o` 플래그, `decompile-all`, `report`). |
| `scripts_dir` | `string` | `~/.revkit/scripts` | Exec script base directory. Short paths in `exec` resolve to `{scripts_dir}/{engine}/`. / exec 스크립트 기본 디렉토리. `exec`에서 단축 경로가 `{scripts_dir}/{engine}/`으로 해석됨. |

### `analysis` — Analysis Behavior / 분석 동작

Controls instance lifecycle, polling, and timeout behavior for both IDA and JEB engines.

IDA와 JEB 엔진 모두에 대한 인스턴스 수명 주기, 폴링, 타임아웃 동작을 제어한다.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `max_instances` | `int` | `3` | Maximum number of concurrent engine instances. `start` refuses if limit reached. / 최대 동시 엔진 인스턴스 수. 한도 도달 시 `start` 거부. |
| `wait_poll_interval` | `float` | `1.0` | Seconds between polls when `wait` checks if analysis is done. / `wait` 명령이 분석 완료를 확인할 때 폴 간격 (초). |
| `wait_timeout` | `int` | `120` | Maximum seconds `wait` will block before timeout. 0 = infinite. / `wait`이 타임아웃하기까지 최대 대기 시간 (초). 0 = 무한. |
| `stale_threshold` | `int` | `86400` | Seconds after which a non-responsive instance is considered stale. Used by `cleanup`. / 응답 없는 인스턴스를 오래된 것으로 간주하는 시간 (초). `cleanup`에서 사용. |
| `open_db_timeout` | `int` | `300` | Maximum seconds to wait for initial database open/analysis. Large binaries need more. / 초기 데이터베이스 열기/분석 최대 대기 시간 (초). 대용량 바이너리에는 더 큰 값 필요. |
| `heartbeat_interval` | `int` | `30` | Seconds between server heartbeat pings. Used to detect stale instances. / 서버 하트비트 핑 간격 (초). 오래된 인스턴스 감지에 사용. |
| `auto_save` | `bool` | `true` | Automatically save database after modifications (rename, set-type, etc.). / 수정 후 자동으로 데이터베이스 저장 (rename, set-type 등). |
| `stop_timeout` | `int` | `30` | Maximum seconds to wait for process exit during `stop`/`restart`. The `save_db` RPC also uses this as its timeout. Polling-based (1s intervals). / `stop`/`restart` 시 프로세스 종료 최대 대기 시간 (초). `save_db` RPC 타임아웃으로도 사용. 폴링 기반 (1초 간격). |

### `security` — Security Settings / 보안 설정

Controls authentication and dangerous operation permissions.

인증 및 위험한 작업 권한을 제어한다.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `auth_token_file` | `string` | `~/.revkit/auth_tokens.json` | Path to the token file for gateway API authentication. / 게이트웨이 API 인증용 토큰 파일 경로. |
| `exec_enabled` | `bool` | `false` | Global default for `exec` / `py-eval` commands. Can be overridden per-engine via `ida.security.exec_enabled` / `jeb.security.exec_enabled`. / `exec` / `py-eval` 명령어의 전역 기본값. `ida.security.exec_enabled` / `jeb.security.exec_enabled`로 엔진별 오버라이드 가능. |

> **Per-engine override / 엔진별 오버라이드**: The global `security.exec_enabled` serves as the default. Each engine can override it independently via `ida.security.exec_enabled` and `jeb.security.exec_enabled`. At server startup, the engine-specific security section is merged into the global security settings.
>
> 전역 `security.exec_enabled`는 기본값 역할을 한다. 각 엔진은 `ida.security.exec_enabled`와 `jeb.security.exec_enabled`를 통해 독립적으로 오버라이드할 수 있다. 서버 시작 시 엔진별 보안 섹션이 전역 보안 설정에 병합된다.

> **WARNING / 경고**: Setting `exec_enabled: true` allows arbitrary code execution inside IDA/JEB processes. Only enable on trusted, isolated machines. Never enable on shared or production servers.
>
> `exec_enabled: true`는 IDA/JEB 프로세스 내에서 임의 코드 실행을 허용한다. 신뢰할 수 있는 격리된 머신에서만 활성화할 것. 공유 서버나 프로덕션 서버에서는 절대 활성화하지 말 것.

### `server` — RPC Server Settings / RPC 서버 설정

Controls the JSON-RPC server that each engine instance runs.

각 엔진 인스턴스가 실행하는 JSON-RPC 서버를 제어한다.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `host` | `string` | `127.0.0.1` | Bind address for the RPC server. `127.0.0.1` = local only, `0.0.0.0` = all interfaces. / RPC 서버 바인드 주소. `127.0.0.1` = 로컬만, `0.0.0.0` = 모든 인터페이스. |

> **Note / 참고**: The port is assigned dynamically and written to the registry. Only the host needs to be configured.
>
> 포트는 동적으로 할당되어 레지스트리에 기록된다. 호스트만 설정하면 된다.

### `log` — Log Rotation / 로그 로테이션

Controls log file rotation for instance logs.

인스턴스 로그의 로그 파일 로테이션을 제어한다.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `max_size_mb` | `int` | `10` | Maximum size of a single log file before rotation (MB). / 로테이션 전 단일 로그 파일 최대 크기 (MB). |
| `backup_count` | `int` | `3` | Number of rotated log files to keep. / 보관할 로테이션된 로그 파일 수. |
| `stderr_capture` | `bool` | `true` | Capture engine process stderr to `{iid}.stderr` files. When enabled, stderr output from IDA/JEB server processes is redirected to per-instance files under `logs/{engine}/instances/`. / 엔진 프로세스 stderr를 `{iid}.stderr` 파일로 캡처. 활성화 시 IDA/JEB 서버 프로세스의 stderr 출력이 `logs/{engine}/instances/` 아래의 인스턴스별 파일로 리디렉션됨. |

### `output` — RPC Output Pagination / RPC 출력 페이지네이션

Controls default limits for commands that return lists (functions, strings, imports, etc.).

리스트를 반환하는 명령어 (함수, 문자열, import 등)의 기본 제한을 제어한다.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `default_count` | `int` | `50` | Default number of items returned when `-n` is not specified. / `-n` 미지정 시 반환되는 기본 항목 수. |
| `max_count` | `int` | `500` | Hard upper limit. Requests exceeding this are capped. / 절대 상한. 이를 초과하는 요청은 잘린다. |
| `encoding` | `string` | `utf-8` | Output file encoding. Important on Windows where default is `cp949`. / 출력 파일 인코딩. 기본값이 `cp949`인 Windows에서 중요. |

### `ida` — IDA Pro Engine / IDA Pro 엔진

IDA Pro specific settings.

IDA Pro 전용 설정.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `install_dir` | `string` | *(required)* | Path to IDA Pro installation directory containing `idat64`. / `idat64`를 포함하는 IDA Pro 설치 디렉토리 경로. |
| `registry` | `string` | `~/.revkit/ida/registry.json` | IDA instance registry path. Used by both CLI and IDA server. / IDA 인스턴스 레지스트리 경로. CLI와 IDA 서버 모두 사용. |

```jsonc
{
  "ida": {
    "install_dir": "C:/Program Files/IDA Professional 9.3",  // Linux: "/opt/ida"
    "registry": "~/.revkit/ida/registry.json",
    "security": {
      "exec_enabled": true
    }
  }
}
```

#### `ida.security` — Per-Engine Security Override / 엔진별 보안 오버라이드

Overrides the global `security` settings for the IDA engine. At server startup, values here are merged on top of the global `security` section.

IDA 엔진에 대해 전역 `security` 설정을 오버라이드한다. 서버 시작 시 여기의 값이 전역 `security` 섹션 위에 병합된다.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `exec_enabled` | `bool` | *(inherits global)* | Override `security.exec_enabled` for IDA. If omitted, the global value is used. / IDA용 `security.exec_enabled` 오버라이드. 생략 시 전역 값 사용. |

> On Linux/macOS, typically `/opt/ida` or `/Applications/IDA Pro.app/Contents/MacOS`.
>
> Linux/macOS에서는 보통 `/opt/ida` 또는 `/Applications/IDA Pro.app/Contents/MacOS`.

### `jeb` — JEB Pro Engine / JEB Pro 엔진

JEB Pro specific settings, including JVM heap auto-sizing.

JVM 힙 자동 조절을 포함한 JEB Pro 전용 설정.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `install_dir` | `string` | *(required)* | Path to JEB installation directory. / JEB 설치 디렉토리 경로. |
| `registry` | `string` | `~/.revkit/jeb/registry.json` | JEB instance registry path. Used by both CLI and JEB server. / JEB 인스턴스 레지스트리 경로. CLI와 JEB 서버 모두 사용. |
| `spawn_method` | `string` | `"wrapper"` | How to launch JEB: `"wrapper"` (recommended, uses bundled scripts) or `"bat"` (Windows `.bat` launcher). / JEB 실행 방식: `"wrapper"` (권장, 번들 스크립트 사용) 또는 `"bat"` (Windows `.bat` 런처). |
| `java_home` | `string` | *(system default)* | **wrapper mode only.** Override JAVA_HOME for JEB process. If unset, uses system Java. Ignored in `bat` mode (bat uses its own Java lookup). / **wrapper 모드 전용.** JEB 프로세스용 JAVA_HOME 오버라이드. 미설정 시 시스템 Java 사용. `bat` 모드에서는 무시됨 (bat이 자체적으로 Java를 탐색). |
| `jvm_opts` | `string[]` | `[]` | **wrapper mode only.** Additional JVM arguments passed to JEB (e.g., `["-XX:+UseG1GC", "-Dfile.encoding=UTF-8"]`). Ignored in `bat` mode (bat reads `jvmopt.txt` instead). / **wrapper 모드 전용.** JEB에 전달되는 추가 JVM 인자 (예: `["-XX:+UseG1GC", "-Dfile.encoding=UTF-8"]`). `bat` 모드에서는 무시됨 (bat은 `jvmopt.txt`를 읽음). |

#### `jeb.heap` — JVM Heap Auto-Sizing / JVM 힙 자동 조절

When `auto` is enabled, revkit automatically selects heap size based on the input file size.

`auto` 활성화 시, revkit이 입력 파일 크기에 따라 자동으로 힙 크기를 선택한다.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `auto` | `bool` | `true` | Enable automatic heap sizing based on input file size. / 입력 파일 크기 기반 자동 힙 조절 활성화. |
| `default` | `string` | `"4G"` | Default heap size when `auto` is disabled or file size doesn't match any rule. / `auto` 비활성화 시 또는 규칙에 매칭되지 않을 때의 기본 힙 크기. |
| `max` | `string` | `"16G"` | Absolute maximum heap size (safety cap). / 절대 최대 힙 크기 (안전 상한). |
| `rules` | `array` | *(see below)* | Size-based rules, evaluated in order. First match wins. / 크기 기반 규칙, 순서대로 평가. 첫 매칭 적용. |

**Default rules / 기본 규칙:**

| `max_mb` (file size) | `xmx` (heap) | Example target / 예시 대상 |
| --- | --- | --- |
| `50` | `2G` | Small DEX, test APKs / 소규모 DEX, 테스트 APK |
| `200` | `4G` | Typical APKs / 일반 APK |
| `500` | `8G` | Large APKs, multi-DEX / 대용량 APK, 멀티 DEX |
| *(above 500 MB)* | `16G` (max) | Very large apps / 초대형 앱 |

```jsonc
{
  "jeb": {
    "install_dir": "C:/WorkSpace/bin/JEB-5.38",              // Linux: "/opt/jeb"
    "registry": "~/.revkit/jeb/registry.json",
    "spawn_method": "wrapper",
    "java_home": "C:/Program Files/Java/jdk-21.0.10",        // Linux: "/usr/lib/jvm/java-21"
    "jvm_opts": ["-XX:+UseG1GC", "-Dfile.encoding=UTF-8"],
    "security": {
      "exec_enabled": false
    },
    "heap": {
      "auto": true,
      "default": "4G",
      "max": "16G",
      "rules": [
        {"max_mb": 50, "xmx": "2G"},
        {"max_mb": 200, "xmx": "4G"},
        {"max_mb": 500, "xmx": "8G"}
      ]
    }
  }
}
```

> **Note / 참고**: `java_home` and `jvm_opts` are only used in `wrapper` spawn mode. In `bat` mode, JEB's own launcher script locates Java and reads JVM options from `jvmopt.txt` in the JEB install directory.
>
> `java_home`과 `jvm_opts`는 `wrapper` 실행 모드에서만 사용된다. `bat` 모드에서는 JEB 자체 런처 스크립트가 Java를 탐색하고 JEB 설치 디렉토리의 `jvmopt.txt`에서 JVM 옵션을 읽는다.

#### `jeb.security` — Per-Engine Security Override / 엔진별 보안 오버라이드

Overrides the global `security` settings for the JEB engine. At server startup, values here are merged on top of the global `security` section.

JEB 엔진에 대해 전역 `security` 설정을 오버라이드한다. 서버 시작 시 여기의 값이 전역 `security` 섹션 위에 병합된다.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `exec_enabled` | `bool` | *(inherits global)* | Override `security.exec_enabled` for JEB. If omitted, the global value is used. / JEB용 `security.exec_enabled` 오버라이드. 생략 시 전역 값 사용. |

### `gateway` — Gateway Daemon / 게이트웨이 데몬

Controls the HTTP API gateway that provides remote access to revkit engines.

revkit 엔진에 대한 원격 접근을 제공하는 HTTP API 게이트웨이를 제어한다.

| Key | Type | Default | Description / 설명 |
| --- | --- | --- | --- |
| `url` | `string` | `""` | Remote gateway URL for client mode. When set (e.g. `http://server:8080`), all CLI commands are forwarded to this gateway instead of running locally. Empty string = local mode. CLI `--remote` flag overrides this. / 클라이언트 모드용 원격 게이트웨이 URL. 설정하면 (예: `http://server:8080`) 모든 CLI 명령이 로컬 실행 대신 이 게이트웨이로 전달됨. 빈 문자열 = 로컬 모드. CLI `--remote` 플래그가 이 설정을 오버라이드함. |
| `host` | `string` | `0.0.0.0` | Bind address for the gateway HTTP server (server-side). / 게이트웨이 HTTP 서버 바인드 주소 (서버 측). |
| `port` | `int` | `8080` | Listen port (server-side). / 리슨 포트 (서버 측). |
| `max_upload_size_mb` | `int` | `500` | Maximum upload file size in MB. Rejects larger files with HTTP 413. / 최대 업로드 파일 크기 (MB). 초과 시 HTTP 413으로 거부. |
| `upload_dir` | `string` | `~/.revkit/uploads` | Directory for uploaded binaries/APKs. / 업로드된 바이너리/APK 저장 디렉토리. |
| `api_key` | `string\|null` | `null` | Static API key for simple auth. `null` = no API key required. / 간단한 인증용 정적 API 키. `null` = API 키 불필요. |
| `allowed_ips` | `string[]` | `[]` | IP allowlist. Empty = all IPs allowed. Supports CIDR (`10.0.0.0/8`). / IP 허용 목록. 비어있으면 모든 IP 허용. CIDR 지원 (`10.0.0.0/8`). |
| `trusted_proxies` | `string[]` | `[]` | Proxy IPs to trust for `X-Forwarded-For` header parsing. / `X-Forwarded-For` 헤더 파싱 시 신뢰할 프록시 IP. |
| `request_timeout` | `int` | `60` | Timeout in seconds for individual RPC requests. / 개별 RPC 요청 타임아웃 (초). |
| `batch_timeout` | `int` | `300` | Timeout in seconds for batch operations (`decompile-all`, `export`). / 배치 작업 타임아웃 (초) (`decompile-all`, `export`). |
| `log_rpc_params` | `bool` | `false` | Log full RPC parameters in audit log. May contain sensitive data. / 감사 로그에 전체 RPC 파라미터 기록. 민감 데이터 포함 가능. |
| `audit_path` | `string` | `~/.revkit/logs/gateway/audit.jsonl` | Path to JSONL audit log file. / JSONL 감사 로그 파일 경로. |
| `audit_max_size_mb` | `int` | `100` | Maximum audit log file size before rotation (MB). / 로테이션 전 감사 로그 최대 크기 (MB). |

> **Security note / 보안 참고**: When exposing the gateway to a network, always configure `api_key` and `allowed_ips`. Use `trusted_proxies` only when behind a known reverse proxy.
>
> 게이트웨이를 네트워크에 노출할 때는 반드시 `api_key`와 `allowed_ips`를 설정할 것. `trusted_proxies`는 알려진 리버스 프록시 뒤에 있을 때만 사용할 것.

#### Gateway 구조 / Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Client PC (노트북, 다른 서버 등)                              │
│                                                             │
│  config.json:                                               │
│    gateway.url = "http://192.168.1.100:8080"  ← 여기만 설정  │
│                                                             │
│  $ revkit ida decompile 0x401000                            │
│       │                                                     │
│       └──── HTTP ────►                                      │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  Server PC (IDA/JEB 설치된 분석 서버)                         │
│                                                             │
│  config.json:                                               │
│    gateway.host = "0.0.0.0"    ← 바인드 주소                 │
│    gateway.port = 8080         ← 리슨 포트                   │
│    gateway.url  = ""           ← 비워둠 (서버는 로컬 모드)     │
│                                                             │
│  $ python -m revkit.tools.gateway.daemon   ← 데몬 실행       │
│       │                                                     │
│       ├── IDA Pro 9.3 (headless)                            │
│       └── JEB Pro 5.38 (headless)                           │
└─────────────────────────────────────────────────────────────┘
```

#### 설정 요약 / Which Keys to Set

| 키 | 서버 PC | 클라이언트 PC | 설명 |
|----|---------|-------------|------|
| `gateway.url` | `""` (비움) | `"http://서버IP:포트"` | 클라이언트만 설정. 설정하면 모든 CLI 명령이 원격으로 전달됨 |
| `gateway.host` | `"0.0.0.0"` | 무관 (사용 안 됨) | 서버만 설정. 게이트웨이 데몬 바인드 주소 |
| `gateway.port` | `8080` | 무관 (사용 안 됨) | 서버만 설정. 게이트웨이 데몬 리슨 포트 |
| `gateway.api_key` | `"my-secret-key"` | `"my-secret-key"` | 양쪽 동일하게 설정. `null`이면 인증 없음 |
| `ida.*` / `jeb.*` | 설치 경로 필요 | 없어도 됨 | 엔진은 서버에만 설치 |

#### Server PC 설정 예시 / Server Config

```json
{
    "gateway": {
        "url": "",
        "host": "0.0.0.0",
        "port": 8080,
        "api_key": "my-secret-key",
        "allowed_ips": ["192.168.1.0/24"],
        "max_upload_size_mb": 500
    },
    "ida": {
        "install_dir": "C:/Program Files/IDA Professional 9.3"
    },
    "jeb": {
        "install_dir": "C:/WorkSpace/bin/JEB-5.38"
    }
}
```

서버 시작:
```bash
python -m revkit.tools.gateway.daemon
# [+] Gateway listening on 0.0.0.0:8080
```

#### Client PC 설정 예시 / Client Config

```json
{
    "gateway": {
        "url": "http://192.168.1.100:8080",
        "api_key": "my-secret-key"
    }
}
```

클라이언트에서는 IDA/JEB 설치 불필요. `gateway.url`만 설정하면 끝:
```bash
# 모든 명령이 자동으로 원격 서버로 전달
revkit ida start upload.exe           # 바이너리 업로드 + 원격 start
revkit ida wait                       # 원격 인스턴스 ready 대기
revkit ida decompile 0x401000         # 원격 디컴파일
revkit jeb decompile "Lcom/app/Main;" # JEB도 동일

# 1회성으로 다른 서버 사용
revkit --remote http://10.0.0.5:9090 ida list
```

#### 동작 흐름 / How It Works

```
1. CLI 시작 → config.json 로드
2. --remote 인자 있으면 → 그 URL 사용
3. --remote 없으면 → config gateway.url 확인
4. gateway.url이 http로 시작하면 → 원격 모드
5. gateway.url이 비어있거나 없으면 → 로컬 모드 (기존과 동일)
```

> **우선순위**: `--remote` CLI 플래그 > config `gateway.url` > 로컬 모드

---

## Environment Variable Expansion / 환경 변수 확장

All string values in the config support environment variable expansion.

설정의 모든 문자열 값은 환경 변수 확장을 지원한다.

| Syntax / 문법 | Expands to / 확장 결과 | Platform / 플랫폼 |
| --- | --- | --- |
| `~` | User home directory / 사용자 홈 디렉토리 | All |
| `$HOME` | User home directory / 사용자 홈 디렉토리 | Linux, macOS |
| `$USERPROFILE` | User home directory / 사용자 홈 디렉토리 | Windows |
| `${VAR_NAME}` | Value of environment variable / 환경 변수 값 | All |

```json
{
  "paths": {
    "output_dir": "~/revkit-output",
    "log_dir": "$HOME/.revkit/logs"
  },
  "ida": {
    "install_dir": "${IDA_DIR}"
  }
}
```

> **Cross-platform / 크로스 플랫폼**: Use `~` for maximum portability. It expands to `$HOME` on Linux/macOS and `%USERPROFILE%` on Windows.
>
> 최대 이식성을 위해 `~`를 사용할 것. Linux/macOS에서는 `$HOME`, Windows에서는 `%USERPROFILE%`로 확장된다.

---

## Local Config Override / 로컬 설정 오버라이드

Place a `config.local.json` in your project (working) directory to override specific settings without modifying the global config.

전역 설정을 수정하지 않고 특정 설정만 오버라이드하려면 프로젝트 (작업) 디렉토리에 `config.local.json`을 배치한다.

### How it works / 동작 방식

1. revkit loads `~/.revkit/config.json` (global defaults).
2. If `config.local.json` exists in the current working directory, it is **deep-merged** on top of the global config.
3. Deep merge means nested objects are merged recursively, not replaced wholesale.

1. revkit이 `~/.revkit/config.json` (전역 기본값)을 로드한다.
2. 현재 작업 디렉토리에 `config.local.json`이 존재하면, 전역 설정 위에 **깊은 병합**된다.
3. 깊은 병합은 중첩된 객체가 통째로 교체되지 않고 재귀적으로 병합됨을 의미한다.

### Example / 예시

`~/.revkit/config.json` (global / 전역):
```jsonc
{
  "analysis": {"max_instances": 3, "wait_timeout": 120},
  "ida": {"install_dir": "C:/Program Files/IDA Professional 9.3"}  // Linux: "/opt/ida"
}
```

`./config.local.json` (project override / 프로젝트 오버라이드):
```json
{
  "analysis": {"max_instances": 5},
  "output": {"default_count": 100}
}
```

**Effective config / 실제 적용 결과:**
```jsonc
{
  "analysis": {"max_instances": 5, "wait_timeout": 120},
  "ida": {"install_dir": "C:/Program Files/IDA Professional 9.3"},  // Linux: "/opt/ida"
  "output": {"default_count": 100}
}
```

> `analysis.wait_timeout` is preserved from global config because deep merge only overrides keys present in the local file.
>
> `analysis.wait_timeout`은 깊은 병합이 로컬 파일에 있는 키만 오버라이드하므로 전역 설정에서 보존된다.

---

## Minimal Config Examples / 최소 설정 예시

### IDA Only / IDA 전용

```jsonc
{
  "ida": {
    "install_dir": "/opt/ida"              // Win: "C:/Program Files/IDA Professional 9.3"
  }
}
```

### JEB Only / JEB 전용

```jsonc
{
  "jeb": {
    "install_dir": "/opt/jeb"              // Win: "C:/WorkSpace/bin/JEB-5.38"
  }
}
```

### Full Local Setup / 전체 로컬 설정

> Paths below use Windows examples. Linux: `"/opt/ida"`, `"/opt/jeb"`.
>
> 아래 경로는 Windows 예시. Linux: `"/opt/ida"`, `"/opt/jeb"`.

```json
{
  "paths": {
    "log_dir": "~/.revkit/logs"
  },
  "ida": {
    "install_dir": "C:/Program Files/IDA Professional 9.3",
    "registry": "~/.revkit/ida/registry.json",
    "security": { "exec_enabled": true }
  },
  "jeb": {
    "install_dir": "C:/WorkSpace/bin/JEB-5.38",
    "registry": "~/.revkit/jeb/registry.json",
    "spawn_method": "wrapper",
    "security": { "exec_enabled": false },
    "heap": {
      "auto": true,
      "default": "4G",
      "max": "16G",
      "rules": [
        {"max_mb": 50, "xmx": "2G"},
        {"max_mb": 200, "xmx": "4G"},
        {"max_mb": 500, "xmx": "8G"}
      ]
    }
  },
  "analysis": {
    "max_instances": 3,
    "wait_timeout": 120,
    "stop_timeout": 30
  },
  "security": {
    "exec_enabled": false
  },
  "log": {
    "max_size_mb": 10,
    "backup_count": 3,
    "stderr_capture": true
  }
}
```

### Remote Gateway Setup / 원격 게이트웨이 설정

For exposing revkit as a network service (e.g., for MCP or team access):

revkit을 네트워크 서비스로 노출할 때 (예: MCP 또는 팀 접근):

```jsonc
{
  "ida": {
    "install_dir": "/opt/ida"              // Win: "C:/Program Files/IDA Professional 9.3"
  },
  "jeb": {
    "install_dir": "/opt/jeb"              // Win: "C:/WorkSpace/bin/JEB-5.38"
  },
  "server": {
    "host": "0.0.0.0"
  },
  "gateway": {
    "host": "0.0.0.0",
    "port": 8080,
    "api_key": "your-secret-api-key-here",
    "allowed_ips": ["10.0.0.0/8", "192.168.1.0/24"],
    "trusted_proxies": ["10.0.0.1"],
    "max_upload_size_mb": 500,
    "request_timeout": 120,
    "batch_timeout": 600
  },
  "security": {
    "exec_enabled": false
  },
  "analysis": {
    "max_instances": 5
  }
}
```

> **Tip / 팁**: For remote setups, increase `analysis.max_instances` and `gateway.batch_timeout` based on expected concurrent users and analysis complexity.
>
> 원격 설정에서는 예상 동시 사용자 수와 분석 복잡도에 따라 `analysis.max_instances`와 `gateway.batch_timeout`을 늘릴 것.
