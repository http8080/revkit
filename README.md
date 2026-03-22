# revkit

**Unified headless binary analysis CLI framework for IDA Pro + JEB.**

IDA Pro + JEB 통합 headless 바이너리 분석 CLI 프레임워크.

Supports local and remote modes with a Gateway for distributed analysis environments.

로컬/원격 모드를 지원하며, Gateway를 통한 분산 분석 환경을 제공한다.

## Documentation / 문서

| Document | Description / 설명 |
| -------- | ------------------ |
| **[README.md](README.md)** (this file) | Installation, configuration, architecture / 설치, 설정, 아키텍처 |
| **[docs/README-IDA.md](docs/README-IDA.md)** | IDA Pro engine — 62 commands, RPC methods, usage / IDA 명령어 상세 |
| **[docs/README-JEB.md](docs/README-JEB.md)** | JEB Pro engine — 72 commands, RPC methods, usage / JEB 명령어 상세 |
| **[docs/README-Config.md](docs/README-Config.md)** | Configuration reference — all config.json keys / 설정 레퍼런스 |
| **[docs/README-Logging.md](docs/README-Logging.md)** | Logging system — JSONL format, directory structure / 로깅 시스템 |
| **[docs/README-RPC.md](docs/README-RPC.md)** | RPC protocol reference — 59 IDA + 57 JEB methods, auth, errors / RPC 프로토콜 레퍼런스 |
| **[docs/tutorials/](docs/tutorials/)** | 14 hands-on tutorials — install, IDA, JEB, scripts, dev, gateway, AI / 14개 실습 튜토리얼 |
| **[docs/README-Setup.md](docs/README-Setup.md)** | Installation & setup guide / 설치 및 환경 설정 가이드 |

---

## Architecture / 아키텍처

```text
[Local Mode / 로컬 모드]
  revkit CLI ──── JSON-RPC ──── Engine Server (IDA/JEB)

[Remote Mode / 원격 모드]
  revkit CLI ──── HTTPS ──── Gateway Daemon ──── Engine Server (IDA/JEB)
```

---

## Quick Start / 빠른 시작

### Install / 설치

```bash
cd revkit && pip install -e .

# With optional dependencies / 선택적 의존성 포함
pip install -e ".[full]"   # psutil (process management / 프로세스 관리)
pip install -e ".[dev]"    # pytest (testing / 테스트)
```

### Basic Usage / 기본 사용법

```bash
# Start IDA analysis server / IDA 분석 서버 시작
revkit ida start sample.exe

# Start JEB analysis server / JEB 분석 서버 시작
revkit jeb start sample.apk

# Auto-detect engine (magic bytes + extension)
# 엔진 자동 감지 (magic bytes + 확장자)
revkit start sample.exe    # → IDA
revkit start sample.apk    # → JEB

# List instances / 인스턴스 목록
revkit ida list
revkit jeb list

# Stop instance / 인스턴스 중지
revkit ida stop -i a3f2
```

### Auto-detect Engine / 엔진 자동 감지

| Magic Bytes | Extension / 확장자 | Engine |
| ----------- | ----------------- | ------ |
| `MZ` | `.exe`, `.dll` | IDA |
| `\x7fELF` | `.so`, `.elf`, `.bin` | IDA |
| `\xFE\xED\xFA` | `.dylib` | IDA |
| `PK\x03\x04` | `.apk` | JEB |
| `dex\n` | `.dex` | JEB |
| - | `.jar` | JEB |

---

## Requirements / 요구사항

- **Python 3.12+**
- **IDA Pro 9.3+** (idalib) and/or **JEB Pro** — at least one required / 최소 하나 필요
- `psutil` — recommended; required on Windows for correct process detection (`registry.py` uses `psutil.pid_exists()`; falls back to `os.kill` on Unix if absent) / Windows에서 프로세스 감지에 필요 (없으면 Unix에서 os.kill fallback)

### IDA Pro Setup / IDA Pro 설정

IDA Pro cannot be installed via pip and requires a separate license.

IDA Pro는 pip로 설치할 수 없으며, 별도 라이선스가 필요하다.

```bash
# 1. After installing IDA Pro, locate the idalib Python binding path
#    IDA Pro 설치 후 idalib Python binding 경로 확인
#    e.g. /opt/ida/idalib/python, C:\IDA\idalib\python

# 2. Set the IDA install path in config.json
#    config.json에 IDA 설치 경로 지정
cat ~/.revkit/config.json
{
    "ida": {
        "install_dir": "/opt/ida"
    }
}

# 3. Verify idalib is importable / import 가능 여부 확인
python -c "import ida_loader; print('OK')"

# 4. Verify via revkit / revkit으로 확인
revkit ida check
```

> idalib is the headless API provided since IDA Pro 9.3+, including modules like `ida_loader` and `ida_hexrays`.
> IDA engine commands only work on machines with IDA installed. In remote mode, requests are forwarded to an IDA-equipped server via the Gateway.
>
> idalib은 IDA Pro 9.3+에서 제공하는 headless API이며, `ida_loader`, `ida_hexrays` 등의 모듈을 포함한다.
> IDA가 설치된 머신에서만 IDA 엔진 명령어가 동작하며, 원격 모드에서는 Gateway를 통해 IDA 서버로 요청을 전달한다.

For detailed IDA commands, see **[docs/README-IDA.md](docs/README-IDA.md)**.

### JEB Pro Setup / JEB Pro 설정

JEB Pro also requires a separate license. / JEB Pro도 별도 라이선스가 필요하다.

```bash
# 1. Set JEB install path in config.json
#    JEB Pro 설치 경로를 config.json에 지정
cat ~/.revkit/config.json
{
    "jeb": {
        "install_dir": "/opt/jeb",
        "spawn_method": "wrapper",
        "java_home": "/usr/lib/jvm/java-17",
        "heap": {
            "auto": true,
            "default": "4G",
            "max": "16G"
        }
    }
}

# 2. Verify JEB CLI / JEB CLI 동작 확인
/opt/jeb/jeb_wincon.bat --version   # Windows
/opt/jeb/jeb --version              # Linux
/opt/jeb/jeb_macos.sh --version     # macOS

# 3. Verify via revkit / revkit으로 확인
revkit jeb check
```

> JEB server runs on Jython 2.7 runtime and requires Java 17+.
>
> JEB 서버는 Jython 2.7 런타임 위에서 동작하며, Java 17+이 필요하다.

For detailed JEB commands, see **[docs/README-JEB.md](docs/README-JEB.md)**.

---

## CLI Options / CLI 옵션

| Option | Description / 설명 |
| ------ | ----------------- |
| `--config PATH` | Config file path (default: `~/.revkit/config.json`) / 설정 파일 경로 |
| `--json` | JSON envelope output / JSON envelope 출력 |
| `--out FILE` | Save result to file / 결과를 파일로 저장 |
| `--remote URL` | Remote mode via Gateway / Gateway 경유 원격 모드 |
| `-q / --quiet` | Suppress output / 출력 억제 |
| `-v / --verbose` | Verbose logging / 상세 로깅 |
| `-i ID` | Specify instance ID / 인스턴스 ID 지정 |
| `-b HINT` | Binary name hint / 바이너리 이름 힌트 |

---

## Commands Overview / 명령어 개요

### Tier 1 — Common / 공통 (5 commands)

Shared across all engines. / 전체 엔진 공통.

| Command | Description / 설명 |
| ------- | ----------------- |
| `start <binary>` | Start analysis server / 분석 서버 시작 |
| `list` | List active instances / 활성 인스턴스 목록 |
| `stop` | Stop instance / 인스턴스 중지 |
| `status` | Query instance status / 인스턴스 상태 조회 |
| `wait` | Wait for instance ready / 인스턴스 ready 대기 |

### IDA Commands (62)

Analysis, modification, types, advanced, diff, report, batch, utility.

See **[docs/README-IDA.md](docs/README-IDA.md)** for full command reference.

| Category | Example Commands |
| -------- | --------------- |
| Analysis / 분석 | `decompile`, `disasm`, `segments`, `func-info`, `find-func`, `bytes`, `find-pattern` |
| Modification / 수정 | `rename`, `set-type`, `comment`, `patch`, `auto-rename`, `rename-batch` |
| Types / 타입 | `structs`, `enums`, `type-info`, `vtables`, `sigs` |
| Advanced / 고급 | `callgraph`, `cross-refs`, `search-code`, `strings-xrefs`, `basic-blocks`, `stack-frame` |
| Diff / 비교 | `diff`, `compare`, `code-diff` |
| Report / 보고서 | `report`, `annotations`, `snapshot`, `bookmark`, `profile`, `export-script` |
| Batch / 배치 | `batch` (directory analysis) |
| Utility / 유틸리티 | `shell`, `update`, `completions` |

### JEB Commands (72)

Analysis, modification, recon, search, xrefs, security, tooling, report, batch, config, utility.

See **[docs/README-JEB.md](docs/README-JEB.md)** for full command reference.

| Category | Example Commands |
| -------- | --------------- |
| Analysis / 분석 | `decompile`, `method`, `smali`, `classes`, `methods-of-class`, `fields-of-class`, `strings`, `native-methods` |
| Modification / 수정 | `rename`, `rename-class`, `rename-method`, `rename-field`, `rename-batch`, `auto-rename`, `set-comment`, `undo` |
| Recon / 정찰 | `summary`, `permissions`, `components`, `info`, `manifest`, `main-activity`, `resources` |
| Search / 검색 | `search-classes`, `search-methods`, `search-code`, `strings-xrefs` |
| Xrefs | `xrefs`, `callers`, `callees`, `callgraph`, `cross-refs` |
| Security / 보안 | `entry-points`, `security-scan` |
| Tooling / 도구 | `merge` (split APK → `{pkg}_merged.apk`), `gen-runner`, `patch`, `unpatch` |
| Report / 보고서 | `report`, `annotations`, `snapshot` |
| Batch / 배치 | `batch` (directory analysis) |
| Config / 설정 | `config-show`, `config-set` |
| Utility / 유틸리티 | `exec`, `completion` |

---

## Configuration / 설정

Default path / 기본 경로: `~/.revkit/config.json`

### Full Config Example / 전체 설정 예시

> For detailed documentation of every key, see [docs/README-Config.md](docs/README-Config.md).
>
> 모든 키의 상세 설명은 [docs/README-Config.md](docs/README-Config.md) 참조.
>
> **Platform-specific paths / 플랫폼별 경로:**
>
> | Key | Windows | Linux |
> | --- | --- | --- |
> | `ida.install_dir` | `"C:/Program Files/IDA Professional 9.3"` | `"/opt/ida"` |
> | `jeb.install_dir` | `"C:/WorkSpace/bin/JEB-5.38"` | `"/opt/jeb"` |
> | `jeb.java_home` | `"C:/Program Files/Java/jdk-21"` | `"/usr/lib/jvm/java-21"` |

```json
{
  "paths": {
    "idb_dir": "~/.revkit/ida/idb",
    "log_dir": "~/.revkit/logs",
    "registry": "~/.revkit/ida/registry.json",
    "project_dir": "~/.revkit/jeb/projects",
    "output_dir": "~/.revkit/output"
  },
  "analysis": {
    "max_instances": 3,
    "wait_poll_interval": 1.0,
    "wait_timeout": 120,
    "stale_threshold": 86400,
    "open_db_timeout": 300,
    "heartbeat_interval": 30,
    "auto_save": true
  },
  "security": {
    "auth_token_file": "~/.revkit/auth_tokens.json",
    "exec_enabled": false
  },
  "server": { "host": "127.0.0.1" },
  "log": { "max_size_mb": 10, "backup_count": 3, "stderr_capture": true },
  "output": { "default_count": 50, "max_count": 500, "encoding": "utf-8" },
  "ida": {
    "install_dir": "/opt/ida"
  },
  "jeb": {
    "install_dir": "/opt/jeb",
    "spawn_method": "wrapper",
    "java_home": "/usr/lib/jvm/java-21",
    "security": { "exec_enabled": false },
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

### Config Sections / 설정 섹션 요약

| Section | Description / 설명 |
| ------- | ------------------ |
| `paths` | Data directories — IDB, logs, registry, projects, output / 데이터 디렉터리 |
| `analysis` | Instance limits, timeouts, polling intervals / 분석 인스턴스 제한·타임아웃 |
| `security` | Auth token path, exec permission / 인증 토큰, exec 권한 |
| `server` | Headless server bind host / 서버 바인드 호스트 |
| `log` | Log rotation settings / 로그 로테이션 |
| `output` | Default output limits, encoding / 출력 제한·인코딩 |
| `ida` | IDA Pro install path / IDA 설치 경로 |
| `jeb` | JEB install path, heap config, spawn method / JEB 설치·힙·실행 방식 |
| `gateway` | Gateway daemon settings / 게이트웨이 설정 |

### Environment Variable Expansion / 환경 변수 확장

Config values support `~`, `$HOME`, `%USERPROFILE%` expansion (cross-platform).

설정 값은 `~`, `$HOME`, `%USERPROFILE%` 확장을 지원한다 (크로스 플랫폼).

### Local Config Override / 로컬 설정 오버라이드

Place `config.local.json` in the project directory to override base config values.

프로젝트 디렉터리에 `config.local.json`을 배치하여 기본 설정을 오버라이드할 수 있다.

---

## Platform Support / 플랫폼 지원

revkit supports both **Windows** and **Linux**. / revkit은 **Windows**와 **Linux**를 모두 지원한다.

| Feature / 기능 | Windows | Linux |
| --- | --- | --- |
| Process spawn / 프로세스 생성 | `CREATE_NO_WINDOW` | `start_new_session` |
| Process kill / 프로세스 종료 | `taskkill /F /T` (fallback) | `SIGKILL` (fallback) |
| JEB launcher / JEB 런처 | `jeb_wincon.bat` | `jeb` (shell script) |
| JEB spawn method / JEB 실행 방식 | `bat` or `wrapper` | `wrapper` only |
| Java binary / Java 바이너리 | `java.exe` | `java` |
| Classpath separator / 클래스패스 구분자 | `;` | `:` |
| RAM detection / RAM 감지 | psutil > PowerShell > 8GB fallback | cgroup > /proc/meminfo > psutil > 8GB fallback |
| Encoding / 인코딩 | UTF-8 forced (cp949 override) | UTF-8 native |
| Config paths / 설정 경로 | `~/.revkit/config.json` (same) | `~/.revkit/config.json` (same) |
| Migration backward compat / 마이그레이션 호환 | Windows junction (`mklink /J`) | Symlink (`ln -s`) |

> **Note**: `psutil` is recommended on both platforms but required on Windows for reliable process detection.
>
> `psutil`은 양쪽 플랫폼 모두 권장하지만, Windows에서는 안정적인 프로세스 감지를 위해 필수.

---

## Remote Mode / 원격 모드

```bash
# Remote analysis via Gateway / Gateway 경유 원격 분석
revkit --remote http://analysis-server:8080 ida start sample.exe

# Remote instance list / 원격 인스턴스 목록
revkit --remote http://analysis-server:8080 list

# Remote RPC call (save locally with --out)
# 원격 RPC 호출 (--out으로 로컬 저장)
revkit --remote http://srv:8080 ida decompile 0x401000 --out result.json
```

### Remote Start Flow / 원격 start 흐름

```text
1. CLI: Upload binary to Gateway → get file_id
        바이너리를 Gateway에 upload → file_id 획득
2. CLI: POST /api/v1/engines/{engine}/start → instance_id
3. CLI: Poll until instance ready / polling으로 instance ready 대기
4. CLI: Output instance_id → RPC calls available
        instance_id 출력 → 이후 RPC 호출 가능
```

### Remote Functions / 원격 함수

| Function | Description / 설명 |
| -------- | ------------------ |
| `upload_binary()` | Upload binary to Gateway (multipart) / 바이너리 업로드 |
| `remote_start()` | Upload + start engine + return instance_id / 업로드 + 엔진 시작 |
| `remote_list()` | List remote instances / 원격 인스턴스 목록 |
| `post_rpc_remote()` | Send RPC call via Gateway proxy / Gateway 프록시 RPC 호출 |

---

## Gateway

HTTP Gateway daemon with API key authentication, IP whitelist (CIDR), and audit logging.

HTTP Gateway daemon. API key 인증, IP whitelist (CIDR), audit logging 지원.

```bash
# Start Gateway / Gateway 시작
python -m revkit.tools.gateway.daemon --config config.json
```

### API Endpoints

| Method | Path | Description / 설명 |
| ------ | ---- | ----------------- |
| `GET` | `/api/v1/health` | Health check (no auth / 인증 불필요) |
| `GET` | `/api/v1/instances` | List all instances / 전체 인스턴스 목록 |
| `POST` | `/api/v1/instances/{id}/rpc` | JSON-RPC proxy / JSON-RPC 프록시 |
| `DELETE` | `/api/v1/instances/{id}` | Delete instance / 인스턴스 삭제 |
| `POST` | `/api/v1/engines/{engine}/start` | Start engine / 엔진 시작 |
| `POST` | `/api/v1/upload` | Upload binary (multipart) / 바이너리 업로드 |

### Gateway Config / Gateway 설정

```json
{
    "gateway": {
        "host": "0.0.0.0",
        "port": 8080,
        "api_key": "your-secret-key",
        "allowed_ips": ["192.168.1.0/24"],
        "trusted_proxies": ["10.0.0.1"],
        "max_upload_size_mb": 500,
        "request_timeout": 60,
        "batch_timeout": 300,
        "upload_dir": "~/.revkit/uploads",
        "audit_path": "~/.revkit/gateway/audit.jsonl",
        "audit_max_size_mb": 100,
        "log_rpc_params": false
    }
}
```

| Key | Description / 설명 | Default |
| --- | ------------------ | ------- |
| `host` | Bind address / 바인드 주소 | `0.0.0.0` |
| `port` | Port number / 포트 번호 | `8080` |
| `api_key` | API key (null = disabled) / API 키 | `null` |
| `allowed_ips` | IP whitelist (CIDR supported) / IP 화이트리스트 | `[]` (all) |
| `trusted_proxies` | Trusted proxy IPs for X-Forwarded-For / 신뢰할 프록시 | `[]` |
| `max_upload_size_mb` | Max upload size (MB) / 최대 업로드 크기 | `500` |
| `request_timeout` | RPC timeout (seconds) / RPC 타임아웃 | `60` |
| `batch_timeout` | Batch RPC timeout / 배치 타임아웃 | `300` |
| `upload_dir` | Upload directory / 업로드 디렉터리 | `~/.revkit/uploads` |
| `log_rpc_params` | Log RPC params in audit / RPC 파라미터 로깅 | `false` |

### Authentication Flow / 인증 흐름

```text
1. Extract client IP (X-Forwarded-For if from trusted proxy)
   클라이언트 IP 추출 (신뢰할 프록시의 경우 X-Forwarded-For)
2. Check IP whitelist (CIDR matching) / IP 화이트리스트 확인
3. Validate API key (timing-safe comparison) / API 키 검증 (타이밍 공격 방지)
```

### Audit Logging / 감사 로깅

JSONL format, one event per line / JSONL 형식, 한 줄에 하나의 이벤트:

```json
{
    "ts": "2026-03-20T10:30:45.123456+00:00",
    "engine": "ida",
    "cmd": "decompile",
    "iid": "a3f2",
    "ok": true,
    "ms": 1234.56,
    "source_ip": "192.168.1.100"
}
```

Sensitive fields (`code`, `script`, `exec_code`) are automatically redacted.

민감 필드(`code`, `script`, `exec_code`)는 자동으로 마스킹된다.

---

## Engine Support / 엔진 지원

| Feature | IDA | JEB |
| ------- | --- | --- |
| Binary formats / 바이너리 | PE, ELF, Mach-O | APK, DEX, JAR |
| DB extension / DB 확장자 | `.i64` | `.jdb2` (auto-saved to `paths.project_dir`, reused across sessions) |
| Identifier / 식별자 | Memory address (`0x401000`) | DEX signature (`Lcom/example/Foo;`) |
| Instance ID / 인스턴스 ID | 4-digit hex (`a3f2`) | `{name}_{4hex}` (`app-a3f2`) |
| Server runtime / 서버 런타임 | CPython 3.12+ | Jython 2.7 |
| Commands / 명령어 | 62 | 72 |
| Detailed docs / 상세 문서 | [README-IDA.md](docs/README-IDA.md) | [README-JEB.md](docs/README-JEB.md) |

### JEB Project Persistence / JEB 프로젝트 영속성

JEB `.jdb2` projects are saved to `paths.project_dir` (default: `~/.revkit/jeb/projects/`) and automatically reused across sessions:

JEB `.jdb2` 프로젝트는 `paths.project_dir` (기본: `~/.revkit/jeb/projects/`)에 저장되며, 세션 간 자동 재사용된다:

1. **Save**: `saveProject(key, path, null, null)` — saves to configured project directory, not JEB install dir.
2. **Load**: On `start`, searches for existing `.jdb2` by binary name prefix and loads it via `loadProject()`.
3. **Fresh**: Use `start --fresh` to skip `.jdb2` reuse and create a new project.
4. **Cleanup**: `cleanup` deletes orphaned `.jdb2` files not linked to any active instance.

---

## Core Infrastructure / 핵심 인프라

### Instance Registry / 인스턴스 레지스트리

Thread-safe JSON file with file locking. / 파일 락을 사용한 스레드 안전 JSON 파일.

Path / 경로: `~/.revkit/{engine}/registry.json`

```json
{
    "id": "a3f2",
    "state": "ready",
    "path": "/path/to/binary",
    "binary": "sample.exe",
    "pid": 12345,
    "port": 18861,
    "started": 1234567890.0,
    "last_heartbeat": 1234567890.5
}
```

States / 상태: `initializing` → `analyzing` → `ready` | `error`

Auto-cleanup: removes stale entries (dead process, no heartbeat > 120s). `cleanup` also deletes unused `.jdb2` project files.

자동 정리: 죽은 프로세스, 120초 이상 heartbeat 없는 항목을 제거한다. `cleanup`은 미사용 `.jdb2` 프로젝트 파일도 삭제한다.

### JSON-RPC Client

```text
POST http://127.0.0.1:{port}/
Content-Type: application/json

{
    "method": "decompile",
    "params": {"addr": "0x401000"},
    "id": 1
}
```

Features / 기능:

- Automatic retry (default: 3 attempts) / 자동 재시도 (기본 3회)
- Batch timeout support / 배치 타임아웃 지원
- Auth token support / 인증 토큰 지원
- Verbose logging / 상세 로깅

### Process Management / 프로세스 관리

- Cross-platform detached process spawning / 크로스 플랫폼 분리 프로세스 생성
  - Windows: `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP`
  - Unix: `start_new_session=True`
- Force kill with `psutil` fallback to `os.kill` / `psutil` fallback
- Stderr redirected to log file / stderr는 로그 파일로 리다이렉트

---

## Project Structure / 프로젝트 구조

```text
revkit-private/
├── .gitignore
├── README.md
├── requirements.txt
├── docs/
│   ├── README-IDA.md               # IDA engine detailed docs / IDA 상세 문서
│   ├── README-JEB.md               # JEB engine detailed docs / JEB 상세 문서
│   ├── README-Config.md            # Configuration reference / 설정 레퍼런스
│   ├── README-Logging.md           # Logging system / 로깅 시스템
│   └── README-Setup.md             # Installation guide / 설치 가이드
├── Samples/                        # Test binaries / 테스트용 바이너리
│   ├── APK/                        #   APK (KCB, NICE, SCI, UnCrackable)
│   ├── DEX/                        #   Memory-dumped DEX / 메모리 덤프 DEX
│   ├── ELF/                        #   ELF (ARM64, ARMv7, Mips4, PowerPC, V850)
│   ├── EXE/                        #   PE (notepad.exe)
│   └── IPA/                        #   IPA (KCB, NICE, SCI)
├── guide/                          # Design docs & roadmap / 설계 문서 + 로드맵
│   ├── integration_plan.md
│   ├── roadmap.md
│   ├── test_plan.md
│   ├── CHANGELOG.md
│   ├── Minutes/                    #   Review notes / 리뷰 기록
│   └── design/                     #   Phase 3 design (step01~step20)
└── revkit/
    ├── __init__.py
    ├── pyproject.toml
    ├── bin/                        # Wrapper scripts / 래퍼 스크립트
    │   ├── revkit                  #   Main CLI entrypoint / 메인 CLI 엔트리포인트
    │   ├── jeb-cli                 #   Legacy JEB wrapper (deprecated)
    │   └── ida-cli.py              #   Legacy IDA wrapper (deprecated)
    ├── tools/
    │   ├── cli/                    # CLI
    │   │   ├── main.py             #   argparse + auto-detect engine
    │   │   ├── remote.py           #   Gateway remote mode client / 원격 모드 클라이언트
    │   │   └── commands/
    │   │       └── common.py       #   Tier 1 handlers (start/list/stop/status/wait)
    │   ├── core/                   # Shared infrastructure / 공통 인프라
    │   │   ├── config.py           #   Config load/save / 설정 로드·저장
    │   │   ├── registry.py         #   Instance registry (JSON) / 인스턴스 레지스트리
    │   │   ├── rpc.py              #   JSON-RPC client
    │   │   ├── audit.py            #   Audit logging (JSONL) / 감사 로깅
    │   │   ├── logging_setup.py    #   JSONL logging system / 로깅 시스템
    │   │   ├── instance.py         #   Instance management / 인스턴스 관리
    │   │   ├── output.py           #   Output format (table/JSON) / 출력 포맷
    │   │   ├── process.py          #   Process management (psutil fallback) / 프로세스 관리
    │   │   └── utils.py            #   Utilities / 유틸리티
    │   ├── engines/
    │   │   ├── base.py             #   EngineBase ABC + CmdContext
    │   │   ├── ida/                #   IDA Pro engine
    │   │   │   ├── engine.py       #     IDAEngine implementation / 구현
    │   │   │   ├── commands/       #     CLI commands (9 modules / 9모듈)
    │   │   │   └── server/         #     JSON-RPC server + handlers (9 modules / 9모듈)
    │   │   └── jeb/                #   JEB Pro engine
    │   │       ├── engine.py       #     JEBEngine implementation / 구현
    │   │       ├── commands/       #     CLI commands (13 modules / 13모듈)
    │   │       └── server/         #     JSON-RPC server + handlers (11 modules / 11모듈)
    │   ├── gateway/                # HTTP Gateway
    │   │   ├── daemon.py           #   ThreadingHTTPServer
    │   │   ├── auth.py             #   API key + IP whitelist + CIDR
    │   │   ├── router.py           #   URL routing + RPC proxy / 라우팅 + RPC 프록시
    │   │   ├── upload.py           #   Multipart binary upload / 바이너리 업로드
    │   │   ├── audit.py            #   Gateway audit logging / 감사 로깅
    │   │   └── config.py           #   Gateway config / 설정
    │   ├── libs/
    │   │   └── APKEditor-1.4.7.jar #   Split APK merge tool (REAndroid) / 병합 도구
    │   └── scripts/                # Migration / 마이그레이션
    │       ├── migrate.py          #   ~/.ida-headless + ~/.jeb-headless → ~/.revkit/
    │       └── verify_migration.py #   Migration verification / 검증
    └── tests/                      # 218 tests
        ├── conftest.py
        ├── test_cli/               #   CLI + remote (25)
        ├── test_core/              #   Core modules (61)
        ├── test_engines/           #   Engines (29)
        ├── test_gateway/           #   Gateway (61)
        ├── test_integration/       #   E2E + migration (22)
        └── test_security/          #   Path traversal (8)
```

---

## Testing / 테스트

```bash
cd revkit
pip install -e ".[dev]"
python -m pytest tests/ -v
```

218 tests across 6 categories / 218개 테스트, 6개 카테고리:

| Category / 카테고리 | Count / 수 | Target / 대상 |
| ------------------- | --------- | ------------ |
| core | 61 | config, registry, rpc, audit, instance, output, process, utils |
| engines | 29 | base, ida_engine, jeb_engine |
| cli | 25 | main, remote |
| gateway | 61 | auth, daemon, router, upload, audit |
| integration | 22 | local E2E, remote E2E, migration |
| security | 8 | path traversal |

---

## Migration / 마이그레이션

Migrate from legacy directories to unified revkit structure.

기존 `~/.ida-headless/` + `~/.jeb-headless/` → `~/.revkit/{ida,jeb}/` 마이그레이션:

```bash
# Dry-run / 시뮬레이션
python -m revkit.tools.scripts.migrate --dry-run

# Execute / 실행
python -m revkit.tools.scripts.migrate

# Verify / 검증
python -m revkit.tools.scripts.migrate --verify
```

---

## License / 라이선스

Private. / 비공개.
