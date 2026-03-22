# revkit — Setup Guide / 설치 가이드

Complete installation and setup guide for revkit on Windows, Linux, and macOS.

Windows, Linux, macOS 환경에서 revkit을 설치하고 설정하는 전체 가이드입니다.

---

## Table of Contents / 목차

- [Prerequisites / 사전 요구사항](#prerequisites--사전-요구사항)
- [Step 1: Install Python Dependencies / Python 패키지 설치](#step-1-install-python-dependencies--python-패키지-설치)
- [Step 2: Create Config Directory / 설정 디렉토리 생성](#step-2-create-config-directory--설정-디렉토리-생성)
- [Step 3: Create config.json / 설정 파일 생성](#step-3-create-configjson--설정-파일-생성)
- [Step 4: Initialize revkit / revkit 초기화](#step-4-initialize-revkit--revkit-초기화)
- [Step 5: Verify Installation / 설치 확인](#step-5-verify-installation--설치-확인)
- [Step 6: Test Server Launch / 서버 실행 테스트](#step-6-test-server-launch--서버-실행-테스트)
- [IDA Pro Setup Details / IDA Pro 설정 상세](#ida-pro-setup-details--ida-pro-설정-상세)
- [JEB Pro Setup Details / JEB Pro 설정 상세](#jeb-pro-setup-details--jeb-pro-설정-상세)
- [Directory Structure After Setup / 설정 후 디렉토리 구조](#directory-structure-after-setup--설정-후-디렉토리-구조)
- [Windows-Specific Notes / Windows 관련 참고사항](#windows-specific-notes--windows-관련-참고사항)
- [Linux-Specific Notes / Linux 관련 참고사항](#linux-specific-notes--linux-관련-참고사항)
- [macOS-Specific Notes / macOS 관련 참고사항](#macos-specific-notes--macos-관련-참고사항)
- [Troubleshooting / 문제 해결](#troubleshooting--문제-해결)

---

## Prerequisites / 사전 요구사항

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | Must be on PATH |
| IDA Pro | 9.3+ | For IDA engine (license required) |
| JEB Pro | 5.x | For JEB engine (license required) |
| Java | 17+ (21 recommended) | For JEB engine (wrapper mode) |
| pip packages | `requests`, `psutil` | `psutil` optional on Linux, required on Windows |
| Shell | bash/zsh (Linux/macOS), Git Bash (Windows) | Standard CLI usage |

You need at least one of IDA Pro or JEB Pro. Both are not required — install only the engine(s) you plan to use.

IDA Pro 또는 JEB Pro 중 최소 하나가 필요하다. 둘 다 필요하지 않으며 사용할 엔진만 설치하면 된다.

---

## Step 1: Install Python Dependencies / Python 패키지 설치

```bash
cd Private/revkit-private/revkit
pip install -e .
```

To install with all optional dependencies:

모든 선택적 의존성을 포함하여 설치하려면:

```bash
pip install -e ".[full]"
```

Alternatively, install manually:

수동으로 설치할 경우:

```bash
pip install requests psutil
```

---

## Step 2: Create Config Directory / 설정 디렉토리 생성

```bash
mkdir -p ~/.revkit
```

On Windows with Git Bash, `~` expands to `C:/Users/<username>`. The actual directory will be `C:/Users/<username>/.revkit`.

Windows Git Bash에서 `~`는 `C:/Users/<사용자명>`으로 확장된다. 실제 디렉토리는 `C:/Users/<사용자명>/.revkit`이 된다.

---

## Step 3: Create config.json / 설정 파일 생성

Create `~/.revkit/config.json` with the following template. Adjust paths to match your system.

아래 템플릿으로 `~/.revkit/config.json`을 생성한다. 경로는 자신의 환경에 맞게 수정한다.

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
  "server": {
    "host": "127.0.0.1"
  },
  "log": {
    "max_size_mb": 10,
    "backup_count": 3,
    "stderr_capture": true
  },
  "output": {
    "default_count": 50,
    "max_count": 500,
    "encoding": "utf-8"
  },
  "ida": {
    "install_dir": "C:/Program Files/IDA Professional 9.3",  // Linux: "~/ida-pro-9.3"
    "security": { "exec_enabled": true }
  },
  "jeb": {
    "install_dir": "C:/WorkSpace/bin/JEB-5.38",              // Linux: "~/JEB-5.38"
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
  "gateway": {
    "host": "0.0.0.0",
    "port": 8080,
    "max_upload_size_mb": 500,
    "upload_dir": "~/.revkit/uploads",
    "api_key": null,
    "allowed_ips": [],
    "trusted_proxies": [],
    "request_timeout": 60,
    "batch_timeout": 300,
    "log_rpc_params": false,
    "audit_path": "~/.revkit/logs/gateway/audit.jsonl",
    "audit_max_size_mb": 100
  }
}
```

### Config Section Reference / 설정 섹션 설명

| Section | Description | 설명 |
|---------|-------------|------|
| `paths` | Data directories for IDB files, logs, registry, JEB projects, and output | IDB 파일, 로그, 레지스트리, JEB 프로젝트, 출력 디렉토리 경로 |
| `analysis` | Instance limits, timeouts, heartbeat, auto-save behavior | 인스턴스 제한, 타임아웃, 하트비트, 자동 저장 설정 |
| `security` | Auth token file path, exec permission toggle | 인증 토큰 파일 경로, 명령 실행 권한 |
| `server` | RPC server bind address (localhost recommended) | RPC 서버 바인드 주소 (localhost 권장) |
| `log` | Log rotation size and backup count | 로그 로테이션 크기 및 백업 수 |
| `output` | Default/max result counts, text encoding | 기본/최대 결과 수, 텍스트 인코딩 |
| `ida` | IDA Pro installation directory | IDA Pro 설치 경로 |
| `jeb` | JEB installation directory, spawn method, heap sizing rules | JEB 설치 경로, 실행 방식, 힙 크기 규칙 |
| `gateway` | API gateway: host, port, upload limits, auth, audit logging | API 게이트웨이: 호스트, 포트, 업로드 제한, 인증, 감사 로그 |

**Notes on paths / 경로 관련 참고:**

- `~` is expanded to the user home directory automatically (`$HOME` or `%USERPROFILE%`).
- Environment variables like `$HOME` and `%USERPROFILE%` are also expanded.
- On Windows, use **forward slashes** in paths: `"C:/Program Files/IDA Professional 9.3"`.
- `~`는 자동으로 사용자 홈 디렉토리로 확장된다.
- `$HOME`, `%USERPROFILE%` 등 환경변수도 자동 확장된다.
- Windows에서는 경로에 **슬래시(/)** 를 사용한다: `"C:/Program Files/IDA Professional 9.3"`.

---

## Step 4: Initialize revkit / revkit 초기화

Run the `init` command to create required directories (idb_dir, log_dir, registry file):

`init` 명령으로 필요한 디렉토리(idb_dir, log_dir, 레지스트리 파일)를 생성한다:

```bash
# IDA engine initialization
python -m revkit.tools.cli.main ida init

# Verify environment (checks Python, idapro module, IDA directory)
python -m revkit.tools.cli.main ida check
```

For JEB:

JEB의 경우:

```bash
python -m revkit.tools.cli.main jeb init
python -m revkit.tools.cli.main jeb check
```

---

## Step 5: Verify Installation / 설치 확인

```bash
# Show top-level help (ida/jeb subcommands)
# 최상위 도움말 표시
python -m revkit.tools.cli.main --help

# Show all IDA commands (62 commands)
# 전체 IDA 명령 표시 (62개)
python -m revkit.tools.cli.main ida --help

# Show all JEB commands (72 commands)
# 전체 JEB 명령 표시 (72개)
python -m revkit.tools.cli.main jeb --help

# List running instances (should show "No active instances")
# 실행 중인 인스턴스 목록 (활성 인스턴스 없음으로 표시되어야 함)
python -m revkit.tools.cli.main ida list
python -m revkit.tools.cli.main jeb list
```

---

## Step 6: Test Server Launch / 서버 실행 테스트

### IDA Engine

```bash
# Start a headless IDA server on a binary
python -m revkit.tools.cli.main --config ~/.revkit/config.json ida start Samples/EXE/notepad.exe

# Wait for the server to be ready (blocks until RPC is up)
python -m revkit.tools.cli.main --config ~/.revkit/config.json ida wait -i <instance_id>

# Check server status
python -m revkit.tools.cli.main --config ~/.revkit/config.json ida status -i <instance_id>

# Run a command (example: decompile a function)
python -m revkit.tools.cli.main --config ~/.revkit/config.json ida decompile 0x401000 -i <instance_id>

# Stop the server
python -m revkit.tools.cli.main --config ~/.revkit/config.json ida stop -i <instance_id>
```

### JEB Engine

```bash
# Start a headless JEB server on an APK (reuses existing .jdb2 project if available)
python -m revkit.tools.cli.main --config ~/.revkit/config.json jeb start Samples/APK/sample.apk

# Start fresh (ignore saved .jdb2 project)
python -m revkit.tools.cli.main --config ~/.revkit/config.json jeb start --fresh Samples/APK/sample.apk

# Wait, status, stop — same pattern as IDA
python -m revkit.tools.cli.main --config ~/.revkit/config.json jeb wait -i <instance_id>
python -m revkit.tools.cli.main --config ~/.revkit/config.json jeb status -i <instance_id>
python -m revkit.tools.cli.main --config ~/.revkit/config.json jeb stop -i <instance_id>
```

Replace `<instance_id>` with the 4-digit hex ID returned by `start` (e.g., `a3f2`).

`<instance_id>`를 `start` 명령이 반환하는 4자리 hex ID로 교체한다 (예: `a3f2`).

---

## IDA Pro Setup Details / IDA Pro 설정 상세

- **IDA Pro 9.3+** must be installed separately (commercial license required).
- Set `ida.install_dir` in `config.json` to the IDA installation path.
- IDA 9.3 uses **idalib** (headless Python API): uses `idat` (Linux) or `idat.exe` (Windows) internally.
- Python must be able to import `idapro`:
  ```bash
  pip install ~/ida-pro-9.3/idalib/python/idapro-*.whl    # install
  python ~/ida-pro-9.3/idalib/python/py-activate-idalib.py -d ~/ida-pro-9.3  # activate (Linux MUST)
  python -c "import idapro; print('OK')"                   # verify
  ```
  If this fails, ensure the IDA Python site-packages are on your `PYTHONPATH`, or install the `idapro` pip package. On Linux, the `py-activate-idalib.py` step is **required** — without it, `ida_loader` will not be found.
- The `IDADIR` environment variable is set automatically by revkit at runtime.

- **IDA Pro 9.3+** 를 별도로 설치해야 한다 (상용 라이선스 필요).
- `config.json`에서 `ida.install_dir`을 IDA 설치 경로로 설정한다.
- IDA 9.3은 **idalib**(headless Python API)을 사용한다: 내부적으로 `idat`(Linux) 또는 `idat.exe`(Windows)를 사용한다.
- Python에서 `idapro`를 import 할 수 있어야 한다. Linux에서는 `py-activate-idalib.py` 실행이 **필수** — 이걸 안 하면 `ida_loader`를 찾을 수 없다.
- `IDADIR` 환경변수는 revkit이 런타임에 자동 설정한다.

---

## JEB Pro Setup Details / JEB Pro 설정 상세

- **JEB Pro** must be installed separately (commercial license required).
- Set `jeb.install_dir` in `config.json` to the JEB installation path.
- **spawn_method**: `"wrapper"` (recommended, all platforms) or `"bat"` (Windows only).
  - `"wrapper"`: Uses `java` + `JebScriptRunner` directly. Requires Java 17+ on PATH or set `jeb.java_home`. **Works on Windows, Linux, macOS.**
  - `"bat"`: Uses `jeb_wincon.bat` from the JEB installation. Simpler but less configurable. **Windows only** — requires `patch` first.
- **Heap auto-sizing**: When `jeb.heap.auto` is `true`, the JVM heap size is determined by the input APK file size using the rules in `jeb.heap.rules`:
  - APK up to 50 MB: 2G heap
  - APK up to 200 MB: 4G heap
  - APK up to 500 MB: 8G heap
  - Larger: uses `jeb.heap.default` (4G), capped at `jeb.heap.max` (16G)
- Set `jeb.java_home` if Java is not in `PATH`.

- **JEB Pro**를 별도로 설치해야 한다 (상용 라이선스 필요).
- `config.json`에서 `jeb.install_dir`을 JEB 설치 경로로 설정한다.
- **spawn_method**: `"wrapper"` (권장, 모든 플랫폼) 또는 `"bat"` (Windows 전용).
  - `"wrapper"`: `java` + `JebScriptRunner`를 직접 실행한다. Java 17+가 PATH에 있거나 `jeb.java_home`을 설정해야 한다. **Windows, Linux, macOS 모두 지원.**
  - `"bat"`: JEB 설치 디렉토리의 `jeb_wincon.bat`을 사용한다. 단순하지만 설정 범위가 제한적이다. **Windows 전용** — `patch` 선행 필요.
- **힙 자동 크기 조정**: `jeb.heap.auto`가 `true`이면 입력 APK 파일 크기에 따라 JVM 힙 크기가 결정된다.
- Java가 `PATH`에 없으면 `jeb.java_home`을 설정한다.

---

## Directory Structure After Setup / 설정 후 디렉토리 구조

```
~/.revkit/
├── config.json              <- main configuration / 메인 설정 파일
├── auth_tokens.json         <- auto-generated auth tokens / 자동 생성 인증 토큰
├── ida/
│   ├── registry.json        <- instance registry / 인스턴스 레지스트리
│   └── idb/                 <- IDA database files (.i64)
│       └── {instance_id}/
├── jeb/
│   └── projects/            <- JEB project files / JEB 프로젝트 파일
├── logs/                    <- all log files (JSONL format)
│   ├── revkit.jsonl
│   ├── commands.jsonl
│   ├── ida/
│   │   ├── engine.jsonl
│   │   └── instances/
│   │       ├── {iid}.jsonl      <- per-instance server log
│   │       └── {iid}.stderr     <- per-instance stderr capture
│   ├── jeb/
│   │   ├── engine.jsonl
│   │   └── instances/
│   │       ├── {iid}.jsonl
│   │       └── {iid}.stderr
│   └── gateway/
│       ├── gateway.jsonl
│       └── audit.jsonl
├── output/                  <- RPC output files / RPC 출력 파일
└── uploads/                 <- gateway file uploads / 게이트웨이 업로드 파일
```

---

## Windows-Specific Notes / Windows 관련 참고사항

1. **Forward slashes in config.json**: Always use `/` not `\` in path values.
   ```json
   "install_dir": "C:/Program Files/IDA Professional 9.3"
   ```
   config.json 경로 값에는 항상 `/`를 사용한다. `\`는 JSON 이스케이프 문자이므로 문제가 생긴다.

2. **Git Bash**: Use `$HOME` instead of `~` when passing config paths in shell commands.
   ```bash
   python -m revkit.tools.cli.main --config $HOME/.revkit/config.json ida start ...
   ```
   Git Bash에서 config 경로를 전달할 때는 `~` 대신 `$HOME`을 사용한다.

3. **Execution methods**: revkit can be invoked in multiple ways:
   ```bash
   # Module invocation (always works)
   python -m revkit.tools.cli.main ida ...

   # Shell script
   bash revkit/bin/revkit ida ...
   ```
   revkit은 여러 방법으로 실행할 수 있다. `python -m` 방식이 가장 확실하다.

4. **IDA 9.3 on Windows**: `idat.exe` (text mode), `ida.exe` (GUI). The revkit server uses idalib directly — no separate executable is spawned for analysis.

   IDA 9.3 서버는 idalib을 직접 사용한다. 분석을 위해 별도 실행 파일을 실행하지 않는다.

5. **Python encoding**: All file operations in revkit use `encoding='utf-8'` to avoid `cp949` codec errors common on Korean Windows systems.

   모든 파일 작업은 `encoding='utf-8'`을 사용한다. 한국어 Windows에서 발생하는 `cp949` 코덱 오류를 방지하기 위함이다.

---

## Linux-Specific Notes / Linux 관련 참고사항

### IDA Pro on Linux

IDA Pro 9.3+ provides `idalib` headless Python API. On Linux, you must manually activate the binding.

IDA Pro 9.3+는 `idalib` headless Python API를 제공한다. Linux에서는 바인딩을 수동으로 활성화해야 한다.

```bash
# 1. Install idalib wheel / idalib wheel 설치
pip install ~/ida-pro-9.3/idalib/python/idapro-*.whl

# 2. Activate idalib (MUST run once — without this, import ida_loader fails)
#    idalib 활성화 (필수 — 이걸 안 하면 ida_loader import 실패)
python ~/ida-pro-9.3/idalib/python/py-activate-idalib.py -d ~/ida-pro-9.3

# 3. Verify / 확인
python -c "import idapro; print('OK')"
revkit ida check
```

> **Known issue**: `revkit ida check` shows `idapro: found` but `ida start` crashes with `ModuleNotFoundError: No module named 'ida_loader'` — you forgot step 2 (activate).
>
> `ida check`는 통과하지만 `ida start`가 `ida_loader` 에러로 실패하면 2단계(activate)를 빠뜨린 것입니다.

### JEB Pro on Linux

JEB uses `jeb_linux.sh` launcher (not `jeb_wincon.bat`). `spawn_method` must be `"wrapper"`.

JEB는 `jeb_linux.sh` 런처를 사용한다 (`jeb_wincon.bat` 아님). `spawn_method`는 반드시 `"wrapper"`.

```bash
# 1. Verify launcher / 런처 확인
ls ~/JEB-5.38/jeb_linux.sh

# 2. Generate script runner (MUST run once) / 스크립트 러너 생성 (필수)
revkit jeb gen-runner
# Expected: [+] Compiled: JebScriptRunner.class

# 3. Config — spawn_method MUST be "wrapper" on Linux
#    ("bat" mode only works on Windows with patched jeb.jar)
cat ~/.revkit/config.json
{
    "jeb": {
        "install_dir": "~/JEB-5.38",
        "spawn_method": "wrapper",
        "java_home": "/usr/lib/jvm/java-21-openjdk-amd64"
    }
}
```

> `spawn_method: "bat"` is Windows-only. On Linux, always use `"wrapper"`.
>
> `spawn_method: "bat"`은 Windows 전용. Linux에서는 항상 `"wrapper"`를 사용.

### Process Management / 프로세스 관리

| Task / 작업 | Windows | Linux / macOS |
| --- | --- | --- |
| List processes / 프로세스 목록 | `tasklist \| findstr ida` | `ps aux \| grep ida_server` |
| Force kill / 강제 종료 | `taskkill /F /PID {pid}` | `kill -9 {pid}` |
| Kill by name / 이름으로 종료 | `taskkill /IM ida.exe /F` | `pkill -f ida_server` |
| Kill tree / 트리 종료 | `taskkill /F /T /PID {pid}` | `kill -9 {pid}` (psutil handles children) |
| Check port / 포트 확인 | `netstat -ano \| findstr {port}` | `ss -tlnp \| grep {port}` |

### Encoding / 인코딩

Linux uses UTF-8 natively. No `cp949` issues. The UTF-8 override in `cli/main.py` is harmless on Linux.

Linux는 기본 UTF-8. `cp949` 문제 없음. `cli/main.py`의 UTF-8 강제 설정은 Linux에서 무해.

---

## macOS-Specific Notes / macOS 관련 참고사항

macOS setup is similar to Linux with these differences:

macOS 설정은 Linux와 유사하며 아래 차이점이 있다:

- **JEB launcher / JEB 런처**: `jeb_macos.sh` (`jeb_linux.sh` 아님)
- **Java**: Homebrew (`brew install openjdk@21`) 또는 Adoptium에서 다운로드
- **Python**: Homebrew (`brew install python@3.12`) 또는 시스템 Python 3
- **Process management / 프로세스 관리**: Linux와 동일 (`ps`, `kill`, `pkill`)
- **IDA Pro**: Linux와 동일한 idalib 활성화 절차 / idalib 활성화 절차 동일

---

## Troubleshooting / 문제 해결

| Issue / 증상 | Cause / 원인 | Fix / 해결 |
|-------------|-------------|-----------|
| `ModuleNotFoundError: No module named 'idapro'` | IDA not installed or its Python packages not on PATH | Install IDA Pro 9.3+ and ensure `python -c "import idapro"` works. Check `PYTHONPATH` or install `idapro` pip package. |
| `ModuleNotFoundError: No module named 'revkit'` | revkit not installed or wrong working directory | Run `pip install -e .` from `revkit/` directory, or run from the project root. |
| `cp949 codec can't decode byte` | Missing `encoding='utf-8'` in file operation | This should not happen in revkit (all I/O is utf-8). If it does, check for external scripts using default encoding. |
| Server timeout on `start` / `start`에서 타임아웃 | Server failed to launch, or binary too large | Check `~/.revkit/logs/{engine}/instances/{iid}.stderr` for error details. Increase `analysis.open_db_timeout` for large binaries. |
| `KeyError: 'paths'` | config.json missing required sections | Ensure all sections exist in config.json. Use the template above as reference. |
| `Permission denied` on log files | Log directory permissions issue | Check `~/.revkit/logs/` permissions. Run `mkdir -p ~/.revkit/logs` and ensure write access. |
| `No module named 'revkit.tools.engines.engines'` | Wrong relative import (JEB engine) | Fix import: use `from ...base` not `from ...engines.base` (3 dots = engines level). |
| `Connection refused` on RPC commands | Server not running or not yet ready | Run `wait -i <iid>` before sending RPC commands. Check `list` to verify instance is active. |
| `No active instances` after `start` | Server crashed immediately | Check `~/.revkit/logs/{engine}/instances/{iid}.stderr`. Common cause: invalid binary path or license issue. |
| JEB `OutOfMemoryError` | Heap too small for APK size | Increase heap rules in `jeb.heap.rules` or set a larger `jeb.heap.default`. |
| `ida_loader` not found (Linux) | idalib not activated | Run `python py-activate-idalib.py -d ~/ida-pro-9.3` (see Linux Notes). / `py-activate-idalib.py` 실행 필요 (Linux Notes 참조). |
| JEB `Launcher not found` (Linux) | Wrong launcher name | Verify `jeb_linux.sh` exists. Code fix applied in `engine.py:_get_launcher_name()`. / `jeb_linux.sh` 존재 확인. |
| JEB `spawn_method: bat` fails (Linux) | bat mode is Windows-only | Set `spawn_method: "wrapper"` in config.json. / config.json에서 `"wrapper"`로 변경. |
| `KeyError: 'open_db_timeout'` | config.json missing analysis keys | Add full `analysis` section to config.json, or update revkit (DEFAULT_CONFIG fallback added). / config.json에 `analysis` 섹션 추가. |

---

## Quick Reference / 빠른 참조

```bash
# Full workflow: init -> start -> wait -> use -> stop
# 전체 워크플로우: 초기화 -> 시작 -> 대기 -> 사용 -> 중지

python -m revkit.tools.cli.main ida init
python -m revkit.tools.cli.main --config ~/.revkit/config.json ida start path/to/binary.exe
python -m revkit.tools.cli.main --config ~/.revkit/config.json ida wait -i <iid>
python -m revkit.tools.cli.main --config ~/.revkit/config.json ida decompile 0x401000 -i <iid>
python -m revkit.tools.cli.main --config ~/.revkit/config.json ida stop -i <iid>

# Cleanup all instances / 전체 인스턴스 정리
# Removes stale registry entries + unused .jdb2 project files
# 스테일 레지스트리 엔트리 + 미사용 .jdb2 프로젝트 파일 삭제
python -m revkit.tools.cli.main ida cleanup
python -m revkit.tools.cli.main jeb cleanup          # also deletes orphaned .jdb2
python -m revkit.tools.cli.main jeb cleanup --dry-run # preview without deleting
```

---

## Server Deployment / 서버 배포

Remote mode requires a server machine running the Gateway daemon + IDA/JEB engines. Follow these steps to set up the analysis server.

원격 모드를 사용하려면 서버 머신에서 Gateway 데몬 + IDA/JEB 엔진을 실행해야 한다. 아래 단계를 따라 분석 서버를 구성한다.

### 1. Install revkit / revkit 설치

The server needs IDA Pro and/or JEB Pro installed, plus the revkit package.

서버에는 IDA Pro 및/또는 JEB Pro가 설치되어 있어야 하며, revkit 패키지도 설치해야 한다.

```bash
# From the Release directory / Release 디렉토리에서
cd Release/revkit
pip install -e ".[full]"    # editable mode — source changes apply immediately
                            # editable 모드 — 소스 수정 즉시 반영

# Verify / 확인
revkit ida check             # → [+] All checks passed
revkit jeb check             # → [+] All checks passed
```

If installing from source (development) / 소스에서 설치 (개발용):

```bash
cd /path/to/revkit          # project root with pyproject.toml inside revkit/
pip install -e "revkit[full]"
```

> **Note**: `pip install` must run from the directory **containing** `pyproject.toml`, not its parent. The Release directory structure is `Release/revkit/` (project root) → `revkit/` (package).
>
> `pip install`은 `pyproject.toml`이 **있는** 디렉토리에서 실행해야 한다. Release 구조: `Release/revkit/` (프로젝트 루트) → `revkit/` (패키지).

### 2. Configure server / 서버 설정

Edit `~/.revkit/config.json`:

`~/.revkit/config.json` 편집:

```json
{
  "server": {
    "host": "0.0.0.0"          // bind to all interfaces (not 127.0.0.1)
                                // 모든 인터페이스에 바인딩 (127.0.0.1 아님)
  },
  "gateway": {
    "host": "0.0.0.0",         // gateway also binds externally
    "port": 8080,              // client connects to this port (changeable, e.g. 9932)
                                // 클라이언트 접속 포트 (변경 가능, 예: 9932)
    "api_key": "YOUR_API_KEY", // null = no auth (dev only)
    "max_upload_size_mb": 0,   // 0 = unlimited
    "upload_dir": "~/WorkSpace/uploads",
    "allowed_ips": [],         // empty = allow all, or ["192.168.1.0/24"]
    "request_timeout": 60,
    "batch_timeout": 300,
    "audit_path": "~/.revkit/logs/gateway/audit.jsonl"
  }
}
```

Key settings explained / 주요 설정 설명:

| Setting | Purpose / 용도 |
| --- | --- |
| `server.host` | IDA/JEB RPC server bind address. Must be `0.0.0.0` for remote access. / IDA/JEB RPC 서버 바인딩 주소. 원격 접속 시 `0.0.0.0` 필수. |
| `gateway.host` | Gateway daemon bind address. / 게이트웨이 데몬 바인딩 주소. |
| `gateway.port` | Port clients connect to. / 클라이언트 접속 포트. |
| `gateway.api_key` | API key for authentication. `null` disables auth. / 인증용 API 키. `null`이면 인증 비활성화. |
| `gateway.upload_dir` | Where uploaded binaries/APKs are stored. / 업로드된 바이너리/APK 저장 경로. |
| `gateway.allowed_ips` | IP allowlist. Empty array allows all. / IP 허용 목록. 빈 배열이면 전체 허용. |

Generate a secure API key / 안전한 API 키 생성:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 3. Start Gateway / 게이트웨이 시작

```bash
# Foreground (for testing) / 포그라운드 (테스트용)
python -m revkit.tools.gateway.daemon --config ~/.revkit/config.json

# Background (production) / 백그라운드 (프로덕션)
nohup python -m revkit.tools.gateway.daemon --config ~/.revkit/config.json \
  >> ~/.revkit/logs/gateway/stdout.log 2>&1 &

# Verify — use real IP, not 127.0.0.1 / 확인 — 실제 IP 사용 (127.0.0.1 아님)
# Check IP: ip addr show | grep "inet " | grep -v 127.0.0.1
# IP 확인: ip addr show | grep "inet " | grep -v 127.0.0.1
curl http://192.168.50.100:8080/api/v1/health
# → {"status": "ok", "service": "revkit-gateway", ...}
```

> **Important**: Always use the real network IP (e.g. `192.168.50.100`), not `127.0.0.1` or `localhost`. Clients connect via the network IP, so verify with the same address.
>
> 반드시 실제 네트워크 IP (예: `192.168.50.100`)를 사용하세요. `127.0.0.1`이나 `localhost`가 아닙니다. 클라이언트는 네트워크 IP로 접속하므로 같은 주소로 검증해야 합니다.

### 4. Client setup / 클라이언트 설정

The client machine only needs revkit installed — **IDA/JEB are NOT required** on the client.

클라이언트에는 revkit만 설치하면 된다 — **IDA/JEB는 클라이언트에 불필요**.

```bash
# Install revkit on client (same Release package) / 클라이언트에 revkit 설치
cd Release/revkit
pip install -e ".[full]"
```

### 5. Client connection / 클라이언트 접속

```bash
# Full options / 전체 옵션 (포트는 서버 gateway.port에 맞춤)
revkit --remote http://SERVER_IP:PORT --api-key YOUR_API_KEY ida list

# Permanent — add to client's ~/.revkit/config.json / 영구 설정
# Client only needs the gateway section / 클라이언트는 gateway 섹션만 필요
# ⚠️ URL 포트는 서버의 gateway.port와 일치해야 함
{
  "gateway": {
    "url": "http://SERVER_IP:PORT",
    "api_key": "YOUR_API_KEY"
  }
}

# Short form — uses gateway.url + gateway.api_key from config
# 축약형 — config의 gateway.url + gateway.api_key 사용
revkit -R ida list
revkit -R ida start sample.exe
revkit -R jeb classes
```

Three ways to connect / 접속 방법 3가지:

| Method / 방법 | Example / 예시 | When / 용도 |
| --- | --- | --- |
| Full URL | `--remote http://IP:8080 --api-key KEY` | One-time, no config / 1회성, config 없을 때 |
| `-R` shorthand | `revkit -R ida list` | Config has `gateway.url` + `api_key` / config 설정 완료 시 |
| Auto (no flag) | `revkit ida list` | Config has `gateway.url` — always remote / config에 url 있으면 항상 원격 |

> **Priority / 우선순위**: `--remote URL` > `-R` (config) > `gateway.url` in config > local mode. Same for `--api-key` > `gateway.api_key`.
>
> `--remote URL` > `-R` (config) > config의 `gateway.url` > 로컬 모드 순서. `--api-key` > `gateway.api_key`도 동일.

### 6. systemd service (optional) / systemd 서비스 (선택)

For auto-start on boot / 부팅 시 자동 시작:

```ini
# /etc/systemd/system/revkit-gateway.service
[Unit]
Description=revkit Gateway Daemon
After=network.target

[Service]
Type=simple
User=http80
WorkingDirectory=/home/http80/revkit
ExecStart=/home/http80/revkit-env/bin/python -m revkit.tools.gateway.daemon --config /home/http80/.revkit/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable revkit-gateway
sudo systemctl start revkit-gateway
sudo systemctl status revkit-gateway
```

### Config hot-reload / 설정 자동 반영

The Gateway watches `config.json` for changes (every 2 seconds). No manual restart needed for most settings.

Gateway는 `config.json` 변경을 2초마다 감지한다. 대부분의 설정은 수동 재시작 불필요.

| Change / 변경 | Action / 동작 | Restart / 재시작 |
| --- | --- | --- |
| `api_key`, `allowed_ips`, `timeouts` | Auto-reload (hot) / 자동 반영 | No / 불필요 |
| `port`, `host` | Auto-restart / 자동 재시작 | Automatic / 자동 |
| IDA/JEB `install_dir`, `registry` | No effect until next `start` / 다음 `start`에 반영 | No / 불필요 |

```
# Example: change port from 8080 to 8090
# config.json에서 port를 8080 → 8090으로 변경하면
# Gateway가 자동으로 재시작됨 — 수동 재시작 불필요

[INFO] Config file changed, reloading...
[INFO] Port/host changed (0.0.0.0:8080 -> 0.0.0.0:8090), restarting...
[INFO] Gateway restarted on 0.0.0.0:8090
```

### Server checklist / 서버 체크리스트

```
□ revkit installed (pip install -e ".[full]")
□ ida check / jeb check passed
□ server.host = "0.0.0.0"
□ gateway section configured
□ api_key set (not null in production)
□ upload_dir exists and writable
□ firewall: port 8080 open
□ Gateway started and /health responds
□ Client can connect with --remote
```
