# Tutorial 14: Remote Analysis via Gateway / Gateway를 통한 원격 분석

Analyze binaries on a remote server without local IDA/JEB installation. All commands work identically -- just add `-R` or `--remote`.

로컬에 IDA/JEB 설치 없이 원격 서버에서 바이너리를 분석합니다. 모든 명령이 동일하게 동작하며, `-R` 또는 `--remote`만 추가하면 됩니다.

> **Prerequisites / 사전 준비**: Gateway running on server (see [12-gateway-setup.md](12-gateway-setup.md)) / 서버에서 게이트웨이 실행 중

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. Remote Mode Activation / 원격 모드 활성화

There are three ways to activate remote mode. Choose whichever fits your workflow.

원격 모드를 활성화하는 세 가지 방법이 있습니다. 워크플로우에 맞는 것을 선택하세요.

### Method 1: `-R` flag (reads `gateway.url` from config)

The simplest approach when `gateway.url` is already set in `~/.revkit/config.json`.

`~/.revkit/config.json`에 `gateway.url`이 이미 설정되어 있을 때 가장 간단한 방법입니다.

```bash
$RK -R ida list
# → No active ida instances
```

### Method 2: `--remote URL` (explicit server address)

Use this to connect to a specific server without modifying config. Useful for one-off connections.

설정을 수정하지 않고 특정 서버에 연결할 때 사용합니다. 일회성 연결에 유용합니다.

```bash
$RK --remote http://192.168.50.100:9932 ida list
# → No active ida instances
```

### Method 3: `gateway.mode = "auto"` (no flag needed)

Set `gateway.mode` to `"auto"` in config. All commands automatically route through the gateway without any flag.

config에서 `gateway.mode`를 `"auto"`로 설정합니다. 플래그 없이 모든 명령이 자동으로 게이트웨이를 통해 라우팅됩니다.

```json
{
  "gateway": {
    "mode": "auto",
    "url": "http://SERVER_IP:9932",
    "api_key": "sk-revkit-prod-a1b2c3d4e5"
  }
}
```

```bash
# No -R flag needed / -R 플래그 불필요
$RK ida list
# → Automatically uses gateway / 자동으로 게이트웨이 사용
```

### Priority / 우선순위

```
--remote URL  >  -R (config gateway.url)  >  gateway.mode=auto  >  local mode
```

---

## 2. Client Configuration / 클라이언트 설정

On the **client** machine, edit `~/.revkit/config.json`.

**클라이언트** 머신에서 `~/.revkit/config.json`을 편집합니다.

```json
{
  "gateway": {
    "url": "http://SERVER_IP:9932",
    "api_key": "sk-revkit-prod-a1b2c3d4e5"
  }
}
```

- `url` -- the gateway server address / 게이트웨이 서버 주소
- `api_key` -- must match the server's `gateway.api_key` / 서버의 `gateway.api_key`와 일치해야 함

> **Note**: You do NOT need IDA Pro or JEB installed on the client machine. Only the `revkit` Python package is required.
>
> 클라이언트 머신에 IDA Pro 또는 JEB가 설치되어 있을 필요가 없습니다. `revkit` Python 패키지만 있으면 됩니다.

---

## 3. Remote IDA Workflow / 원격 IDA 워크플로우

A complete workflow for analyzing a Windows PE binary remotely.

Windows PE 바이너리를 원격으로 분석하는 전체 워크플로우입니다.

### Start + Wait / 시작 + 대기

```bash
# Upload + start (upload is automatic) / 업로드 + 시작 (업로드 자동)
$RK -R ida start Samples/EXE/notepad.exe
# → Uploading notepad.exe... (1.2 MB)
# → [+] Started ida (id=a3k2, pid=45678, spawn=default)

# Wait for analysis / 분석 완료 대기
$RK -R ida wait --timeout 300
# → [+] a3k2 is ready
```

> **Upload**: The CLI detects that the file is local and automatically uploads it to the gateway server. No separate upload step is needed.
>
> CLI가 파일이 로컬에 있음을 감지하고 자동으로 게이트웨이 서버에 업로드합니다. 별도의 업로드 단계가 필요 없습니다.

### Analyze / 분석

```bash
# Summary / 요약
$RK -R ida summary
# Binary:      notepad.exe
# Functions:   521
# Strings:     621
# Imports:     340
# Segments:    10 (.text, .rdata, .data, ...)

# Decompile / 디컴파일
$RK -R ida decompile 0x140010108
# int __fastcall wWinMain(HINSTANCE hInstance, ...)
# {
#     ...
# }

# List segments / 세그먼트 목록
$RK -R ida segments
# | Name   | Start          | End            | Size    | Perm |
# |--------|----------------|----------------|---------|------|
# | .text  | 0x140001000    | 0x14001A000    | 0x19000 | r-x  |
# | .rdata | 0x14001A000    | 0x140025000    | 0xB000  | r--  |
# | ...    |                |                |         |      |

# Find functions / 함수 검색
$RK -R ida find-func "main"
# → 4 matches: __scrt_common_main_seh, wWinMain, ...
```

### Save Results Locally / 결과를 로컬에 저장

```bash
# Decompile output saved to LOCAL machine / 디컴파일 결과가 로컬 머신에 저장
$RK -R ida decompile 0x140010108 --out /tmp/decompile.c
# → Output saved to /tmp/decompile.c

# Generate report to local file / 리포트를 로컬 파일로 생성
$RK -R ida report /tmp/report.md
# → Report saved to /tmp/report.md
```

### Stop / 중지

```bash
$RK -R ida stop
# → [+] Stopped ida instance a3k2
```

---

## 4. Remote JEB Workflow / 원격 JEB 워크플로우

A complete workflow for analyzing an Android APK remotely.

Android APK를 원격으로 분석하는 전체 워크플로우입니다.

### Start + Wait / 시작 + 대기

```bash
# Upload + start / 업로드 + 시작
$RK -R jeb start Samples/APK/UnCrackable/UnCrackable-Level3.apk --fresh
# → Uploading UnCrackable-Level3.apk... (3.4 MB)
# → [+] Started jeb (id=b7m9, pid=56789, spawn=wrapper)

# Wait for analysis / 분석 완료 대기
$RK -R jeb wait --timeout 300
# → [+] b7m9 is ready
```

### Analyze / 분석

```bash
# App info / 앱 정보
$RK -R jeb info
# Package:     owasp.mstg.uncrackable3
# Min SDK:     19
# Target SDK:  28
# Activities:  1
# Services:    0

# List classes / 클래스 목록
$RK -R jeb classes --filter "Activity"
# | Class Signature                                    |
# |----------------------------------------------------|
# | Lsg/vantagepoint/uncrackable3/MainActivity;        |

# Decompile / 디컴파일
$RK -R jeb decompile "Lsg/vantagepoint/uncrackable3/MainActivity;"
# public class MainActivity extends AppCompatActivity {
#     ...
#     private void verify(String input) {
#         ...
#     }
# }

# Security scan / 보안 스캔
$RK -R jeb security-scan
# | Finding                | Severity | Location                    |
# |------------------------|----------|-----------------------------|
# | Root detection          | Medium   | MainActivity.onCreate       |
# | Native library load     | Info     | MainActivity.onCreate       |
# | Tamper detection        | Medium   | MainActivity.verify         |
```

### Stop / 중지

```bash
$RK -R jeb stop
# → [+] Stopped jeb instance b7m9
```

---

## 5. `--out`: Local Save in Remote Mode / 원격에서 로컬 저장

When using `--out` in remote mode, the result is saved to the **client** machine, not the server. The gateway streams the result back and the CLI writes it locally.

원격 모드에서 `--out`을 사용하면 결과가 서버가 아닌 **클라이언트** 머신에 저장됩니다. 게이트웨이가 결과를 스트리밍하고 CLI가 로컬에 저장합니다.

```bash
# Decompile result saved to local machine / 디컴파일 결과가 로컬 머신에 저장
$RK -R ida decompile 0x140010108 --out /tmp/result.c
# → Output saved to /tmp/result.c

cat /tmp/result.c
# int __fastcall wWinMain(HINSTANCE hInstance, ...)
# {
#     ...
# }

# JEB decompile saved locally / JEB 디컴파일도 로컬 저장
$RK -R jeb decompile "Lsg/vantagepoint/uncrackable3/MainActivity;" --out /tmp/main.java
# → Output saved to /tmp/main.java

# Report saved locally / 리포트 로컬 저장
$RK -R ida report /tmp/analysis_report.md
# → Report saved to /tmp/analysis_report.md
```

---

## 6. `--json` Output / JSON 출력

JSON output works identically in remote mode. Useful for scripting and CI/CD pipelines.

JSON 출력은 원격 모드에서도 동일하게 동작합니다. 스크립팅과 CI/CD 파이프라인에 유용합니다.

```bash
$RK -R --json ida list
# [
#   {
#     "id": "a3k2",
#     "pid": 45678,
#     "binary": "notepad.exe",
#     "status": "ready",
#     "port": 18100
#   }
# ]

$RK -R --json ida status
# {
#   "id": "a3k2",
#   "binary": "notepad.exe",
#   "func_count": 521,
#   "ida_version": "9.3",
#   "decompiler_available": true,
#   "uptime": "5m 23s"
# }

$RK -R --json jeb info
# {
#   "package": "owasp.mstg.uncrackable3",
#   "min_sdk": 19,
#   "target_sdk": 28,
#   "activities": 1,
#   "services": 0
# }
```

---

## 7. Multi-instance / 다중 인스턴스

You can run multiple remote instances simultaneously and target them with `-i`.

동시에 여러 원격 인스턴스를 실행하고 `-i`로 대상을 지정할 수 있습니다.

```bash
# Start two IDA instances / IDA 인스턴스 두 개 시작
$RK -R ida start sample1.exe
# → [+] Started ida (id=a3k2)
$RK -R ida start sample2.exe
# → [+] Started ida (id=f5n1)

# List all instances / 모든 인스턴스 목록
$RK -R ida list
# | ID   | PID   | Binary       | Port  | Status |
# |------|-------|--------------|-------|--------|
# | a3k2 | 45678 | sample1.exe  | 18100 | ready  |
# | f5n1 | 45690 | sample2.exe  | 18200 | ready  |

# Target a specific instance / 특정 인스턴스 대상 지정
$RK -R ida status -i a3k2
$RK -R ida decompile 0x401000 -i f5n1

# Stop one / 하나만 중지
$RK -R ida stop -i a3k2
# → [+] Stopped ida instance a3k2
```

---

## 8. Mixed Mode: Local + Remote / 로컬 + 원격 동시 사용

You can mix local and remote analysis in the same session. Remote commands use `-R`, local commands omit it.

같은 세션에서 로컬과 원격 분석을 혼합할 수 있습니다. 원격 명령은 `-R`을 사용하고, 로컬 명령은 생략합니다.

```bash
# Remote IDA analysis / 원격 IDA 분석
$RK -R ida start Samples/EXE/notepad.exe
$RK -R ida wait
$RK -R ida segments
$RK -R ida decompile 0x140010108

# Local JEB analysis (if JEB installed locally) / 로컬 JEB 분석 (JEB가 로컬 설치된 경우)
$RK jeb start Samples/APK/UnCrackable/UnCrackable-Level3.apk --fresh
$RK jeb wait
$RK jeb classes
$RK jeb decompile "Lsg/vantagepoint/uncrackable3/MainActivity;"

# Both work independently / 둘 다 독립적으로 동작
$RK -R ida summary       # remote / 원격
$RK jeb info              # local / 로컬
```

> **Tip**: Use `--remote` with different servers to analyze across multiple remote machines simultaneously.
>
> 여러 원격 머신에서 동시에 분석하려면 `--remote`에 다른 서버 주소를 사용하세요.

```bash
$RK --remote http://server-A:9932 ida start binary.exe
$RK --remote http://server-B:9932 jeb start app.apk
```

---

## 9. LOCAL_ONLY Commands / 로컬 전용 명령

Some commands only make sense locally and are blocked in remote mode. These are commands that require direct filesystem access or local tooling.

일부 명령은 로컬에서만 의미가 있으며 원격 모드에서는 차단됩니다. 직접적인 파일시스템 접근이나 로컬 도구가 필요한 명령들입니다.

```bash
# These return "local-only command" error in remote mode
# 원격 모드에서 "local-only command" 에러 반환

$RK -R ida init
# → [!] 'init' is a local-only command. Cannot run in remote mode.

$RK -R ida check
# → [!] 'check' is a local-only command. Cannot run in remote mode.

$RK -R ida cleanup
# → [!] 'cleanup' is a local-only command. Cannot run in remote mode.

$RK -R ida shell
# → [!] 'shell' is a local-only command. Cannot run in remote mode.

$RK -R ida compare
# → [!] 'compare' is a local-only command. Cannot run in remote mode.

$RK -R ida batch
# → [!] 'batch' is a local-only command. Cannot run in remote mode.

$RK -R ida bookmark
# → [!] 'bookmark' is a local-only command. Cannot run in remote mode.
```

Use these commands locally instead, or manage the server directly.

이 명령들은 로컬에서 사용하거나 서버에서 직접 관리하세요.

---

## 10. Error Handling / 에러 처리

Common remote mode errors and how to resolve them.

원격 모드에서 흔한 에러와 해결 방법입니다.

### Gateway Unreachable / 게이트웨이 연결 불가

```bash
$RK --remote http://wrong-host:9999 ida list
# → [!] Gateway unreachable: http://wrong-host:9999
# → Check that the gateway is running and the URL is correct.
```

**Fix**: Verify the server address and that the gateway daemon is running on the server.

**해결**: 서버 주소를 확인하고 서버에서 게이트웨이 데몬이 실행 중인지 확인합니다.

### Authentication Failure / 인증 실패

```bash
$RK -R ida list
# → [!] 403 Forbidden: invalid API key
```

**Fix**: Ensure `gateway.api_key` in client config matches the server's `gateway.api_key`.

**해결**: 클라이언트 config의 `gateway.api_key`가 서버의 `gateway.api_key`와 일치하는지 확인합니다.

### No Active Instances / 활성 인스턴스 없음

```bash
$RK -R ida decompile 0x401000
# → [!] No active ida instances. Run 'start' first.
```

**Fix**: Start an instance first with `$RK -R ida start <binary>`.

**해결**: 먼저 `$RK -R ida start <바이너리>`로 인스턴스를 시작합니다.

### File Not Found / 파일 없음

```bash
$RK -R ida start /nonexistent/file.exe
# → [!] File not found: /nonexistent/file.exe
```

**Fix**: Check the file path. The file must exist on the client machine for upload.

**해결**: 파일 경로를 확인합니다. 업로드를 위해 파일이 클라이언트 머신에 존재해야 합니다.

### Upload Size Exceeded / 업로드 크기 초과

```bash
$RK -R ida start huge_binary.exe
# → [!] Upload failed: file exceeds maximum size (500 MB)
```

**Fix**: Ask the server admin to increase `gateway.max_upload_size_mb`, or transfer the file to the server directly.

**해결**: 서버 관리자에게 `gateway.max_upload_size_mb`를 늘려달라고 요청하거나, 파일을 서버에 직접 전송합니다.

### Request Timeout / 요청 타임아웃

```bash
$RK -R ida decompile-all --out /tmp/all.json
# → [!] Request timed out (60s). Try increasing gateway.request_timeout.
```

**Fix**: For long-running operations, increase `gateway.request_timeout` or `gateway.batch_timeout` on the server.

**해결**: 오래 걸리는 작업의 경우, 서버에서 `gateway.request_timeout` 또는 `gateway.batch_timeout`을 늘립니다.

---

## 11. Tips / 팁

### Upload is automatic / 업로드는 자동

When you run `start` with a local file path, the CLI uploads it to the gateway server automatically. No separate upload step is needed.

로컬 파일 경로로 `start`를 실행하면 CLI가 자동으로 게이트웨이 서버에 업로드합니다. 별도의 업로드 단계가 필요 없습니다.

### `--out` saves to the CLIENT / `--out`은 클라이언트에 저장

Output files are always written to the client machine, even though analysis runs on the server. The gateway streams results back to the CLI.

분석이 서버에서 실행되더라도 출력 파일은 항상 클라이언트 머신에 저장됩니다. 게이트웨이가 결과를 CLI로 스트리밍합니다.

### No feature loss / 기능 손실 없음

The gateway proxies ALL RPC methods transparently. Every command that works locally also works remotely (except LOCAL_ONLY commands listed in section 9).

게이트웨이가 모든 RPC 메서드를 투명하게 프록시합니다. 로컬에서 동작하는 모든 명령이 원격에서도 동작합니다 (섹션 9의 LOCAL_ONLY 명령 제외).

### Clean up with `gateway stop-all` / `gateway stop-all`로 정리

To stop all running instances on the server at once:

서버의 모든 실행 중인 인스턴스를 한 번에 중지하려면:

```bash
$RK -R gateway stop-all
# → Stopped 3 instances (2 ida, 1 jeb)
```

### JEB APK upload overhead / JEB APK 업로드 오버헤드

APK uploads add approximately 2-5 seconds of overhead compared to local analysis, depending on file size and network speed. Once uploaded, all subsequent commands have no additional overhead.

APK 업로드는 파일 크기와 네트워크 속도에 따라 로컬 분석 대비 약 2-5초의 오버헤드가 추가됩니다. 업로드 후에는 모든 후속 명령에 추가 오버헤드가 없습니다.

### Use `--json` for scripting / 스크립팅에 `--json` 사용

Combine `-R` with `--json` for reliable output parsing in scripts and CI/CD pipelines:

스크립트와 CI/CD 파이프라인에서 안정적인 출력 파싱을 위해 `-R`과 `--json`을 결합합니다:

```bash
# Get instance ID programmatically / 인스턴스 ID를 프로그래밍 방식으로 가져오기
INSTANCE=$($RK -R --json ida list | jq -r '.[0].id')
$RK -R ida decompile 0x140010108 -i "$INSTANCE" --out /tmp/result.c
```

---

## Quick Reference / 빠른 참조

```bash
# === IDA Remote Workflow ===
$RK -R ida start Samples/EXE/notepad.exe     # upload + start
$RK -R ida wait --timeout 300                 # wait for ready
$RK -R ida summary                            # overview
$RK -R ida decompile 0x140010108              # decompile function
$RK -R ida find-func "main"                   # search functions
$RK -R ida report /tmp/report.md              # save report locally
$RK -R ida stop                               # stop instance

# === JEB Remote Workflow ===
$RK -R jeb start UnCrackable-Level3.apk       # upload + start
$RK -R jeb wait --timeout 300                 # wait for ready
$RK -R jeb info                               # app info
$RK -R jeb classes --filter "Activity"        # list classes
$RK -R jeb decompile "Lcom/example/Main;"     # decompile class
$RK -R jeb security-scan                      # security analysis
$RK -R jeb stop                               # stop instance

# === Management ===
$RK -R ida list                               # list remote instances
$RK -R gateway stop-all                       # stop all instances
$RK -R gateway info                           # gateway status
```

---

**Previous / 이전**: [13-ai-agent-analysis.md](13-ai-agent-analysis.md) -- Automated analysis with Claude Code / Claude Code 자동 분석
