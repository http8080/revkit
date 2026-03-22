# Tutorial 16: Security & Multi-Instance / 보안 설정 + 다중 인스턴스

Configure authentication, IP restrictions, and manage multiple analysis instances simultaneously.

인증, IP 제한을 설정하고 여러 분석 인스턴스를 동시에 관리합니다.

> **Prerequisites / 사전 준비**: Gateway deployed per [Tutorial 12](12-gateway-setup.md) / [Tutorial 12](12-gateway-setup.md)에 따라 게이트웨이 배포 완료

```bash
RK="python -m revkit.tools.cli.main"
```

---

## Part 1: Security Configuration / 보안 설정

---

## 1. API Key Authentication / API 키 인증

Set an API key in `~/.revkit/config.json` on the **server** to require authentication for all requests.

**서버**의 `~/.revkit/config.json`에 API 키를 설정하여 모든 요청에 인증을 요구합니다.

```json
{
  "gateway": {
    "api_key": "your-secret-key-here"
  }
}
```

### Testing Authentication / 인증 테스트

```bash
# No key → 403 Forbidden / 키 없이 → 403
curl http://SERVER:8080/api/v1/instances
# → {"error": "Forbidden"}

# Correct key → 200 OK / 올바른 키 → 200
curl -H "Authorization: Bearer your-secret-key-here" http://SERVER:8080/api/v1/instances
# → {"instances": [...]}
```

The CLI handles authentication automatically when `gateway.api_key` is set in the client config. No manual header needed.

CLI는 클라이언트 설정에 `gateway.api_key`가 설정되어 있으면 자동으로 인증을 처리합니다. 수동 헤더 불필요.

```bash
# CLI sends Bearer token automatically / CLI가 Bearer 토큰 자동 전송
$RK -R ida list
$RK -R jeb list
```

### Disabling Authentication / 인증 비활성화

Set `api_key` to `null` to allow unauthenticated access (development/local use only).

`api_key`를 `null`로 설정하면 인증 없이 접근 가능합니다 (개발/로컬 전용).

```json
{
  "gateway": {
    "api_key": null
  }
}
```

### Rotating Keys / 키 교체

```bash
# Generate a new random API key on the server / 서버에서 새 랜덤 API 키 생성
$RK -R gateway rotate-key
# → New API key: sk-revkit-xxxxxxxxxxxx
# → Update client configs with the new key
```

After rotation, update all client configs with the new key.

교체 후 모든 클라이언트 설정을 새 키로 업데이트합니다.

---

## 2. IP Restrictions / IP 제한

Restrict gateway access to specific IP addresses or CIDR ranges. Requests from unlisted IPs receive 403.

게이트웨이 접근을 특정 IP 주소 또는 CIDR 범위로 제한합니다. 미등록 IP의 요청은 403을 받습니다.

```json
{
  "gateway": {
    "allowed_ips": ["192.168.50.0/24", "10.0.0.0/8"]
  }
}
```

An empty list allows all IPs.

빈 목록은 모든 IP를 허용합니다.

```json
{
  "gateway": {
    "allowed_ips": []
  }
}
```

### Managing IPs via CLI / CLI로 IP 관리

```bash
# List current allowed IPs / 현재 허용 IP 목록
$RK -R gateway allow-ip list
# → 192.168.50.0/24
# → 10.0.0.0/8

# Add a new range / 새 범위 추가
$RK -R gateway allow-ip add 172.16.0.0/12
# → Added: 172.16.0.0/12

# Remove a range / 범위 제거
$RK -R gateway allow-ip remove 172.16.0.0/12
# → Removed: 172.16.0.0/12
```

Changes take effect immediately without restarting the gateway.

변경 사항은 게이트웨이를 재시작하지 않아도 즉시 적용됩니다.

---

## 3. Exec Control / exec 제어

The `exec` command runs arbitrary code inside IDA/JEB. It has **two independent security levels** that both must be enabled for remote exec to work.

`exec` 명령은 IDA/JEB 내에서 임의 코드를 실행합니다. 원격 exec가 동작하려면 **두 가지 독립적인 보안 레벨** 모두 활성화되어야 합니다.

### Level 1: Gateway Level / 게이트웨이 수준

Blocks the exec RPC at the gateway proxy before it reaches any engine server.

exec RPC가 엔진 서버에 도달하기 전에 게이트웨이 프록시에서 차단합니다.

```json
{
  "gateway": {
    "exec_enabled": false
  }
}
```

### Level 2: Engine Level / 엔진 수준

Blocks exec at the IDA/JEB server itself. Can be set globally or per-engine.

IDA/JEB 서버 자체에서 exec를 차단합니다. 전역 또는 엔진별로 설정 가능.

```json
{
  "security": {
    "exec_enabled": false
  },
  "ida": {
    "security": { "exec_enabled": false }
  },
  "jeb": {
    "security": { "exec_enabled": false }
  }
}
```

### Behavior Matrix / 동작 매트릭스

| Gateway `exec_enabled` | Engine `exec_enabled` | Result / 결과 |
|---|---|---|
| `true` | `true` | exec works / exec 동작 |
| `true` | `false` | blocked at server / 서버에서 차단 |
| `false` | `true` | blocked at gateway / 게이트웨이에서 차단 |
| `false` | `false` | blocked at gateway / 게이트웨이에서 차단 |

```bash
# Test: exec disabled → error / exec 비활성화 → 에러
$RK -R ida exec "print(idc.get_func_name(0x401000))"
# → Error: exec is disabled (security.exec_enabled = false)

# Enable both levels / 두 레벨 모두 활성화
$RK -R gateway config-set gateway.exec_enabled true
$RK -R gateway config-set ida.security.exec_enabled true

# Now exec works / 이제 exec 동작
$RK -R ida exec "print(idc.get_func_name(0x401000))"
# → sub_401000
```

---

## 4. Upload Control / 업로드 제어

Control the maximum file size for remote uploads (binaries, APKs).

원격 업로드(바이너리, APK)의 최대 파일 크기를 제어합니다.

```json
{
  "gateway": {
    "max_upload_size_mb": 500
  }
}
```

| Value / 값 | Behavior / 동작 |
|---|---|
| `500` | Max 500 MB per file / 파일당 최대 500 MB |
| `0` | No size limit / 크기 제한 없음 |
| `null` | Uploads disabled, returns 403 / 업로드 비활성화, 403 반환 |

```bash
# Upload a 200 MB APK (within 500 MB limit) / 200 MB APK 업로드 (500 MB 제한 이내)
$RK -R jeb start /local/path/large-app.apk
# → Uploading large-app.apk (200 MB)... done
# → Instance started: x7k2

# Upload a 600 MB file (exceeds limit) / 600 MB 파일 업로드 (제한 초과)
$RK -R ida start /local/path/huge-binary.exe
# → Error: File size 600 MB exceeds upload limit (500 MB)
```

---

## 5. Health Endpoint / health 엔드포인트

The `/api/v1/health` endpoint is **always public** -- no authentication or IP checks required. This allows load balancers and monitoring tools to probe the gateway.

`/api/v1/health` 엔드포인트는 **항상 공개**입니다 -- 인증이나 IP 검사가 필요 없습니다. 로드 밸런서와 모니터링 도구가 게이트웨이를 탐색할 수 있습니다.

```bash
curl http://SERVER:8080/api/v1/health
# → {"status": "ok"}
```

No sensitive information (API keys, instance details, file paths) is exposed through this endpoint.

이 엔드포인트를 통해 민감한 정보(API 키, 인스턴스 세부 정보, 파일 경로)는 노출되지 않습니다.

---

## Part 2: Multi-Instance Management / 다중 인스턴스 관리

---

## 6. Running Multiple Instances / 여러 인스턴스 실행

revkit supports running multiple IDA and JEB instances simultaneously. Each instance analyzes a different binary/APK.

revkit은 여러 IDA 및 JEB 인스턴스를 동시에 실행할 수 있습니다. 각 인스턴스는 다른 바이너리/APK를 분석합니다.

```bash
# IDA + JEB simultaneously / IDA + JEB 동시 실행
$RK -R ida start notepad.exe
# → Instance started: a3k2 (port 18100)

$RK -R jeb start app.apk --fresh
# → Instance started: b7m4 (port 18200)

# Two IDA instances with different binaries / 다른 바이너리로 IDA 인스턴스 2개
$RK -R ida start notepad.exe
# → Instance started: a3k2 (port 18100)

$RK -R ida start elf-Linux-ARM64-bash
# → Instance started: c9p1 (port 18300)
```

### Listing Instances / 인스턴스 목록

Each engine shows only its own instances. Registries are isolated.

각 엔진은 자신의 인스턴스만 표시합니다. 레지스트리는 격리되어 있습니다.

```bash
# IDA instances only / IDA 인스턴스만
$RK -R ida list
# ID    PID    PORT   BINARY              STATUS
# a3k2  12345  18100  notepad.exe         ready
# c9p1  12347  18300  elf-Linux-ARM64-b.. ready

# JEB instances only / JEB 인스턴스만
$RK -R jeb list
# ID    PID    PORT   BINARY              STATUS
# b7m4  12346  18200  app.apk             ready
```

---

## 7. Instance Selection / 인스턴스 선택

When only one instance exists for an engine, commands auto-select it. When multiple instances exist, you must specify which one with `-i`.

엔진에 인스턴스가 하나만 있으면 명령이 자동으로 선택합니다. 여러 인스턴스가 있으면 `-i`로 지정해야 합니다.

```bash
# One IDA instance → auto-select / IDA 인스턴스 1개 → 자동 선택
$RK -R ida status
# → Instance a3k2: ready (uptime=5m, func_count=1234)

# Multiple IDA instances → must specify / IDA 인스턴스 여러 개 → 지정 필요
$RK -R ida status
# → Error: Multiple ida instances found. Use -i <id> to specify.
# → Available: a3k2, c9p1

$RK -R ida status -i a3k2
# → Instance a3k2: ready (uptime=5m, func_count=1234)

$RK -R ida decompile 0x401000 -i c9p1
# → (decompiled output from elf-Linux-ARM64-bash)
```

### Working with Specific Instances / 특정 인스턴스 작업

The `-i` flag works with all RPC commands (Tier 2 and Tier 3).

`-i` 플래그는 모든 RPC 명령(Tier 2 및 Tier 3)에서 사용 가능합니다.

```bash
# Decompile in instance a3k2 / a3k2 인스턴스에서 디컴파일
$RK -R ida decompile 0x401000 -i a3k2

# Rename in instance c9p1 / c9p1 인스턴스에서 이름 변경
$RK -R ida rename 0x401000 my_function -i c9p1

# JEB decompile in specific instance / 특정 인스턴스에서 JEB 디컴파일
$RK -R jeb decompile "Lcom/example/MainActivity;" -i b7m4
```

---

## 8. Instance Limits / 인스턴스 제한

Control the maximum number of simultaneous instances per engine. This prevents resource exhaustion on the analysis server.

엔진당 최대 동시 인스턴스 수를 제어합니다. 분석 서버의 리소스 고갈을 방지합니다.

```json
{
  "analysis": {
    "max_instances": 3
  }
}
```

```bash
# Three instances running / 3개 인스턴스 실행 중
$RK -R ida list
# ID    PID    PORT   BINARY
# a3k2  12345  18100  notepad.exe
# c9p1  12347  18300  bash
# d2q8  12349  18500  calc.exe

# Attempt to start a fourth → blocked / 네 번째 시작 시도 → 차단
$RK -R ida start sample4.exe
# → Error: Max instances reached (3). Stop an instance first.
```

The limit applies **per engine**. With `max_instances: 3`, you can run 3 IDA instances AND 3 JEB instances simultaneously (6 total).

제한은 **엔진별**로 적용됩니다. `max_instances: 3`이면 IDA 인스턴스 3개와 JEB 인스턴스 3개를 동시에 실행할 수 있습니다 (총 6개).

---

## 9. Cleanup Strategies / 정리 전략

### Stop a Specific Instance / 특정 인스턴스 중지

```bash
$RK -R ida stop -i a3k2
# → Instance a3k2 stopped
```

### Stop All Instances / 모든 인스턴스 중지

Stops all running instances across both engines.

두 엔진의 모든 실행 중인 인스턴스를 중지합니다.

```bash
$RK -R gateway stop-all
# → Stopped: a3k2 (ida), b7m4 (jeb), c9p1 (ida)
# → 3 instances stopped
```

### Clean Stale Registry Entries / 비활성 레지스트리 항목 정리

Removes registry entries for instances whose processes are no longer running. Controlled by `analysis.stale_threshold` (default: 86400 seconds = 24 hours).

프로세스가 더 이상 실행되지 않는 인스턴스의 레지스트리 항목을 제거합니다. `analysis.stale_threshold`로 제어됩니다 (기본값: 86400초 = 24시간).

```bash
$RK -R gateway cleanup
# → Cleaned 2 stale entries (ida: 1, jeb: 1)
```

### Clean Uploaded Files / 업로드된 파일 정리

```bash
# List uploaded files / 업로드된 파일 목록
$RK -R gateway uploads
# → notepad.exe (2.1 MB, uploaded 2h ago)
# → app.apk (45.3 MB, uploaded 1d ago)

# Clean all uploaded files / 모든 업로드 파일 정리
$RK -R gateway uploads-clean
# → Cleaned 2 files (47.4 MB freed)
```

### Full Cleanup / 전체 정리

```bash
# Stop everything, clean uploads, clean stale entries
# 모든 것 중지, 업로드 정리, 비활성 항목 정리
$RK -R gateway stop-all && $RK -R gateway uploads-clean && $RK -R gateway cleanup
```

---

## 10. Cross-Engine Isolation / 엔진 간 격리

IDA and JEB maintain completely separate registries. There is no cross-contamination between engines.

IDA와 JEB는 완전히 별도의 레지스트리를 유지합니다. 엔진 간 교차 오염이 없습니다.

```
~/.revkit/
├── ida/
│   └── registry.json    ← IDA instances only / IDA 인스턴스만
└── jeb/
    └── registry.json    ← JEB instances only / JEB 인스턴스만
```

```bash
# IDA commands only see IDA instances / IDA 명령은 IDA 인스턴스만 표시
$RK -R ida list
# ID    PID    PORT   BINARY
# a3k2  12345  18100  notepad.exe

# JEB commands only see JEB instances / JEB 명령은 JEB 인스턴스만 표시
$RK -R jeb list
# ID    PID    PORT   BINARY
# b7m4  12346  18200  app.apk

# IDA cannot access JEB instance / IDA는 JEB 인스턴스에 접근 불가
$RK -R ida status -i b7m4
# → Error: Instance 'b7m4' not found
```

Each engine instance runs on its own port, its own PID, and its own registry file. This ensures that stopping an IDA instance never affects JEB instances, and vice versa.

각 엔진 인스턴스는 자체 포트, 자체 PID, 자체 레지스트리 파일에서 실행됩니다. IDA 인스턴스를 중지해도 JEB 인스턴스에 영향을 미치지 않으며, 그 반대도 마찬가지입니다.

---

## 11. Putting It All Together / 종합 예제

A production-ready configuration combining security and multi-instance settings.

보안과 다중 인스턴스 설정을 결합한 프로덕션 수준 구성.

```json
{
  "analysis": {
    "max_instances": 3,
    "stale_threshold": 86400
  },
  "security": {
    "exec_enabled": false
  },
  "gateway": {
    "host": "127.0.0.1",
    "port": 8080,
    "api_key": "sk-revkit-prod-a1b2c3d4e5",
    "allowed_ips": ["192.168.50.0/24", "10.0.0.0/8"],
    "trusted_proxies": ["127.0.0.1"],
    "exec_enabled": false,
    "max_upload_size_mb": 500,
    "log_rpc_params": false,
    "audit_max_size_mb": 100
  },
  "ida": {
    "security": { "exec_enabled": false }
  },
  "jeb": {
    "security": { "exec_enabled": false }
  }
}
```

### Typical Workflow / 일반적인 워크플로

```bash
# 1. Start analysis instances / 분석 인스턴스 시작
$RK -R ida start notepad.exe
$RK -R jeb start app.apk --fresh

# 2. Work with each instance / 각 인스턴스 작업
$RK -R ida decompile 0x401000
$RK -R jeb classes

# 3. Start another IDA for comparison / 비교를 위해 다른 IDA 시작
$RK -R ida start patched-notepad.exe

# 4. Compare across instances / 인스턴스 간 비교
$RK -R ida decompile 0x401000 -i a3k2   # original
$RK -R ida decompile 0x401000 -i c9p1   # patched

# 5. Cleanup when done / 완료 후 정리
$RK -R gateway stop-all
$RK -R gateway cleanup
```

---

## 12. Troubleshooting / 문제 해결

| Symptom / 증상 | Cause / 원인 | Fix / 해결 |
|---|---|---|
| 403 on all requests / 모든 요청에 403 | API key mismatch / API 키 불일치 | Verify same `api_key` in server and client configs |
| 403 with correct key / 올바른 키인데 403 | Client IP not in `allowed_ips` / 클라이언트 IP 미등록 | Add client IP/CIDR to `allowed_ips` or set `[]` |
| "Multiple instances, use -i" / "여러 인스턴스, -i 사용" | Multiple instances of same engine / 같은 엔진 인스턴스 다수 | Specify instance with `-i <id>` |
| "Max instances reached" / "최대 인스턴스 도달" | Instance limit hit / 인스턴스 제한 도달 | Stop an instance or increase `max_instances` |
| "Instance not found" / "인스턴스 미발견" | Wrong instance ID or wrong engine / 잘못된 ID 또는 엔진 | Check `ida list` / `jeb list` for valid IDs |
| exec returns permission error / exec 권한 에러 | `exec_enabled: false` at gateway or engine / 게이트웨이 또는 엔진에서 비활성화 | Set both `gateway.exec_enabled` and engine `security.exec_enabled` to `true` |
| Stale instances in list / 목록에 비활성 인스턴스 | Process died but registry not cleaned / 프로세스 종료 후 레지스트리 미정리 | Run `gateway cleanup` or engine-specific `cleanup` |
| Upload rejected / 업로드 거부 | File exceeds `max_upload_size_mb` / 파일 크기 초과 | Increase limit or set `0` for unlimited |

---

**Previous / 이전**: [13-ai-agent-analysis.md](13-ai-agent-analysis.md) -- Automated analysis with Claude Code / Claude Code 자동 분석
