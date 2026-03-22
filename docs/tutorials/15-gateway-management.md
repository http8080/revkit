# Tutorial 15: Gateway Management Commands / Gateway 관리 명령

Monitor, configure, and manage the Gateway server remotely using 16 dedicated gateway subcommands.

Gateway 서버를 16개 전용 gateway 하위 명령으로 원격 모니터링, 설정, 관리합니다.

> **Prerequisites / 사전 준비**:
> - Gateway running on the server (see [12-gateway-setup.md](12-gateway-setup.md))
> - Client configured with `gateway.url` and `gateway.api_key` in `~/.revkit/config.json`
>
> 서버에서 게이트웨이가 실행 중이고, 클라이언트에 `gateway.url` + `gateway.api_key`가 설정되어 있어야 합니다.

```bash
RK="python -m revkit.tools.cli.main"
```

> All gateway commands require remote mode: `$RK -R gateway <command>`
>
> 모든 gateway 명령은 원격 모드가 필요합니다: `$RK -R gateway <command>`

---

## 1. Server Status / 서버 상태

Three commands to inspect the gateway server's health, environment, and disk usage.

게이트웨이 서버의 상태, 환경, 디스크 사용량을 확인하는 세 가지 명령입니다.

### gateway info

Query the gateway's running status, uptime, and active instance count.

게이트웨이의 실행 상태, 가동시간, 활성 인스턴스 수를 조회합니다.

```bash
$RK -R gateway info
# → status: running
# → uptime_sec: 3600
# → total_instances: 2
# → ida_instances: 1
# → jeb_instances: 1
# → gateway_version: 1.0.0
```

### gateway system

Show server-level system information: OS, Python version, hardware specs, and configured tool paths.

서버의 시스템 정보를 표시합니다: OS, Python 버전, 하드웨어 사양, 도구 경로.

```bash
$RK -R gateway system
# → os: Linux 6.17.0-19-generic
# → python: 3.12.3
# → hostname: analysis-server
# → cpu_count: 16
# → ram_total_gb: 64.0
# → ida_dir: /opt/ida
# → jeb_dir: /opt/jeb
```

### gateway disk

Check disk usage for key directories: uploads, logs, and home.

주요 디렉토리의 디스크 사용량을 확인합니다: 업로드, 로그, 홈.

```bash
$RK -R gateway disk
# → upload_dir (~/.revkit/uploads):
# →   total_gb: 500.0, free_gb: 320.5, percent: 35.9%
# → log_dir (~/.revkit/logs):
# →   total_gb: 500.0, free_gb: 320.5, percent: 35.9%
# → home (~):
# →   total_gb: 500.0, free_gb: 320.5, percent: 35.9%
```

---

## 2. Configuration / 설정

View and modify the server configuration remotely. No SSH access required.

원격으로 서버 설정을 조회하고 수정합니다. SSH 접근이 필요 없습니다.

### gateway config (view)

Display the current server configuration. The API key is masked for security.

현재 서버 설정을 표시합니다. API 키는 보안을 위해 마스킹됩니다.

```bash
$RK -R gateway config
# → {
# →   "paths": {"idb_dir": "~/.revkit/ida/idb", ...},
# →   "analysis": {"max_instances": 3, ...},
# →   "gateway": {
# →     "host": "0.0.0.0",
# →     "port": 8080,
# →     "api_key": "sk-****...**** (masked)",
# →     ...
# →   }
# → }
```

### gateway config-set (modify)

Change a specific configuration value on the server. Uses dot-notation for nested keys.

서버의 특정 설정 값을 변경합니다. 중첩 키에 점 표기법을 사용합니다.

```bash
# Increase default output count / 기본 출력 수 증가
$RK -R gateway config-set output.default_count 100
# → Updated output.default_count: 50 -> 100

# Change max instances / 최대 인스턴스 수 변경
$RK -R gateway config-set analysis.max_instances 5
# → Updated analysis.max_instances: 3 -> 5

# Restore original value / 원래 값 복원
$RK -R gateway config-set output.default_count 50
# → Updated output.default_count: 100 -> 50
```

> Config changes take effect via hot-reload within ~2 seconds. No daemon restart required.
>
> 설정 변경은 핫 리로드를 통해 ~2초 내에 적용됩니다. 데몬 재시작 불필요.

---

## 3. Instance Management / 인스턴스 관리

Stop and clean up engine instances across all engines from a single command.

단일 명령으로 모든 엔진의 인스턴스를 중지하고 정리합니다.

### gateway stop-all

Stop all running IDA and JEB instances on the server. Each instance receives a graceful stop signal, then force-kill after timeout.

서버의 모든 실행 중인 IDA 및 JEB 인스턴스를 중지합니다. 각 인스턴스에 graceful 중지 신호를 보내고, 타임아웃 후 강제 종료합니다.

```bash
$RK -R gateway stop-all
# → Stopped: 2 instances (ida: 1, jeb: 1)
```

### gateway cleanup

Remove stale registry entries for instances that are no longer running (crashed, orphaned).

더 이상 실행 중이 아닌 인스턴스(크래시, 고아)의 레지스트리 항목을 제거합니다.

```bash
$RK -R gateway cleanup
# → ida: active=0, cleaned=2
# → jeb: active=0, cleaned=1
```

---

## 4. Upload Management / 업로드 관리

Manage files uploaded to the server for analysis.

분석을 위해 서버에 업로드된 파일을 관리합니다.

### gateway uploads

List all files in the server's upload directory with total size.

서버 업로드 디렉토리의 모든 파일과 총 크기를 나열합니다.

```bash
$RK -R gateway uploads
# → count: 3
# → total_size_mb: 45.2
# → files:
# →   notepad.exe     2.1 MB   2026-03-20 14:30
# →   sample.apk     40.0 MB   2026-03-21 09:15
# →   libcrypto.so    3.1 MB   2026-03-22 08:00
```

### gateway uploads-clean

Delete all files from the upload directory and reclaim disk space.

업로드 디렉토리의 모든 파일을 삭제하고 디스크 공간을 회수합니다.

```bash
$RK -R gateway uploads-clean
# → removed: 3, freed_mb: 45.2
```

### gateway download

Download a file from the server's upload directory to a local path.

서버의 업로드 디렉토리에서 로컬 경로로 파일을 다운로드합니다.

```bash
# Download by filename / 파일명으로 다운로드
$RK -R gateway download notepad.exe --out /tmp/downloaded.exe
# → File saved to /tmp/downloaded.exe (2.1 MB)

# Without --out, saves to current directory / --out 없으면 현재 디렉토리에 저장
$RK -R gateway download sample.apk
# → File saved to ./sample.apk (40.0 MB)
```

---

## 5. Security / 보안

Rotate API keys and manage IP allowlists without editing config files manually.

설정 파일을 직접 편집하지 않고 API 키를 교체하고 IP 허용 목록을 관리합니다.

### gateway rotate-key

Generate a new random API key. The old key is immediately invalidated.

새로운 랜덤 API 키를 생성합니다. 이전 키는 즉시 무효화됩니다.

```bash
$RK -R gateway rotate-key
# → New API key: dGhpcyBpcyBhIHNhbXBsZSBiYXNlNjR1cmwga2V5AA (44 chars, base64url)
# ⚠️ Old key immediately rejected. Update client config!
# ⚠️ 이전 키는 즉시 거부됩니다. 클라이언트 설정을 업데이트하세요!
```

After rotating, update `gateway.api_key` in the client's `~/.revkit/config.json` with the new key. The next command with the old key will fail with 403.

교체 후 클라이언트의 `~/.revkit/config.json`에서 `gateway.api_key`를 새 키로 업데이트하세요. 이전 키로 보내는 다음 명령은 403으로 실패합니다.

### gateway allow-ip list

Show the current IP allowlist.

현재 IP 허용 목록을 표시합니다.

```bash
$RK -R gateway allow-ip list
# → allowed_ips:
# →   192.168.50.0/24
```

An empty list means all IPs are allowed.

빈 목록은 모든 IP가 허용됨을 의미합니다.

### gateway allow-ip add

Add an IP address or CIDR range to the allowlist.

허용 목록에 IP 주소 또는 CIDR 범위를 추가합니다.

```bash
$RK -R gateway allow-ip add 10.0.0.0/8
# → Added 10.0.0.0/8
# → allowed_ips: ["192.168.50.0/24", "10.0.0.0/8"]
```

### gateway allow-ip remove

Remove an IP address or CIDR range from the allowlist.

허용 목록에서 IP 주소 또는 CIDR 범위를 제거합니다.

```bash
$RK -R gateway allow-ip remove 10.0.0.0/8
# → Removed 10.0.0.0/8
# → allowed_ips: ["192.168.50.0/24"]
```

---

## 6. Monitoring / 모니터링

Inspect audit logs, connection history, instance logs, and analysis progress.

감사 로그, 연결 기록, 인스턴스 로그, 분석 진행률을 검사합니다.

### gateway audit

View recent audit log entries. Each entry records a gateway request with timestamp, method, path, and status.

최근 감사 로그 항목을 조회합니다. 각 항목은 타임스탬프, 메서드, 경로, 상태를 기록합니다.

```bash
$RK -R gateway audit --tail 10
# → 2026-03-22 10:30:00  POST  /api/v1/rpc/ida  decompile    200  245ms
# → 2026-03-22 10:30:05  POST  /api/v1/rpc/ida  rename       200   52ms
# → 2026-03-22 10:31:00  POST  /api/v1/rpc/jeb  classes      200  180ms
# → ...
```

### gateway connections

View recent client connections with IP addresses and request details.

IP 주소 및 요청 세부 정보와 함께 최근 클라이언트 연결을 조회합니다.

```bash
$RK -R gateway connections --tail 10
# → 2026-03-22 10:30:00  192.168.50.10  POST  /api/v1/rpc/ida   200
# → 2026-03-22 10:30:05  192.168.50.10  POST  /api/v1/rpc/ida   200
# → 2026-03-22 10:31:00  192.168.50.20  POST  /api/v1/rpc/jeb   200
# → 2026-03-22 10:32:00  10.0.0.5       GET   /api/v1/health    200
# → ...
```

### gateway logs (instance-specific)

Retrieve log entries for a specific engine instance running on the server.

서버에서 실행 중인 특정 엔진 인스턴스의 로그 항목을 가져옵니다.

```bash
# Get instance ID first / 먼저 인스턴스 ID 확인
$RK -R ida list
# → a3k2  ida  notepad.exe  running  :18100

# View instance logs / 인스턴스 로그 조회
$RK -R gateway logs -i a3k2 --tail 10
# → 2026-03-22 10:29:55  [INFO]  Server started on port 18100
# → 2026-03-22 10:30:00  [INFO]  RPC: decompile addr=0x401000
# → 2026-03-22 10:30:00  [INFO]  Decompiled 0x401000 (245ms)
# → ...
```

### gateway progress

Check the analysis progress of a specific instance. Useful for long-running operations like `decompile-all`.

특정 인스턴스의 분석 진행률을 확인합니다. `decompile-all` 같은 장기 실행 작업에 유용합니다.

```bash
$RK -R gateway progress -i a3k2
# → instance: a3k2
# → state: analyzing
# → progress: 45%
# → current: decompile-all (2340/5200 functions)

# When idle / 유휴 상태일 때
$RK -R gateway progress -i a3k2
# → instance: a3k2
# → state: ready
```

---

## 7. Common Workflows / 일반적인 워크플로우

### Daily Cleanup / 일일 정리

Stop all instances, clean uploads, and remove stale registry entries.

모든 인스턴스를 중지하고, 업로드를 정리하고, 비활성 레지스트리 항목을 제거합니다.

```bash
$RK -R gateway stop-all
# → Stopped: 2 instances (ida: 1, jeb: 1)

$RK -R gateway uploads-clean
# → removed: 3, freed_mb: 45.2

$RK -R gateway cleanup
# → ida: active=0, cleaned=2
# → jeb: active=0, cleaned=1
```

### Security Audit / 보안 감사

Review recent activity, connections, and access controls.

최근 활동, 연결, 접근 제어를 검토합니다.

```bash
# Check recent requests / 최근 요청 확인
$RK -R gateway audit --tail 100

# Review connection sources / 연결 소스 검토
$RK -R gateway connections --tail 50

# Verify IP allowlist / IP 허용 목록 확인
$RK -R gateway allow-ip list
# → allowed_ips: ["192.168.50.0/24"]
```

### API Key Rotation / API 키 교체

Rotate the key and update the client configuration.

키를 교체하고 클라이언트 설정을 업데이트합니다.

```bash
# Step 1: Rotate on server / 서버에서 교체
$RK -R gateway rotate-key
# → New API key: dGhpcyBpcyBhIHNhbXBsZSBiYXNlNjR1cmwga2V5AA

# Step 2: Update client config / 클라이언트 설정 업데이트
# Edit ~/.revkit/config.json:
#   "gateway": { "api_key": "dGhpcyBpcyBhIHNhbXBsZSBiYXNlNjR1cmwga2V5AA" }

# Step 3: Verify / 확인
$RK -R gateway info
# → status: running (auth OK)
```

### Server Health Check / 서버 상태 점검

Quick overview of server health before starting work.

작업 시작 전 서버 상태 빠른 확인.

```bash
$RK -R gateway info && \
$RK -R gateway system && \
$RK -R gateway disk
```

---

## 8. Command Reference / 명령 참조

All 16 gateway management commands at a glance.

16개 gateway 관리 명령 요약.

| # | Command / 명령 | Description / 설명 |
|---|---|---|
| 1 | `gateway info` | Server status, uptime, instance count / 서버 상태, 가동시간, 인스턴스 수 |
| 2 | `gateway system` | OS, Python, hardware, tool paths / OS, Python, 하드웨어, 도구 경로 |
| 3 | `gateway disk` | Disk usage for key directories / 주요 디렉토리 디스크 사용량 |
| 4 | `gateway config` | View server config (API key masked) / 서버 설정 조회 (API 키 마스킹) |
| 5 | `gateway config-set` | Modify config value (hot-reload) / 설정 값 변경 (핫 리로드) |
| 6 | `gateway stop-all` | Stop all IDA/JEB instances / 모든 IDA/JEB 인스턴스 중지 |
| 7 | `gateway cleanup` | Remove stale registry entries / 비활성 레지스트리 항목 제거 |
| 8 | `gateway uploads` | List uploaded files / 업로드된 파일 목록 |
| 9 | `gateway uploads-clean` | Delete all uploads / 모든 업로드 삭제 |
| 10 | `gateway download` | Download file from server / 서버에서 파일 다운로드 |
| 11 | `gateway rotate-key` | Generate new API key / 새 API 키 생성 |
| 12 | `gateway allow-ip list` | Show IP allowlist / IP 허용 목록 표시 |
| 13 | `gateway allow-ip add` | Add IP/CIDR to allowlist / 허용 목록에 IP/CIDR 추가 |
| 14 | `gateway allow-ip remove` | Remove IP/CIDR from allowlist / 허용 목록에서 IP/CIDR 제거 |
| 15 | `gateway audit` | View audit log entries / 감사 로그 항목 조회 |
| 16 | `gateway connections` | View recent connections / 최근 연결 조회 |

Additional instance-scoped commands (used with `-i INSTANCE_ID`):

인스턴스 범위 추가 명령 (`-i INSTANCE_ID`와 함께 사용):

| Command / 명령 | Description / 설명 |
|---|---|
| `gateway logs -i ID` | Instance log entries / 인스턴스 로그 항목 |
| `gateway progress -i ID` | Analysis progress / 분석 진행률 |

---

## 9. Notes / 참고사항

- **Remote mode required**: `gateway` commands only work with `-R` or `--remote`. Running `$RK gateway info` locally produces an error.

  원격 모드 필수: `gateway` 명령은 `-R` 또는 `--remote`에서만 작동합니다. 로컬에서 실행하면 에러가 발생합니다.

- **No auth mode**: Setting `gateway.api_key` to `null` disables authentication entirely. Not recommended for production.

  인증 없음 모드: `gateway.api_key`를 `null`로 설정하면 인증이 완전히 비활성화됩니다. 프로덕션에서는 권장하지 않습니다.

- **Hot-reload**: Config changes via `config-set` take effect within ~2 seconds without restarting the daemon.

  핫 리로드: `config-set`을 통한 설정 변경은 데몬을 재시작하지 않고 ~2초 내에 적용됩니다.

- **Key rotation**: `rotate-key` immediately invalidates the old key. Ensure you save the new key before the current session ends.

  키 교체: `rotate-key`는 이전 키를 즉시 무효화합니다. 현재 세션이 끝나기 전에 새 키를 저장하세요.

- **IP allowlist**: An empty `allowed_ips` list (`[]`) means all IPs are permitted. Adding any entry restricts access to listed IPs only.

  IP 허용 목록: 빈 `allowed_ips` 목록(`[]`)은 모든 IP가 허용됨을 의미합니다. 항목을 추가하면 나열된 IP만 접근 가능합니다.

---

**Previous / 이전**: [12-gateway-setup.md](12-gateway-setup.md) — Gateway deployment and configuration / Gateway 배포 및 설정
