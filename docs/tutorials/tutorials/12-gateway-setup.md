# Tutorial 12: Gateway Deployment / Gateway 배포

Deploy the revkit API gateway for remote access. Enables team collaboration and CI/CD integration from any machine.

원격 접근을 위해 revkit API 게이트웨이를 배포합니다. 어떤 머신에서든 팀 협업과 CI/CD 통합이 가능합니다.

> **Prerequisites / 사전 준비**: revkit installed on the server machine / 서버 머신에 revkit 설치 완료

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. Architecture / 아키텍처

The gateway sits between remote clients and local IDA/JEB instances. It proxies RPC calls, handles auth, and manages file uploads.

게이트웨이는 원격 클라이언트와 로컬 IDA/JEB 인스턴스 사이에 위치합니다. RPC 호출을 프록시하고, 인증을 처리하며, 파일 업로드를 관리합니다.

```
Remote Client          Gateway Server          IDA/JEB Instances
─────────────         ─────────────────        ──────────────────
$RK --remote ───HTTP──> :8080 gateway ──RPC──> :18100 IDA server
                        │ auth                  :18200 JEB server
                        │ upload                :18300 IDA server
                        │ audit log             ...
```

---

## 2. Server Configuration / 서버 설정

Edit `~/.revkit/config.json` on the **server** machine.

**서버** 머신에서 `~/.revkit/config.json`을 편집합니다.

```json
{
  "gateway": {
    "host": "0.0.0.0",
    "port": 8080,
    "api_key": "your-secret-api-key-here",
    "allowed_ips": [],
    "trusted_proxies": [],
    "max_upload_size_mb": 500,
    "upload_dir": "~/.revkit/uploads",
    "request_timeout": 60,
    "batch_timeout": 300,
    "log_rpc_params": false,
    "audit_path": "~/.revkit/logs/gateway/audit.jsonl",
    "audit_max_size_mb": 100
  }
}
```

### Key Settings / 주요 설정

| Setting / 설정 | Default / 기본값 | Description / 설명 |
|---|---|---|
| `host` | `0.0.0.0` | Bind address. `0.0.0.0` for all interfaces / 바인드 주소. 모든 인터페이스 |
| `port` | `8080` | Gateway listen port / 게이트웨이 리슨 포트 |
| `api_key` | `null` | API key for auth. `null` = no auth / 인증용 API 키. `null` = 인증 없음 |
| `allowed_ips` | `[]` | IP allowlist. `[]` = allow all / IP 허용 목록. `[]` = 모두 허용 |
| `trusted_proxies` | `[]` | Reverse proxy IPs for X-Forwarded-For / 리버스 프록시 IP |
| `max_upload_size_mb` | `500` | Max upload file size / 최대 업로드 파일 크기 |
| `request_timeout` | `60` | Single request timeout (seconds) / 단일 요청 타임아웃 (초) |
| `batch_timeout` | `300` | Batch operation timeout (seconds) / 배치 작업 타임아웃 (초) |

---

## 3. Starting the Gateway Daemon / 게이트웨이 데몬 시작

```bash
# Start the gateway daemon / 게이트웨이 데몬 시작
python -m revkit.tools.gateway.daemon --config ~/.revkit/config.json &
# → Gateway started on 0.0.0.0:8080

# Check health / 상태 확인
curl http://127.0.0.1:8080/api/v1/health
# → {"status": "ok", ...}

# Or use remote CLI to query gateway info / 원격 CLI로 게이트웨이 정보 조회
$RK -R gateway info
# → Gateway running on 0.0.0.0:8080 (uptime=5m)

# Stop the daemon / 데몬 중지
kill $(pgrep -f "revkit.tools.gateway")
# Or stop all instances via remote CLI / 원격 CLI로 모든 인스턴스 중지
$RK -R gateway stop-all
```

The gateway runs as a background daemon process. There is no `gateway start` CLI command — the daemon is started directly with Python.

게이트웨이는 백그라운드 데몬 프로세스로 실행됩니다. `gateway start` CLI 명령은 없으며, 데몬은 Python으로 직접 시작합니다.

---

## 4. Client Configuration / 클라이언트 설정

On the **client** machine, set `gateway.url` in `~/.revkit/config.json`.

**클라이언트** 머신에서 `~/.revkit/config.json`에 `gateway.url`을 설정합니다.

```json
{
  "gateway": {
    "url": "http://analysis-server:8080",
    "api_key": "your-secret-api-key-here"
  }
}
```

Once configured, all CLI commands automatically route through the gateway. No command changes needed.

설정이 완료되면 모든 CLI 명령이 자동으로 게이트웨이를 통해 라우팅됩니다. 명령 변경이 필요 없습니다.

```bash
# These now go through the gateway / 이제 게이트웨이를 통해 전달
$RK ida list
$RK jeb start sample.apk
$RK ida decompile 0x401000
```

### One-time Remote Override / 일회성 원격 오버라이드

Use `--remote` (or `-R` shorthand) to connect to a specific server without changing config.

설정을 변경하지 않고 특정 서버에 연결하려면 `--remote` (또는 `-R` 단축키)를 사용합니다.

```bash
# Connect to a specific server / 특정 서버에 연결
$RK --remote http://other-server:8080 ida list

# Use -R shorthand (reads gateway.url from config) / -R 단축키 (config의 gateway.url 사용)
$RK -R ida list

# Priority: --remote URL > -R (config url) > config gateway.url > local mode
# 우선순위: --remote URL > -R (config url) > config gateway.url > 로컬 모드
```

---

## 5. Authentication / 인증

### API Key / API 키

The simplest auth method. Set the same `api_key` on server and client configs.

가장 간단한 인증 방법. 서버와 클라이언트 설정에 동일한 `api_key`를 설정합니다.

```json
// Server config / 서버 설정
{"gateway": {"api_key": "sk-revkit-prod-a1b2c3d4e5"}}

// Client config / 클라이언트 설정
{"gateway": {"api_key": "sk-revkit-prod-a1b2c3d4e5"}}
```

The client sends the API key in the `Authorization: Bearer <key>` header automatically.

클라이언트가 `Authorization: Bearer <key>` 헤더에 API 키를 자동으로 전송합니다.

### IP Allowlist / IP 허용 목록

Restrict access to specific IP addresses or CIDR ranges.

특정 IP 주소 또는 CIDR 범위로 접근을 제한합니다.

```json
{
  "gateway": {
    "allowed_ips": [
      "192.168.1.0/24",
      "10.0.0.5",
      "203.0.113.42"
    ]
  }
}
```

An empty list (`[]`) means all IPs are allowed. When populated, requests from unlisted IPs are rejected with 403.

빈 목록(`[]`)은 모든 IP가 허용됨을 의미합니다. 목록이 설정되면 미등록 IP의 요청은 403으로 거부됩니다.

---

## 6. Reverse Proxy Setup / 리버스 프록시 설정

For production, place the gateway behind nginx or similar.

프로덕션 환경에서는 nginx 등의 뒤에 게이트웨이를 배치합니다.

```nginx
# /etc/nginx/sites-available/revkit
server {
    listen 443 ssl;
    server_name revkit.example.com;

    ssl_certificate     /etc/ssl/certs/revkit.pem;
    ssl_certificate_key /etc/ssl/private/revkit.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 300s;

        # Upload size limit / 업로드 크기 제한
        client_max_body_size 500M;
    }
}
```

Configure `trusted_proxies` so the gateway correctly resolves client IPs from `X-Forwarded-For`.

게이트웨이가 `X-Forwarded-For`에서 클라이언트 IP를 올바르게 해석하도록 `trusted_proxies`를 설정합니다.

```json
{
  "gateway": {
    "host": "127.0.0.1",
    "trusted_proxies": ["127.0.0.1"]
  }
}
```

---

## 7. File Upload / 파일 업로드

Remote clients can upload binaries/APKs for analysis. The gateway stores them in `upload_dir`.

원격 클라이언트가 분석을 위해 바이너리/APK를 업로드할 수 있습니다. 게이트웨이가 `upload_dir`에 저장합니다.

```bash
# Upload and start analysis / 업로드 후 분석 시작
$RK --remote http://server:8080 ida start /local/path/to/binary.exe
# The CLI uploads the file, then the server starts analysis
# CLI가 파일을 업로드한 후 서버가 분석을 시작합니다

# Size limit / 크기 제한
# Controlled by gateway.max_upload_size_mb (default: 500 MB)
```

---

## 8. Audit Logging / 감사 로깅

All gateway requests are logged to `audit_path` in JSONL format. This is separate from engine logs.

모든 게이트웨이 요청이 JSONL 형식으로 `audit_path`에 기록됩니다. 엔진 로그와는 별도입니다.

```bash
# View recent audit entries / 최근 감사 항목 확인
tail -5 ~/.revkit/logs/gateway/audit.jsonl | jq .
```

```json
{
  "timestamp": "2026-03-22T10:30:00Z",
  "client_ip": "192.168.1.100",
  "method": "decompile",
  "engine": "ida",
  "instance_id": "a3k2",
  "status": "success",
  "duration_ms": 245
}
```

### Controlling Audit Detail / 감사 상세 제어

```json
{
  "gateway": {
    "log_rpc_params": false,
    "audit_max_size_mb": 100
  }
}
```

- `log_rpc_params: true` — includes full RPC parameters in audit (may contain sensitive data) / 감사에 전체 RPC 매개변수 포함 (민감 데이터 포함 가능)
- `audit_max_size_mb` — max audit log size before rotation / 로테이션 전 최대 감사 로그 크기

---

## 9. Security Checklist / 보안 체크리스트

Before exposing the gateway to a network, review this checklist.

게이트웨이를 네트워크에 노출하기 전에 이 체크리스트를 검토하세요.

### Required / 필수

- [ ] **Set an API key** — `gateway.api_key` must not be `null` in production / 프로덕션에서 `null`이면 안 됨
- [ ] **Use HTTPS** — deploy behind a TLS-terminating reverse proxy / TLS 종료 리버스 프록시 뒤에 배포
- [ ] **Restrict IPs** — set `allowed_ips` to known client ranges / 알려진 클라이언트 범위로 설정
- [ ] **Disable exec** — there are TWO levels: `gateway.exec_enabled` (gateway-level, blocks exec at the proxy) and `security.exec_enabled` or `ida.security.exec_enabled`/`jeb.security.exec_enabled` (engine-level, blocks exec at the server). Set both to `false` unless needed / 게이트웨이 수준(`gateway.exec_enabled`)과 엔진 수준(`security.exec_enabled`, `ida.security.exec_enabled`/`jeb.security.exec_enabled`) 두 가지가 있습니다. 필요하지 않으면 둘 다 `false`

### Recommended / 권장

- [ ] **Bind to localhost** — set `host: "127.0.0.1"` behind reverse proxy / 리버스 프록시 뒤에서 localhost 바인드
- [ ] **Set trusted_proxies** — for correct client IP resolution / 올바른 클라이언트 IP 해석
- [ ] **Limit upload size** — `max_upload_size_mb` appropriate for your use case / 사용 사례에 적합하게 설정
- [ ] **Enable audit logging** — `audit_path` configured and monitored / 설정 및 모니터링
- [ ] **Rotate audit logs** — `audit_max_size_mb` prevents disk exhaustion / 디스크 고갈 방지
- [ ] **Firewall rules** — restrict gateway port at the OS/network level / OS/네트워크 수준에서 포트 제한
- [ ] **Separate auth per engine** — `ida.security` and `jeb.security` can override global / 엔진별 보안 설정 가능

---

## 10. Gateway Management Commands / 게이트웨이 관리 명령

When connected to a remote gateway (via `-R` or `--remote`), you can manage the server with `gateway` subcommands.

원격 게이트웨이에 연결된 상태(`-R` 또는 `--remote`)에서 `gateway` 하위 명령으로 서버를 관리할 수 있습니다.

```bash
$RK -R gateway info              # Gateway status + uptime / 상태 + 가동시간
$RK -R gateway config            # Show server config / 서버 설정 조회
$RK -R gateway config-set KEY VAL # Set config key / 설정 변경
$RK -R gateway stop-all          # Stop all engine instances / 모든 엔진 인스턴스 중지
$RK -R gateway uploads           # List uploaded files / 업로드된 파일 목록
$RK -R gateway uploads-clean     # Clean upload directory / 업로드 디렉토리 정리
$RK -R gateway audit             # View audit log / 감사 로그 조회
$RK -R gateway system            # Server system info / 서버 시스템 정보
$RK -R gateway disk              # Disk usage / 디스크 사용량
$RK -R gateway cleanup           # Clean stale instances / 비활성 인스턴스 정리
$RK -R gateway rotate-key        # Generate new API key / 새 API 키 생성
$RK -R gateway allow-ip          # Manage allowed IPs / 허용 IP 관리
$RK -R gateway connections       # Recent connections / 최근 연결 목록
$RK -R gateway download          # Download file from server / 서버에서 파일 다운로드
$RK -R gateway logs              # Instance logs / 인스턴스 로그
$RK -R gateway progress          # Analysis progress / 분석 진행률
```

---

## 11. Troubleshooting / 문제 해결

| Symptom / 증상 | Cause / 원인 | Fix / 해결 |
|---|---|---|
| Connection refused / 연결 거부 | Gateway not running / 게이트웨이 미실행 | `python -m revkit.tools.gateway.daemon --config ~/.revkit/config.json &` |
| 403 Forbidden | Wrong API key or IP blocked / 잘못된 API 키 또는 IP 차단 | Check `api_key` and `allowed_ips` |
| 413 Payload Too Large | File exceeds upload limit / 파일 크기 초과 | Increase `max_upload_size_mb` |
| Timeout on batch / 배치 타임아웃 | `batch_timeout` too low / 너무 낮음 | Increase `batch_timeout` |
| X-Forwarded-For ignored | Proxy not in `trusted_proxies` / 프록시 미등록 | Add proxy IP to `trusted_proxies` |
| `exec` returns permission error | `exec_enabled: false` | Set `gateway.exec_enabled: true` (gateway-level) AND `security.exec_enabled: true` or engine-specific `ida.security.exec_enabled`/`jeb.security.exec_enabled: true` |

---

**Next / 다음**: [13-ai-agent-analysis.md](13-ai-agent-analysis.md) — Automated analysis with Claude Code / Claude Code 자동 분석
