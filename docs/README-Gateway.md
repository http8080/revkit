# Gateway 레퍼런스

> revkit Gateway — CLI ↔ 엔진 서버 간 HTTP 프록시 + 관리 API.
> 원격 분석, 파일 업로드, 인증, 인스턴스 관리를 담당.

---

## Table of Contents

- [1. 아키텍처](#1-아키텍처)
- [2. 데몬 시작/종료](#2-데몬-시작종료)
- [3. REST API 엔드포인트](#3-rest-api-엔드포인트)
- [4. CLI 관리 명령](#4-cli-관리-명령-revkit--r-gateway-)
- [5. config.json gateway 섹션](#5-configjson-gateway-섹션)
- [6. RPC 프록시 동작](#6-rpc-프록시-동작)
- [7. 파일 업로드 흐름](#7-파일-업로드-흐름)
- [8. 인증 시스템](#8-인증-시스템)
- [9. Config Hot-Reload](#9-config-hot-reload)
- [10. 감사 로깅](#10-감사-로깅)
- [11. 주의사항](#11-주의사항)

---

## 1. 아키텍처

```
클라이언트 (revkit -R)          Gateway (:8080)              엔진 서버 (:random)
┌──────────────┐              ┌──────────────┐              ┌──────────────┐
│  revkit CLI  │──── HTTP ───→│ ThreadingHTTP│──── HTTP ───→│ IDA / JEB    │
│  -R / --remote              │   Server     │   JSON-RPC   │   RPC Server │
│              │←── JSON ────│              │←── JSON ────│              │
└──────────────┘              └──────────────┘              └──────────────┘
                                    │
                                    ├── 인증 (API key + IP 화이트리스트)
                                    ├── 감사 로깅 (JSONL)
                                    ├── Config hot-reload (2초 간격)
                                    └── 파일 업로드 (multipart/form-data)
```

**핵심 구성 요소:**

| 모듈 | 역할 |
|------|------|
| `gateway/daemon.py` | `GatewayDaemon` (ThreadingHTTPServer 상속), `ConfigWatcher`, `run_gateway()` |
| `gateway/router.py` | URL 패턴 매칭 → 핸들러 디스패치 (22개 라우트) |
| `gateway/auth.py` | API key 검증 (timing-safe), IP 화이트리스트 (CIDR), X-Forwarded-For |
| `gateway/upload.py` | multipart 파싱, UUID 파일명, atomic write, 디스크 공간 체크 |
| `gateway/audit.py` | JSONL 감사 로그, 스레드 안전, 크기 초과 시 아카이브 회전 |
| `gateway/config.py` | `GATEWAY_DEFAULTS`, `load_gateway_config()`, `validate_gateway_config()` |
| `cli/remote.py` | 클라이언트 측: `upload_binary()`, `post_rpc_remote()`, `remote_start()`, `remote_list()` |

**요청 처리 흐름:**

1. `GatewayHandler._handle()` 진입
2. `/api/v1/health` 이외 경로 → `authenticate()` (API key + IP 체크)
3. `route_request()` → `COMPILED_ROUTES` 패턴 매칭 → 핸들러 함수 호출
4. 감사 로그 기록 (`_audit()`)

---

## 2. 데몬 시작/종료

### 시작

```bash
# 직접 실행
python -m revkit.tools.gateway.daemon --config ~/.revkit/config.json

# 백그라운드 실행
python -m revkit.tools.gateway.daemon --config ~/.revkit/config.json &
```

시작 시 출력:
```
2026-03-22 14:00:00 [INFO] revkit.gateway: Gateway listening on 0.0.0.0:8080
2026-03-22 14:00:00 [INFO] revkit.gateway: Config watcher started (checking every 2.0s)
```

### 종료

```bash
# SIGTERM / SIGINT → graceful shutdown
kill $(pgrep -f "revkit.tools.gateway")

# 또는 Ctrl+C (포그라운드)
```

종료 시 동작:
1. `SIGTERM` / `SIGINT` / `SIGBREAK` (Windows) 수신
2. ConfigWatcher 중지
3. `ThreadingHTTPServer.shutdown()` → 진행 중 요청 완료 대기
4. 로그: `"Gateway stopped."`

### 포트 충돌

바인드 실패 시 명확한 에러 출력 후 `sys.exit(1)`:
```
ERROR: Cannot bind to 0.0.0.0:8080 - [Errno 98] Address already in use
```

---

## 3. REST API 엔드포인트

### 공개 (인증 불필요)

| Method | Path | 설명 |
|--------|------|------|
| `GET` | `/api/v1/health` | 헬스체크 |

```bash
curl http://server:8080/api/v1/health
```
```json
{"status": "ok", "service": "revkit-gateway", "timestamp": 1711094400.0}
```

### 인스턴스 관리 (인증 필요)

| Method | Path | 설명 |
|--------|------|------|
| `GET` | `/api/v1/instances` | 전체 인스턴스 목록 (IDA + JEB) |
| `POST` | `/api/v1/engines/{engine}/start` | 인스턴스 시작 (`ida` 또는 `jeb`) |
| `POST` | `/api/v1/instances/{id}/rpc` | RPC 프록시 (JSON-RPC 중계) |
| `DELETE` | `/api/v1/instances/{id}` | 인스턴스 삭제 + 프로세스 종료 |

**인스턴스 목록:**
```bash
curl -H "Authorization: Bearer YOUR_KEY" http://server:8080/api/v1/instances
```
```json
{
  "instances": [
    {"id": "abc123", "engine": "jeb", "port": 18300, "pid": 12345,
     "binary": "sample.apk", "state": "ready"}
  ]
}
```

**인스턴스 시작:**
```bash
curl -X POST -H "Authorization: Bearer KEY" \
     -H "Content-Type: application/json" \
     -d '{"file_id": "a1b2c3d4...", "original_name": "sample.apk"}' \
     http://server:8080/api/v1/engines/jeb/start
```

시작 파라미터:
- `file_id` (필수): 업로드된 파일 ID
- `original_name` (선택): 원본 파일명
- `fresh` (선택): `true` → 캐시 DB 무시
- `force` (선택): `true` → 기존 인스턴스 무시 강제 시작
- `xmx` (선택): JVM 힙 크기 (JEB 전용, 예: `"8G"`)

```json
{
  "instance_id": "abc123",
  "engine": "jeb",
  "file_id": "a1b2c3d4...",
  "output": "Started JEB server (id=abc123, port=18300, pid=12345)"
}
```

**RPC 프록시:**
```bash
curl -X POST -H "Authorization: Bearer KEY" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"decompile","params":{"sig":"Lcom/example/Main;"},"id":1}' \
     http://server:8080/api/v1/instances/abc123/rpc
```

**인스턴스 삭제:**
```bash
curl -X DELETE -H "Authorization: Bearer KEY" \
     http://server:8080/api/v1/instances/abc123
```

삭제 시 동작 순서:
1. `save_db` RPC 전송 (실패 무시)
2. `stop` RPC 전송 (실패 무시)
3. 프로세스 생존 확인 → 0.5초 후 `force_kill` (백그라운드 스레드)
4. 레지스트리에서 제거

### 파일 업로드

| Method | Path | 설명 |
|--------|------|------|
| `POST` | `/api/v1/upload` | 바이너리 파일 업로드 (multipart/form-data) |
| `GET` | `/api/v1/upload-progress/{id}` | 업로드 진행률 (미구현) |

```bash
curl -X POST -H "Authorization: Bearer KEY" \
     -F "file=@sample.apk" \
     http://server:8080/api/v1/upload
```
```json
{
  "file_id": "a1b2c3d4e5f6...",
  "original_name": "sample.apk",
  "size": 15728640,
  "path": "/home/user/.revkit/uploads/a1b2c3d4e5f6..."
}
```

### Gateway 관리 엔드포인트

| Method | Path | 핸들러 | 설명 |
|--------|------|--------|------|
| `GET` | `/api/v1/gateway/info` | `handle_gateway_info` | 상태, uptime, 인스턴스 수 |
| `GET` | `/api/v1/gateway/config` | `handle_gateway_config` | 설정 조회 (민감 정보 마스킹) |
| `POST` | `/api/v1/gateway/config` | `handle_gateway_config_set` | 설정 변경 (key-value) |
| `POST` | `/api/v1/gateway/stop-all` | `handle_stop_all` | 전체 인스턴스 정지 |
| `GET` | `/api/v1/gateway/uploads` | `handle_gateway_uploads` | 업로드 디렉토리 파일 목록 |
| `DELETE` | `/api/v1/gateway/uploads` | `handle_gateway_uploads_clean` | 업로드 파일 전체 삭제 |
| `GET` | `/api/v1/gateway/audit` | `handle_gateway_audit` | 감사 로그 조회 (`?tail=N`) |
| `GET` | `/api/v1/gateway/system` | `handle_gateway_system` | OS, Python, CPU, RAM 정보 |
| `GET` | `/api/v1/gateway/disk` | `handle_gateway_disk` | 디스크 사용량 |
| `POST` | `/api/v1/gateway/cleanup` | `handle_gateway_cleanup` | stale 레지스트리 정리 |
| `POST` | `/api/v1/gateway/rotate-key` | `handle_gateway_rotate_key` | API 키 재생성 |
| `POST` | `/api/v1/gateway/allow-ip` | `handle_gateway_allow_ip` | IP 화이트리스트 관리 |
| `GET` | `/api/v1/gateway/connections` | `handle_gateway_connections` | 최근 연결 기록 (`?tail=N`) |
| `GET` | `/api/v1/gateway/download/{id}` | `handle_gateway_download` | 파일 다운로드 |
| `GET` | `/api/v1/instances/{id}/logs` | `handle_instance_logs` | 인스턴스 로그 조회 (`?tail=N`) |
| `GET` | `/api/v1/instances/{id}/progress` | `handle_instance_progress` | 분석 진행률 |

**Gateway Info:**
```json
{
  "status": "running",
  "host": "0.0.0.0",
  "port": 8080,
  "uptime_sec": 3600.5,
  "instances": {"ida": 1, "jeb": 2},
  "total_instances": 3,
  "api_key_set": true,
  "exec_enabled": false,
  "upload_limit_mb": 500,
  "platform": "Linux"
}
```

**System Info:**
```json
{
  "os": "Linux",
  "os_version": "6.17.0-19-generic",
  "arch": "x86_64",
  "python": "3.12.0",
  "hostname": "analysis-server",
  "revkit_version": "1.0.0",
  "cpu_count": 16,
  "cpu_percent": 23.5,
  "ram_total_gb": 64.0,
  "ram_used_gb": 12.3,
  "ram_percent": 19.2,
  "ida_dir": "/opt/ida",
  "jeb_dir": "/opt/jeb"
}
```

**Config Set:**
```bash
# POST 본문
{"key": "gateway.port", "value": 9090}
# 중첩 키 지원: "gateway.port" → config["gateway"]["port"]
```

차단된 키: `security.auth_token_file` (원격 변경 불가)

**Allow IP:**
```bash
# POST 본문
{"action": "add", "ip": "192.168.1.0/24"}     # 추가
{"action": "remove", "ip": "192.168.1.0/24"}  # 제거
{"action": "list"}                              # 조회
```

**Download:**

uploads, idb_dir, project_dir, output_dir 디렉토리를 순서대로 탐색. 파일명에 `{id}` 패턴이 포함된 파일을 `rglob`으로 검색.

응답: `Content-Disposition: attachment; filename="..."` 헤더와 함께 바이너리 스트림.

---

## 4. CLI 관리 명령 (revkit -R gateway ...)

Gateway 관리 명령은 반드시 원격 모드(`-R` 또는 `--remote`)로 실행해야 한다.

```bash
# 기본 (config.json의 gateway.url 사용)
revkit -R gateway info

# URL 직접 지정
revkit --remote http://server:8080 gateway info

# API 키 지정
revkit -R --api-key "YOUR_KEY" gateway info
```

### 16개 서브커맨드

#### `info` -- Gateway 상태 + uptime

```bash
revkit -R gateway info
```
```
  status: running
  host: 0.0.0.0
  port: 8080
  uptime_sec: 3600.5
  instances: {'ida': 1, 'jeb': 2}
  total_instances: 3
  api_key_set: True
  exec_enabled: False
```

#### `config` -- 서버 설정 조회

```bash
revkit -R gateway config
```

전체 `config.json`을 JSON으로 출력. 민감 정보는 마스킹:
- `gateway.api_key` → 앞 8자 + `"..."`
- `security.auth_token_file` → `"(masked)"`

#### `config-set` -- 설정 값 변경

```bash
revkit -R gateway config-set gateway.port 9090
revkit -R gateway config-set gateway.exec_enabled true
revkit -R gateway config-set analysis.max_instances 5
```

값 타입 자동 변환: `true`/`false` → bool, `null` → None, 숫자 → int/float, 나머지 → str.

변경 후 config.json 파일에 즉시 반영 → ConfigWatcher가 2초 내 감지하여 hot-reload.

#### `stop-all` -- 전체 인스턴스 정지

```bash
revkit -R gateway stop-all
```
```
[OK] Stopped: 3 instances
```

각 인스턴스에 `save_db` → `stop` RPC 전송 후, 프로세스 생존 확인. 미종료 시 백그라운드 `force_kill`.

#### `uploads` -- 업로드 파일 목록

```bash
revkit -R gateway uploads
```
```
  Directory: /home/user/.revkit/uploads
  Files: 2, Total: 45.3 MB
    a1b2c3d4e5f6...                           23.1 MB  2026-03-22T14:00:00
    sample.apk                                22.2 MB  2026-03-22T14:05:00
```

#### `uploads-clean` -- 업로드 디렉토리 정리

```bash
revkit -R gateway uploads-clean
```
```
[OK] Removed 2 files, freed 45.3 MB
```

#### `audit` -- 감사 로그 조회

```bash
revkit -R gateway audit              # 최근 20건 (기본)
revkit -R gateway audit --tail 50    # 최근 50건
```
```
  Total entries: 1234, showing last 20
  2026-03-22T14:00:00Z  GET     /api/v1/health                          200  192.168.1.10
  2026-03-22T14:01:00Z  POST    /api/v1/instances/abc123/rpc            200  192.168.1.10
```

#### `system` -- 서버 시스템 정보

```bash
revkit -R gateway system
```
```
  os: Linux
  os_version: 6.17.0-19-generic
  arch: x86_64
  python: 3.12.0
  hostname: analysis-server
  cpu_count: 16
  cpu_percent: 23.5
  ram_total_gb: 64.0
  ram_used_gb: 12.3
  ram_percent: 19.2
```

`psutil` 미설치 시 CPU/RAM 정보는 `"psutil": "not installed"`로 표시.

#### `disk` -- 디스크 사용량

```bash
revkit -R gateway disk
```
```
  upload_dir:
    Path: /home/user/.revkit/uploads
    Used: 120.5GB / 500.0GB (24.1%)
    Free: 379.5GB
  log_dir:
    Path: /home/user/.revkit/logs
    Used: 120.5GB / 500.0GB (24.1%)
    Free: 379.5GB
  home:
    Path: /home/user
    Used: 120.5GB / 500.0GB (24.1%)
    Free: 379.5GB
```

#### `cleanup` -- stale 레지스트리 정리

```bash
revkit -R gateway cleanup
```
```
  ida: 1 active, 0 cleaned
  jeb: 2 active, 1 cleaned
```

좀비 프로세스(PID 사망)를 레지스트리에서 제거.

#### `rotate-key` -- API 키 교체

```bash
revkit -R gateway rotate-key
```
```
[OK] New API key: xYz9AbCdEf...
Update client config with the new key
```

`secrets.token_urlsafe(32)`로 새 키 생성 → `config.json`에 저장 → ConfigWatcher가 hot-reload.

**주의:** 기존 키로 인증된 현재 요청으로 새 키를 발급하므로, 발급 후 클라이언트 config도 업데이트 필요.

#### `allow-ip` -- IP 화이트리스트 관리

```bash
revkit -R gateway allow-ip list                      # 현재 목록
revkit -R gateway allow-ip add 192.168.1.0/24        # CIDR 추가
revkit -R gateway allow-ip add 10.0.0.5              # 단일 IP 추가
revkit -R gateway allow-ip remove 192.168.1.0/24     # 제거
```
```
  Allowed IPs: ['192.168.1.0/24', '10.0.0.5']
```

#### `connections` -- 최근 연결 기록

```bash
revkit -R gateway connections              # 최근 50건 (기본)
revkit -R gateway connections --tail 100   # 최근 100건
```
```
  Total: 500, showing last 50
  2026-03-22T14:00:00  192.168.1.10     GET     /api/v1/health
  2026-03-22T14:01:00  192.168.1.10     POST    /api/v1/instances/abc123/rpc
```

서버 메모리에 최근 500건까지 저장 (`deque(maxlen=500)`). 서버 재시작 시 초기화.

#### `download` -- 서버 파일 다운로드

```bash
revkit -R gateway download abc123def            # file_id로 다운로드
revkit -R gateway download abc123def --out ./local_copy.apk
```

서버의 uploads, idb_dir, project_dir, output_dir을 순서대로 탐색하여 파일명에 `{id}` 패턴이 포함된 파일을 찾아 다운로드.

#### `logs` -- 인스턴스 로그 조회

```bash
revkit -R gateway logs -i abc123              # 최근 50건 (기본)
revkit -R gateway logs -i abc123 --tail 100   # 최근 100건
```
```
  Instance: abc123, entries: 50
  2026-03-22T14:00:00  [INFO]  Server started on port 18300
  2026-03-22T14:01:00  [INFO]  Database loaded: sample.apk
```

로그 경로 탐색 순서:
1. 레지스트리의 `log_path` 필드
2. `~/.revkit/logs/{ida|jeb}/instances/{id}.jsonl` fallback

#### `progress` -- 분석 진행률

```bash
revkit -R gateway progress -i abc123
```
```
  instance_id: abc123
  state: ready
  func_count: 1234
  uptime: 120.5
```

인스턴스가 `ready` 상태이고 포트가 있으면, 엔진 서버에 `status` RPC를 전송하여 실시간 정보 조회.

---

## 5. config.json gateway 섹션

`gateway/config.py`의 `GATEWAY_DEFAULTS` 기반. `config.json`에 없는 키는 기본값 적용.

```json
{
  "gateway": {
    "host": "0.0.0.0",
    "port": 8080,
    "max_upload_size_mb": 500,
    "upload_dir": null,
    "api_key": null,
    "allowed_ips": [],
    "trusted_proxies": [],
    "request_timeout": 60,
    "batch_timeout": 300,
    "log_rpc_params": false,
    "audit_path": null,
    "audit_max_size_mb": 100,
    "exec_enabled": false
  }
}
```

| 키 | 타입 | 기본값 | 설명 |
|----|------|--------|------|
| `host` | string | `"0.0.0.0"` | 바인드 주소 |
| `port` | int | `8080` | 바인드 포트 (1-65535) |
| `max_upload_size_mb` | int/null | `500` | 최대 업로드 크기 (MB). `0` = 무제한, `null` = 업로드 비활성화 |
| `upload_dir` | string/null | `null` | 업로드 디렉토리. `null` → `~/.revkit/uploads` |
| `api_key` | string/null | `null` | API 키. `null` = 인증 비활성화 (모든 요청 허용) |
| `allowed_ips` | list | `[]` | IP 화이트리스트. `[]` = 모든 IP 허용. CIDR 지원 |
| `trusted_proxies` | list | `[]` | 리버스 프록시 IP. X-Forwarded-For 헤더 신뢰 대상 |
| `request_timeout` | int | `60` | 일반 RPC 요청 타임아웃 (초) |
| `batch_timeout` | int | `300` | 배치 RPC 요청 타임아웃 (초) |
| `log_rpc_params` | bool | `false` | 감사 로그에 RPC 파라미터 기록 여부 |
| `audit_path` | string/null | `null` | 감사 로그 경로. `null` → `~/.revkit/gateway/audit.jsonl` |
| `audit_max_size_mb` | int | `100` | 감사 로그 최대 크기 (MB). 초과 시 아카이브 회전 |
| `exec_enabled` | bool | `false` | `exec` RPC 명령 허용 여부. **보안상 `false` 권장** |

### 클라이언트 측 설정

원격 모드 사용 시 클라이언트의 `config.json`에 추가:

```json
{
  "gateway": {
    "url": "http://server:8080",
    "api_key": "YOUR_API_KEY",
    "mode": "auto"
  }
}
```

| 키 | 설명 |
|----|------|
| `gateway.url` | Gateway 서버 주소 |
| `gateway.api_key` | 인증 키 (서버 `api_key`와 동일해야 함) |
| `gateway.mode` | `"auto"` (기본) = url 있으면 자동 원격, `"manual"` = `-R` 플래그 필요 |

우선순위: `--remote URL` CLI 인자 > `gateway.url` config > 로컬 모드

---

## 6. RPC 프록시 동작

### 요청 흐름

```
클라이언트 → POST /api/v1/instances/{id}/rpc
         → Gateway 인증 체크 (API key + IP)
         → 인스턴스 레지스트리 조회 (IDA/JEB 양쪽)
         → exec 차단 체크 (exec_enabled)
         → Content-Length 검증 (최대 10MB)
         → 타임아웃 결정 (일반: request_timeout+5, 배치: batch_timeout+5)
         → auth_token 해석 (레지스트리 → auth_tokens.json fallback)
         → http://127.0.0.1:{port}/ 로 JSON-RPC 중계
         → 응답 그대로 클라이언트에 반환
```

### exec 차단

`gateway.exec_enabled` = `false` (기본값)일 때 `exec` RPC 메서드 호출 시:
```json
{"error": "exec is disabled on gateway (set gateway.exec_enabled=true)"}
```
HTTP 403 응답.

### Content-Length 제한

RPC 본문 최대 10MB. 초과 시 HTTP 413 응답.

### 타임아웃

- 일반 요청: `request_timeout` + 5초 = 기본 65초
- 배치 요청 (`params.is_batch` = `true`): `batch_timeout` + 5초 = 기본 305초

### Auth Token 해석 순서

1. 레지스트리 항목의 `auth_token` 필드
2. `~/.revkit/auth_tokens.json` 파일 (형식: `id:port:token`, 줄 단위)

### 에러 처리

| 상황 | HTTP 코드 | 에러 메시지 |
|------|-----------|------------|
| 인스턴스 미발견 | 404 | `Instance '{id}' not found` |
| 포트 없음 | 502 | `Instance has no port assigned` |
| Content-Length 초과 | 413 | `Content-Length out of range` |
| exec 차단 | 403 | `exec is disabled on gateway` |
| 엔진 서버 응답 없음 | 502 | `Engine server unreachable` |
| 엔진 서버 HTTP 에러 | (원본 코드) | (원본 에러 전달) |

---

## 7. 파일 업로드 흐름

### 전체 흐름 (원격 start)

```
1. CLI: upload_binary() → POST /api/v1/upload (multipart/form-data)
2. Gateway: parse_multipart()
   → Content-Length 검증
   → 디스크 공간 체크 (필요량 x2)
   → multipart boundary 파싱
   → UUID 파일명으로 임시 파일 저장 ({id}.tmp)
   → atomic rename ({id}.tmp → {id})
   → {"file_id": "...", "original_name": "...", "size": ...} 반환

3. CLI: remote_start() → POST /api/v1/engines/{engine}/start
   → file_id로 업로드 파일 위치 확인
   → 원본 파일명으로 복사 (IDB/프로젝트 네이밍용)
   → subprocess로 `revkit {engine} start {path}` 실행
   → 성공 시 업로드 파일 자동 삭제 (cleanup_upload)
```

### 보안

- **경로 순회 방지**: `_validate_path()` — `os.path.realpath()` 비교로 upload_dir 외부 접근 차단
- **파일명 sanitize**: `os.path.basename()` — 경로 구분자 제거
- **크기 제한**: Content-Length 헤더 + 실제 데이터 크기 이중 검증
- **디스크 공간**: 업로드 전 `shutil.disk_usage()` 체크 (필요량의 2배 여유 필요)
- **업로드 비활성화**: `max_upload_size_mb: null` → HTTP 403

### 에러 코드

| 상황 | HTTP 코드 |
|------|-----------|
| Content-Length 누락 | 411 |
| 파일 크기 초과 | 413 |
| multipart boundary 없음 | 400 |
| 파일 파트 없음 | 400 |
| 경로 순회 감지 | 400 |
| 업로드 비활성화 | 403 |
| 디스크 공간 부족 | 507 |

---

## 8. 인증 시스템

### 인증 체크 순서

`authenticate()` 함수 (auth.py):

1. **IP 화이트리스트 체크** (`check_ip_whitelist`)
   - `allowed_ips` = `[]` → 모든 IP 허용 (체크 스킵)
   - CIDR 표기 지원: `"192.168.1.0/24"`
   - 실패 시 → `False` (HTTP 403)

2. **API 키 검증** (`validate_api_key`)
   - `api_key` = `null` → 인증 비활성화 (모든 요청 허용)
   - Timing-safe 비교: `hmac.compare_digest()` 사용
   - 실패 시 → `False` (HTTP 403)

### Bearer Token

```
Authorization: Bearer YOUR_API_KEY_HERE
```

### X-Forwarded-For 처리

리버스 프록시 뒤에서 운영 시:

```json
{
  "gateway": {
    "trusted_proxies": ["10.0.0.1", "172.16.0.0/12"]
  }
}
```

동작 방식 (`extract_client_ip`):
1. 직접 연결 IP가 `trusted_proxies`에 포함되지 않으면 → 직접 IP 사용
2. 포함되면 → `X-Forwarded-For` 헤더의 **오른쪽부터** 탐색
3. trusted proxy가 아닌 첫 번째 IP를 실제 클라이언트 IP로 사용

### 공개 경로

`/api/v1/health`는 인증 없이 접근 가능 (헬스체크/로드밸런서용).

---

## 9. Config Hot-Reload

`ConfigWatcher` 클래스 (daemon.py): config.json 파일의 mtime을 2초 간격으로 폴링.

### 변경 감지 시 동작

| 변경 항목 | 동작 |
|-----------|------|
| `api_key` | 즉시 반영 (서버 재시작 없음) |
| `allowed_ips` | 즉시 반영 |
| `request_timeout`, `batch_timeout` | 즉시 반영 |
| `exec_enabled` | 즉시 반영 |
| `log_rpc_params` | 즉시 반영 |
| `host` 또는 `port` | **서버 재시작** (자동) |

### 포트/호스트 변경 시 재시작 흐름

1. ConfigWatcher가 mtime 변경 감지
2. 새 config 로드 → host/port 비교
3. 변경됐으면 `reload_event.set()`
4. 메인 루프에서 감지:
   - 기존 서버 `shutdown()`
   - ConfigWatcher 중지
   - 새 config로 `GatewayDaemon` 재생성
   - 새 서버 `serve_forever()`
   - 새 ConfigWatcher 시작
5. 로그: `"Gateway restarted on {host}:{port}"`

### 에러 처리

config reload 실패 시 기존 설정 유지. 로그에 에러 기록.

---

## 10. 감사 로깅

### 기록 위치

기본: `~/.revkit/gateway/audit.jsonl` (`audit_path` 설정으로 변경 가능)

### 레코드 형식

```json
{
  "ts": "2026-03-22T14:00:00.123456+00:00",
  "method": "POST",
  "path": "/api/v1/instances/abc123/rpc",
  "status": 200,
  "source_ip": "192.168.1.10",
  "elapsed_ms": 45.23,
  "api_key_id": "xYz9AbCd..."
}
```

| 필드 | 설명 |
|------|------|
| `ts` | UTC ISO 8601 타임스탬프 |
| `method` | HTTP 메서드 |
| `path` | 요청 경로 |
| `status` | HTTP 응답 코드 |
| `source_ip` | 클라이언트 IP (X-Forwarded-For 반영) |
| `elapsed_ms` | 처리 시간 (ms) |
| `api_key_id` | API 키 앞 8자 + `"..."` (인증 추적용) |
| `instance_id` | 대상 인스턴스 ID (해당 시) |
| `rpc_method` | RPC 메서드명 (해당 시) |
| `params` | RPC 파라미터 (`log_rpc_params=true` 시, 민감 필드 REDACTED) |

### 민감 정보 처리

`log_rpc_params: true`로 파라미터를 기록할 때, 다음 필드는 `[REDACTED]`로 마스킹:
- `code`, `script`, `exec_code`, `exec`

### 아카이브 회전

감사 로그 파일 크기가 `audit_max_size_mb` (기본 100MB) 초과 시:
- 기존 파일 → `audit_20260322T140000.jsonl` 형식으로 아카이브
- 새 파일 생성

스레드 안전: `threading.Lock()` 기반. 쓰기 실패 시 무시 (OSError catch).

---

## 11. 주의사항

### 네트워크

- **`host: "127.0.0.1"` 사용 시**: 원격 접속 불가. 외부 접근 필요 시 `"0.0.0.0"` 또는 실제 IP 사용.
- **TLS 미지원**: Gateway 자체는 HTTP만 지원. HTTPS 필요 시 nginx/caddy 등 리버스 프록시 사용 권장.
- **`trusted_proxies` 설정 필수**: 리버스 프록시 뒤에서 운영 시, 프록시 IP를 반드시 등록해야 X-Forwarded-For가 올바르게 처리됨.

### 보안

- **`api_key: null`**: 인증 비활성화. 개발/테스트 환경에서만 사용 권장.
- **`exec_enabled: false`** (기본): `exec` 명령은 임의 코드 실행이므로 기본 차단. 필요한 경우에만 활성화.
- **`config-set`으로 변경 불가한 키**: `security.auth_token_file` — 보안상 원격에서 인증 토큰 경로 변경 차단.

### LOCAL_ONLY 명령

다음 명령들은 Gateway 경유 불가 (로컬 전용):
- `bookmark` — 로컬 파일시스템에 북마크 저장
- `init`, `cleanup`, `logs` — 로컬 파일시스템 직접 접근 필요
- `update`, `completions` / `completion` — CLI 자체 관리

### 제한사항

- **동시 연결**: `ThreadingHTTPServer` 기반 — 스레드 per 요청. 대규모 동시 접속에는 부적합.
- **연결 기록**: 메모리 내 `deque(maxlen=500)` — 서버 재시작 시 초기화.
- **업로드 진행률**: `/api/v1/upload-progress/{id}` 엔드포인트는 미구현 상태.
- **daemon_threads = True**: 메인 스레드 종료 시 처리 중인 요청이 강제 종료될 수 있음.

### 참고

- Gateway 관리 명령을 로컬에서 직접 실행하면 에러:
  ```
  Gateway commands require remote mode. Use: revkit -R gateway <command>
  ```
- 상세 원격 모드 사용법: `docs/README-Remote.md`
