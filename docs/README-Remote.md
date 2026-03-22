# revkit Remote Mode (Gateway) / 원격 모드 (게이트웨이)

Remote analysis: run IDA/JEB on a server, control via CLI from client.

원격 분석 서버에서 IDA/JEB를 실행하고, 클라이언트에서 CLI로 제어하는 구조.

---

## 구조

```
┌─────────────────────────────────────────────────────────┐
│  Client (노트북, CI/CD, Claude Code 등)                  │
│                                                         │
│  ~/.revkit/config.json                                  │
│    gateway.url = "http://192.168.1.100:8080"            │
│                                                         │
│  $ revkit ida start sample.exe                          │
│  $ revkit ida decompile 0x401000                        │
│  $ revkit jeb classes                                   │
│       │                                                 │
│       └──── HTTP POST /api/v1/... ────►                 │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Server (IDA Pro + JEB Pro 설치된 분석 서버)              │
│                                                         │
│  ~/.revkit/config.json                                  │
│    gateway.host = "0.0.0.0"                             │
│    gateway.port = 8080                                  │
│    gateway.url  = ""          ← 비워둠                   │
│                                                         │
│  $ python -m revkit.tools.gateway.daemon                │
│       │                                                 │
│       ├── IDA Pro (headless, RPC server)                 │
│       ├── JEB Pro (headless, RPC server)                 │
│       └── Gateway daemon (HTTP → RPC 브릿지)             │
└─────────────────────────────────────────────────────────┘
```

---

## 동작 원리

1. 클라이언트에서 `revkit ida decompile 0x401000` 실행
2. CLI가 `config.json`의 `gateway.url` 확인
3. URL이 `http`로 시작하면 → 원격 모드 활성화
4. CLI가 HTTP POST로 게이트웨이 서버에 RPC 요청 전송
5. 게이트웨이가 로컬 IDA/JEB RPC 서버로 포워딩
6. 결과를 HTTP 응답으로 클라이언트에 반환

**핵심: 클라이언트 CLI 명령은 로컬/원격 동일. `gateway.url` 유무만 다름.**

---

## 서버 설정

### 1. 필수 소프트웨어

- Python 3.10+
- IDA Pro (headless 가능한 라이선스)
- JEB Pro
- psutil (`pip install psutil`)

### 2. config.json (서버)

```json
{
    "gateway": {
        "url": "",
        "host": "0.0.0.0",
        "port": 8080,
        "api_key": "your-secret-api-key",
        "allowed_ips": ["192.168.1.0/24", "10.0.0.0/8"],
        "max_upload_size_mb": 500,
        "upload_dir": "~/.revkit/uploads",
        "request_timeout": 60,
        "batch_timeout": 300
    },
    "ida": {
        "install_dir": "C:/Program Files/IDA Professional 9.3",  // Linux: "/opt/ida"
        "registry": "~/.revkit/ida/registry.json"
    },
    "jeb": {
        "install_dir": "C:/WorkSpace/bin/JEB-5.38",              // Linux: "/opt/jeb"
        "registry": "~/.revkit/jeb/registry.json",
        "spawn_method": "wrapper",
        "java_home": "C:/Program Files/Java/jdk-21.0.10"         // Linux: "/usr/lib/jvm/java-21"
    },
    "analysis": {
        "max_instances": 10,
        "wait_timeout": 300,
        "auto_save": true
    },
    "security": {
        "auth_token_file": "~/.revkit/auth_tokens.json",
        "exec_enabled": false
    }
}
```

**보안 주의:**
- `api_key`: 반드시 설정 (null이면 인증 없이 접근 가능)
- `allowed_ips`: 접근 허용 IP 대역 지정
- `exec_enabled: false`: 원격에서 임의 코드 실행 차단 (필요시만 true)

### 3. 서버 시작

```bash
# 게이트웨이 데몬 시작
python -m revkit.tools.gateway.daemon

# 백그라운드 실행 (Linux)
nohup python -m revkit.tools.gateway.daemon &

# Windows 서비스로 등록 (선택)
# → 별도 가이드 참조
```

### 4. 서버 상태 확인

```bash
# 서버에서 직접
revkit ida list
revkit jeb list

# 포트 확인
netstat -tlnp | grep 8080
```

---

## 클라이언트 설정

### 1. config.json (클라이언트)

```json
{
    "gateway": {
        "url": "http://192.168.1.100:8080",
        "api_key": "your-secret-api-key"
    }
}
```

**이것만 있으면 됨.** IDA/JEB 설치 불필요. `paths`, `ida`, `jeb` 섹션도 불필요.

### 2. 사용

config에 `gateway.url`과 `api_key`가 설정되어 있으면, 모든 명령이 자동으로 원격 서버에서 실행된다.

```bash
# 바이너리 업로드 + 분석 시작
revkit ida start ./local-sample.exe    # 로컬 파일이 서버로 업로드됨

# 분석 명령 (전부 원격)
revkit ida wait
revkit ida decompile 0x401000
revkit ida functions --count 10
revkit ida strings --filter "http"
revkit ida export-script --out result.py   # 결과는 로컬에 저장

# JEB도 동일
revkit jeb start ./app.apk --fresh
revkit jeb wait
revkit jeb classes --tree
revkit jeb decompile "Lcom/app/MainActivity;"

# 정리
revkit ida stop
```

### 3. 접속 방법 3가지

```bash
# 방법 1: 전체 옵션 (config 없이 1회성)
revkit --remote http://192.168.1.100:8080 --api-key YOUR_KEY ida list

# 방법 2: -R 축약 (config의 gateway.url + api_key 사용)
revkit -R ida list
revkit -R ida start sample.exe
revkit -R jeb classes

# 방법 3: 자동 (config에 gateway.url 있으면 항상 원격)
revkit ida list
```

| 방법 | 플래그 | 조건 |
| --- | --- | --- |
| 전체 옵션 | `--remote URL --api-key KEY` | config 없어도 사용 가능 |
| `-R` 축약 | `-R` | config에 `gateway.url` + `api_key` 필요 |
| 자동 | (없음) | config에 `gateway.url` 있으면 자동 원격 |

> **우선순위**: `--remote URL` > `-R` > config `gateway.url` > 로컬 모드
revkit jeb stop
```

### 3. 1회성 서버 변경

```bash
# 다른 서버 지정 (config 무시)
revkit --remote http://10.0.0.5:9090 ida list

# 로컬로 강제 (gateway.url 설정 무시)
revkit --remote "" ida list
```

---

## Claude Code에서 사용

Claude Code가 원격 모드를 사용할 때 특별히 달라지는 건 없음:

```bash
# Claude Code가 실행하는 명령 — 로컬이든 리모트든 동일
python -m revkit.tools.cli.main ida start Samples/EXE/notepad.exe
python -m revkit.tools.cli.main ida wait --timeout 180
python -m revkit.tools.cli.main ida decompile 0x14000D9AC
python -m revkit.tools.cli.main jeb classes --count-only
```

**주의사항:**
- `--out` 경로: 원격 모드에서 `--out`은 **서버 측** 경로. 클라이언트에 저장하려면 결과를 stdout으로 받아서 리다이렉트
- `exec` 명령: 서버에서 `exec_enabled: false`면 차단됨
- 바이너리 업로드: `start` 시 로컬 파일이 자동 업로드됨 (max_upload_size_mb 제한)
- 타임아웃: 대용량 바이너리는 `request_timeout`, `batch_timeout` 조절 필요

---

## API 엔드포인트

게이트웨이가 제공하는 HTTP API:

| Method | Endpoint | 설명 |
|--------|----------|------|
| POST | `/api/v1/upload` | 바이너리 업로드 |
| POST | `/api/v1/engines/{ida\|jeb}/start` | 인스턴스 시작 |
| GET | `/api/v1/instances` | 활성 인스턴스 목록 |
| POST | `/api/v1/instances/{iid}/rpc` | RPC 호출 포워딩 |
| DELETE | `/api/v1/instances/{iid}` | 인스턴스 종료 |

모든 요청에 `Authorization: Bearer {api_key}` 헤더 필요 (api_key 설정 시).

---

## 우선순위 / Fallback

```
1. --remote CLI 인자          ← 최우선 (1회성 오버라이드)
2. config.json gateway.url   ← 영구 설정
3. 로컬 모드                  ← gateway.url 없거나 비어있을 때
```

---

## 트러블슈팅

| 증상 | 원인 | 해결 |
|------|------|------|
| `Connection refused` | 서버 데몬 미실행 또는 포트 불일치 | `netstat` 확인, 데몬 재시작 |
| `403 Forbidden` | IP 차단 또는 api_key 불일치 | `allowed_ips`, `api_key` 확인 |
| `413 Payload Too Large` | 업로드 파일이 max_upload_size_mb 초과 | 서버 config에서 제한 상향 |
| `408 Request Timeout` | 분석 시간 초과 | `request_timeout`, `batch_timeout` 상향 |
| `exec` 명령 거부 | `exec_enabled: false` | 서버에서 true로 변경 (보안 주의) |
| 원격인데 로컬로 실행됨 | `gateway.url`이 비어있거나 http로 시작 안 함 | URL 형식 확인 (`http://...`) |
