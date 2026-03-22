# 보안 설정 레퍼런스

> revkit 보안 계층: 인증 → IP 제한 → exec 제어 → 업로드 제한 → 감사 로그.

---

## 1. 인증 (API Key)

### 설정

`config.json`:
```json
{
  "gateway": {
    "api_key": "your-secret-key"
  }
}
```

### HTTP 헤더

```
Authorization: Bearer {api_key}
```

### 동작

- `api_key` 설정 시: 모든 요청에 Bearer 토큰 필수 (`/api/v1/health` 제외)
- `api_key: null`: 인증 비활성화 (개발 전용)
- 틀린 키: HTTP 403 Forbidden
- 타이밍 안전 비교: `hmac.compare_digest()` 사용 (타이밍 사이드채널 공격 방지)

### CLI 사용

config에 `gateway.api_key` 설정 시 CLI가 자동으로 `Authorization: Bearer` 헤더 추가.
`--api-key` 플래그로 1회성 오버라이드 가능.

### 키 교체

```bash
# Gateway API 엔드포인트
POST /api/v1/gateway/rotate-key
```

- `secrets.token_urlsafe(32)` 로 새 키 생성 (43자 base64url)
- `config.json`에 즉시 반영 (hot-reload)
- 이전 키 즉시 무효화
- 응답에 새 키 포함 -- 클라이언트 config 업데이트 필요

```bash
# CLI 사용
revkit -R gateway rotate-key
```

---

## 2. IP 제한 (allowed_ips)

### 설정

```json
{
  "gateway": {
    "allowed_ips": ["192.168.50.0/24", "10.0.0.0/8"],
    "trusted_proxies": ["172.17.0.1"]
  }
}
```

### 동작

| 설정 | 결과 |
|------|------|
| `[]` (빈 배열) | 모든 IP 허용 (기본값) |
| CIDR 표기 | `192.168.50.0/24`, `10.0.0.0/8` 등 서브넷 지원 |
| 단일 IP | `["192.168.50.100"]` |

- IP 검증은 Python `ipaddress` 모듈 사용 (`ip_address`, `ip_network`)
- 유효하지 않은 IP 형식은 자동 무시 (ValueError catch)

### 리버스 프록시 뒤 실제 IP 추출

`trusted_proxies` 설정 시 `X-Forwarded-For` 헤더에서 실제 클라이언트 IP를 추출한다.
추출 로직: X-Forwarded-For 목록을 역순으로 순회하여 trusted proxy가 아닌 첫 IP를 사용.

```
X-Forwarded-For: client, proxy1, proxy2
trusted_proxies: ["proxy1", "proxy2"]
→ 실제 IP: client
```

`trusted_proxies`가 비어있으면 X-Forwarded-For를 무시하고 직접 연결 IP를 사용한다.

### API 관리

```bash
# 목록 조회
POST /api/v1/gateway/allow-ip  {"action": "list"}

# 추가
POST /api/v1/gateway/allow-ip  {"action": "add", "ip": "172.16.0.0/12"}

# 제거
POST /api/v1/gateway/allow-ip  {"action": "remove", "ip": "172.16.0.0/12"}
```

```bash
# CLI 사용
revkit -R gateway allow-ip list
revkit -R gateway allow-ip add 172.16.0.0/12
revkit -R gateway allow-ip remove 172.16.0.0/12
```

---

## 3. exec 제어 (2단계)

원격 코드 실행(`exec` 명령)은 2단계 게이트로 보호된다.

### Gateway 레벨 (1차 게이트)

```json
{
  "gateway": {
    "exec_enabled": false
  }
}
```

- `false` (기본값): Gateway에서 `exec` RPC 요청을 차단, HTTP 403 반환
- `true`: Gateway 통과, 엔진 레벨에서 최종 결정

### 엔진 레벨 (2차 게이트)

```json
{
  "security": {
    "exec_enabled": false
  }
}
```

또는 엔진별 오버라이드:

```json
{
  "ida": { "security": { "exec_enabled": true } },
  "jeb": { "security": { "exec_enabled": false } }
}
```

### 조합표

| Gateway | 엔진 | 원격 exec | 로컬 exec |
|---------|------|-----------|-----------|
| `false` | `false` | 차단 (403) | 차단 |
| `false` | `true`  | 차단 (403) | 허용 |
| `true`  | `false` | 차단 (엔진 거부) | 차단 |
| `true`  | `true`  | **허용** | 허용 |

> 로컬 exec (직접 CLI 사용): 엔진 레벨만 확인.
> 원격 exec (Gateway 경유): 양쪽 모두 `true`여야 실행.

---

## 4. 업로드 제한

### 파일 크기 제한

```json
{
  "gateway": {
    "max_upload_size_mb": 500
  }
}
```

| 값 | 동작 |
|-----|------|
| `500` | 최대 500MB |
| `0` | 무제한 |
| `null` | 업로드 완전 비활성화 (HTTP 403) |
| 음수/잘못된 값 | config 검증 오류 |

### Content-Length 검증 (RPC body)

RPC 프록시 요청(`/api/v1/instances/{id}/rpc`)에 별도의 body 크기 제한이 적용된다.

- 최대 10MB (`10 * 1024 * 1024` bytes)
- `Content-Length` 누락 또는 음수: HTTP 400 Bad Request
- 10MB 초과: HTTP 413 Payload Too Large
- `Content-Length` 파싱 실패 (비숫자): HTTP 400 Bad Request

### 디스크 공간 확인

업로드 시 대상 디렉토리의 여유 공간을 확인한다.
필요한 공간의 2배 미만이면 HTTP 507 Insufficient Storage를 반환한다.

### 경로 탐색 방지 (Path Traversal)

- 업로드 파일명에 `../`가 포함되어도 `os.path.basename()`으로 파일명만 추출
- 저장 경로를 `os.path.realpath()`로 정규화하여 `upload_dir` 밖으로의 파일 생성 차단
- 위반 시 HTTP 400 "Path traversal detected"

### 원자적 파일 저장

1. UUID 기반 임시 파일(`{file_id}.tmp`)로 먼저 저장
2. `os.rename()`으로 최종 파일명으로 원자적 이동
3. 실패 시 임시 파일 자동 정리 (`finally` 블록)

### 업로드 디렉토리

```json
{
  "gateway": {
    "upload_dir": "~/.revkit/uploads"
  }
}
```

`upload_dir`이 `null`이면 기본값 `~/.revkit/uploads` 사용. 디렉토리 자동 생성.

---

## 5. 감사 로그 (Audit)

### 2가지 감사 시스템

revkit은 두 가지 레벨의 감사 로그를 운영한다.

#### Gateway 감사 (`gateway/audit.py`)

HTTP 요청 레벨의 감사. 모든 Gateway API 호출을 기록.

위치: `~/.revkit/gateway/audit.jsonl` (기본값)

```json
{
  "ts": "2026-03-22T10:15:30.123456+00:00",
  "method": "POST",
  "path": "/api/v1/instances/abc123/rpc",
  "status": 200,
  "source_ip": "192.168.50.100",
  "elapsed_ms": 45.2,
  "instance_id": "abc123",
  "rpc_method": "decompile"
}
```

선택적 필드:
- `api_key_id`: 사용된 API 키 식별자
- `instance_id`: 대상 인스턴스 ID
- `rpc_method`: 호출된 RPC 메서드 이름
- `params`: RPC 파라미터 (`log_rpc_params: true` 일 때만 기록, 민감 필드 자동 삭제)

#### 엔진 감사 (`core/audit.py`)

엔진 명령 레벨의 감사. 로컬 CLI 명령 실행도 기록.

위치: `~/.revkit/{engine}/audit.jsonl`

```json
{
  "ts": "2026-03-22T10:15:30.123456+00:00",
  "engine": "jeb",
  "cmd": "decompile",
  "iid": "abc123",
  "ok": true,
  "ms": 123.45,
  "source_ip": "192.168.50.100"
}
```

### 민감 정보 자동 삭제 (Redaction)

`params`에 다음 키가 포함되면 값을 `"[REDACTED]"`로 치환:
- `code`
- `script`
- `exec_code`
- `exec`

### 설정

```json
{
  "gateway": {
    "audit_path": "~/.revkit/logs/gateway/audit.jsonl",
    "audit_max_size_mb": 100,
    "log_rpc_params": false
  }
}
```

| 설정 | 기본값 | 설명 |
|------|--------|------|
| `audit_path` | `~/.revkit/gateway/audit.jsonl` | 감사 로그 파일 경로 |
| `audit_max_size_mb` | `100` | 로테이션 기준 크기 (MB) |
| `log_rpc_params` | `false` | RPC 파라미터 기록 여부 |

### 자동 로테이션

파일 크기가 `audit_max_size_mb` 초과 시 현재 파일을 `audit_YYYYMMDDTHHMMSS.jsonl`로 아카이브하고 새 파일을 생성한다.

### API 조회

```bash
# 최근 20건 (기본값)
GET /api/v1/gateway/audit

# 최근 50건
GET /api/v1/gateway/audit?tail=50
```

```bash
# CLI 사용
revkit -R gateway audit --tail 50
```

---

## 6. 엔진 서버 인증 (auth_token)

### 구조

인스턴스 시작 시 랜덤 토큰이 생성되어 `~/.revkit/auth_tokens.json`에 저장된다.

파일 형식 (한 줄에 하나):
```
instance_id:port:token
```

### RPC 호출 시 토큰 해석 순서

1. 레지스트리 항목의 `auth_token` 필드 확인
2. 없으면 `auth_tokens.json` 파일에서 instance_id로 검색
3. 토큰 발견 시 `Authorization: Bearer {token}` 헤더로 전달

### 설정

```json
{
  "security": {
    "auth_token_file": "~/.revkit/auth_tokens.json"
  }
}
```

---

## 7. 공개 엔드포인트

인증 없이 접근 가능한 엔드포인트:

| 엔드포인트 | 응답 |
|-----------|------|
| `GET /api/v1/health` | `{"status": "ok", "service": "revkit-gateway", "timestamp": ...}` |

민감 정보(api_key, 서버 경로, 인스턴스 목록 등)를 포함하지 않는다.

---

## 8. 보안 체크리스트

### 필수

- [ ] `api_key` 설정 (`null` 아님)
- [ ] `allowed_ips` 설정 (빈 배열 아님)
- [ ] `exec_enabled: false` (Gateway + 엔진 양쪽, 필요 시에만 `true`)
- [ ] `max_upload_size_mb` 적절한 값 설정

### 프로덕션 배포

- [ ] 리버스 프록시(nginx, caddy 등) + TLS 사용
- [ ] `trusted_proxies`에 프록시 IP 등록
- [ ] `host`를 `0.0.0.0`이 아닌 특정 인터페이스로 제한 (또는 프록시에서 제한)
- [ ] 방화벽으로 Gateway 포트(8080) 직접 접근 차단

### 운영

- [ ] 감사 로그 정기 모니터링
- [ ] 정기 키 교체 (`rotate-key`)
- [ ] `log_rpc_params: false` 유지 (민감 데이터 노출 방지)
- [ ] 불필요한 업로드 파일 정기 정리 (`DELETE /api/v1/gateway/uploads`)

---

## 9. 기본값 요약

`gateway/config.py`의 `GATEWAY_DEFAULTS`:

```python
{
    "host": "0.0.0.0",
    "port": 8080,
    "max_upload_size_mb": 500,
    "upload_dir": None,                # → ~/.revkit/uploads
    "api_key": None,                   # 인증 비활성화
    "allowed_ips": [],                 # 모든 IP 허용
    "trusted_proxies": [],
    "request_timeout": 60,
    "batch_timeout": 300,
    "log_rpc_params": False,
    "audit_path": None,                # → ~/.revkit/gateway/audit.jsonl
    "audit_max_size_mb": 100,
    "exec_enabled": False,             # exec 차단
}
```

> 기본 설정은 **개발 편의**를 우선한다. 프로덕션 배포 전 반드시 `api_key`, `allowed_ips`, TLS를 설정할 것.

---

## 10. 알려진 제한사항

| 제한 | 권장 대응 |
|------|----------|
| TLS 미지원 | 리버스 프록시(nginx/caddy) 뒤에 배치 |
| Rate limiting 미구현 | 프록시 레벨에서 처리 (`limit_req` 등) |
| IPv6 zone ID 미지원 | link-local IPv6(`fe80::...%eth0`) 사용 시 주의 |
| `auth_tokens.json` 평문 저장 | 파일 퍼미션으로 보호 (`chmod 600`) |
| 감사 로그 변조 방지 미구현 | 외부 로그 수집기(syslog, ELK 등)로 실시간 전송 권장 |
