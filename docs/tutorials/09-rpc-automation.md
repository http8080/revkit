# Tutorial 09: Direct RPC Automation / RPC 직접 자동화

Call the IDA/JEB headless servers directly via HTTP JSON-RPC — useful for non-Python tools, CI pipelines, and custom integrations.

HTTP JSON-RPC를 통해 IDA/JEB headless 서버를 직접 호출합니다 — Python 이외의 도구, CI 파이프라인, 커스텀 통합에 유용합니다.

> **Prerequisites / 사전 준비**: A running instance with a known port / 포트를 알고 있는 실행 중인 인스턴스

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. Finding the Server Port / 서버 포트 찾기

Use `list` or `status` to find the port of a running instance.

`list` 또는 `status`를 사용하여 실행 중인 인스턴스의 포트를 확인합니다.

```bash
$RK ida list
# ID    PID    PORT   BINARY           STATUS
# a3k2  12345  18100  notepad.exe      ready

$RK jeb list
# ID    PID    PORT   BINARY           STATUS
# b7x1  23456  18200  sample.apk       ready
```

The port (e.g., `18100`) is your RPC endpoint: `http://127.0.0.1:18100`.

포트(예: `18100`)가 RPC 엔드포인트입니다: `http://127.0.0.1:18100`.

---

## 2. Auth Token / 인증 토큰

If auth is enabled, include the token from `~/.revkit/auth_tokens.json`.

인증이 활성화되어 있으면 `~/.revkit/auth_tokens.json`의 토큰을 포함합니다.

```bash
# Check token file / 토큰 파일 확인
cat ~/.revkit/auth_tokens.json
# {"a3k2": "abc123..."}

# Set as variable / 변수로 설정
TOKEN="abc123..."
```

Pass the token via the `X-Auth-Token` header.

`X-Auth-Token` 헤더로 토큰을 전달합니다.

---

## 3. IDA RPC Endpoint / IDA RPC 엔드포인트

IDA uses `POST /rpc` with standard JSON-RPC 2.0 format.

IDA는 표준 JSON-RPC 2.0 형식으로 `POST /rpc`를 사용합니다.

### Ping / 핑

```bash
curl -s http://127.0.0.1:18100/rpc \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}' | jq .

# → {"jsonrpc":"2.0","id":1,"result":{"status":"pong"}}
```

### Decompile / 디컴파일

```bash
curl -s http://127.0.0.1:18100/rpc \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{
    "jsonrpc":"2.0","id":2,
    "method":"decompile",
    "params":{"addr":"0x140010108"}
  }' | jq .result.code

# → "int __stdcall wWinMain(HINSTANCE hInstance, ..."
```

### Rename / 이름 변경

```bash
curl -s http://127.0.0.1:18100/rpc \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{
    "jsonrpc":"2.0","id":3,
    "method":"rename",
    "params":{"addr":"0x140010108","name":"my_main"}
  }' | jq .
```

### List Functions / 함수 목록

```bash
curl -s http://127.0.0.1:18100/rpc \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{
    "jsonrpc":"2.0","id":4,
    "method":"methods",
    "params":{"count":10}
  }' | jq .result.methods
```

---

## 4. JEB RPC Endpoint / JEB RPC 엔드포인트

JEB uses `POST /jsonrpc` with the same JSON-RPC 2.0 format.

JEB는 동일한 JSON-RPC 2.0 형식으로 `POST /jsonrpc`를 사용합니다.

### Ping / 핑

```bash
curl -s http://127.0.0.1:18200/jsonrpc \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}' | jq .
```

### Decompile / 디컴파일

```bash
# JEB uses class_sig, not addr / JEB는 addr이 아닌 class_sig 사용
curl -s http://127.0.0.1:18200/jsonrpc \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{
    "jsonrpc":"2.0","id":2,
    "method":"decompile",
    "params":{"class_sig":"Lcom/example/MainActivity;"}
  }' | jq .result.code
```

### Rename / 이름 변경

```bash
curl -s http://127.0.0.1:18200/jsonrpc \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{
    "jsonrpc":"2.0","id":3,
    "method":"rename",
    "params":{
      "sig":"Lcom/example/Foo;->bar()V",
      "name":"processData"
    }
  }' | jq .
```

---

## 5. JEB Parameter Aliases / JEB 매개변수 별칭

JEB RPC methods accept both full names and short aliases for common parameters.

JEB RPC 메서드는 공통 매개변수에 대해 전체 이름과 짧은 별칭을 모두 허용합니다.

| Full Name / 전체 이름 | Alias / 별칭 | Example / 예시 |
|---|---|---|
| `class_sig` | `class` | `Lcom/example/Foo;` |
| `method_sig` | `method` | `Lcom/example/Foo;->bar()V` |
| `field_sig` | `field` | `Lcom/example/Foo;->x:I` |
| `direction` | `dir` | `to` or `from` |

```bash
# Both work / 둘 다 동작
curl ... -d '{"method":"xrefs","params":{"sig":"Lcom/example/Foo;->bar()V"}}'
curl ... -d '{"method":"xrefs","params":{"method":"Lcom/example/Foo;->bar()V"}}'
```

---

## 6. Error Codes / 에러 코드

JSON-RPC errors follow standard codes with revkit-specific extensions.

JSON-RPC 에러는 표준 코드에 revkit 전용 확장을 따릅니다.

| Code / 코드 | Meaning / 의미 | Common Cause / 일반적 원인 |
|---|---|---|
| `-32700` | Parse error / 파싱 에러 | Malformed JSON / 잘못된 JSON |
| `-32600` | Invalid request / 잘못된 요청 | Missing method or jsonrpc field / method 또는 jsonrpc 필드 누락 |
| `-32601` | Method not found / 메서드 없음 | Typo in method name / 메서드 이름 오타 |
| `-32602` | Invalid params / 잘못된 매개변수 | Missing required param / 필수 매개변수 누락 |
| `-32603` | Internal error / 내부 에러 | Server-side exception / 서버측 예외 |
| `-32000` | Analysis error / 분석 에러 | Address not found, class not found / 주소 없음, 클래스 없음 |
| `-32001` | Auth error / 인증 에러 | Invalid or missing token / 잘못되거나 누락된 토큰 |

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32601,
    "message": "Method 'decomplie' not found"
  }
}
```

---

## 7. Automation Examples / 자동화 예시

### Batch Decompile with Shell Script / 셸 스크립트로 배치 디컴파일

```bash
#!/bin/bash
# Decompile a list of functions / 함수 목록 디컴파일
PORT=18100
TOKEN="your_token"

ADDRS=("0x140010108" "0x140001000" "0x140002000")
for addr in "${ADDRS[@]}"; do
  echo "=== $addr ==="
  curl -s http://127.0.0.1:$PORT/rpc \
    -H "Content-Type: application/json" \
    -H "X-Auth-Token: $TOKEN" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"decompile\",\"params\":{\"addr\":\"$addr\"}}" \
    | jq -r '.result.code // .error.message'
  echo
done
```

### Python RPC Client / Python RPC 클라이언트

```python
import requests

def rpc_call(port, method, params, token=None):
    """Send RPC call to revkit server / revkit 서버에 RPC 호출"""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Auth-Token"] = token
    resp = requests.post(
        "http://127.0.0.1:%d/rpc" % port,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers=headers,
    )
    data = resp.json()
    if "error" in data:
        raise RuntimeError(data["error"]["message"])
    return data["result"]

# Usage / 사용법
result = rpc_call(18100, "decompile", {"addr": "0x140010108"})
print(result["code"])
```

---

## 8. Tips / 팁

**Timeouts**: Set `--max-time` in curl for long operations. Default server timeout is 60s.

**타임아웃**: 긴 작업에는 curl에서 `--max-time`을 설정하세요. 기본 서버 타임아웃은 60초입니다.

**Concurrent requests**: The RPC server is single-threaded. Requests are queued, not parallel.

**동시 요청**: RPC 서버는 단일 스레드입니다. 요청은 병렬이 아닌 큐에 저장됩니다.

**Save after modifications**: Call `save_db` (IDA) or `save` (JEB) after rename/comment operations.

**수정 후 저장**: rename/comment 작업 후 `save_db`(IDA) 또는 `save`(JEB)를 호출하세요.

---

**Next / 다음**: [10-add-cli-command.md](10-add-cli-command.md) — Adding a new CLI command / 새 CLI 명령 추가
