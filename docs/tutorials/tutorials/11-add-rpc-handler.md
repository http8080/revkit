# Tutorial 11: Adding a New RPC Handler / 새 RPC 핸들러 추가

Developer guide for adding server-side RPC handlers to IDA and JEB engines. The handler is the server-side counterpart of the CLI command.

IDA와 JEB 엔진에 서버측 RPC 핸들러를 추가하는 개발자 가이드. 핸들러는 CLI 명령의 서버측 대응입니다.

> **Prerequisites / 사전 준비**: [10-add-cli-command.md](10-add-cli-command.md) completed / 완료

---

## 1. Architecture / 아키텍처

When a CLI command calls `post_rpc(url, "method_name", params)`, the server routes it to a handler function.

CLI 명령이 `post_rpc(url, "method_name", params)`를 호출하면 서버가 핸들러 함수로 라우팅합니다.

```
CLI                        Server
cmd_xxx(ctx)    ──RPC──>   dispatch(method, params)
  post_rpc()               │
                            ├─ "func_stats" → _handle_func_stats(params)
                            ├─ "decompile"  → _handle_decompile(params)
                            └─ ...
```

The routing table is defined in `dispatch.py` (IDA) or `framework.py` (JEB).

라우팅 테이블은 `dispatch.py`(IDA) 또는 `framework.py`(JEB)에 정의됩니다.

---

## 2. IDA Handler / IDA 핸들러

IDA handlers are **module-level functions** in `engines/ida/server/handlers/`. They receive `params` (dict) and return a result dict.

IDA 핸들러는 `engines/ida/server/handlers/`의 **모듈 수준 함수**입니다. `params`(dict)를 받고 결과 dict를 반환합니다.

### Step 1: Write the Handler / 핸들러 작성

```python
# revkit/tools/engines/ida/server/handlers/analysis.py

def _handle_func_stats(params):
    """Return function statistics for the current IDB.
    현재 IDB의 함수 통계를 반환합니다.
    """
    import idautils
    import idc
    import ida_funcs

    min_size = params.get("min_size", 0)

    total = 0
    named = 0
    unnamed = 0
    sizes = []

    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        size = func.end_ea - func.start_ea
        if size < min_size:
            continue

        total += 1
        sizes.append(size)
        name = idc.get_func_name(ea)
        if name.startswith("sub_"):
            unnamed += 1
        else:
            named += 1

    avg_size = sum(sizes) // len(sizes) if sizes else 0

    return {
        "total": total,
        "named": named,
        "unnamed": unnamed,
        "avg_size": avg_size,
        "min_size_filter": min_size,
    }
```

### Step 2: Register in dispatch.py / dispatch.py에 등록

```python
# revkit/tools/engines/ida/server/handlers/dispatch.py

from .analysis import (
    _handle_decompile,
    _handle_find_func,
    _handle_func_stats,     # ← ADD THIS / 이것을 추가
    # ... other imports
)

_METHODS = {
    "decompile":   _handle_decompile,
    "find_func":   _handle_find_func,
    "func_stats":  _handle_func_stats,   # ← ADD THIS / 이것을 추가
    # ...
}
```

The `dispatch()` function looks up `_METHODS[method_name]` and calls the handler. No other registration needed.

`dispatch()` 함수가 `_METHODS[method_name]`을 조회하여 핸들러를 호출합니다. 다른 등록은 필요 없습니다.

### Step 3: Test with curl / curl로 테스트

```bash
# Start IDA server / IDA 서버 시작
$RK ida start Samples/EXE/notepad.exe && $RK ida wait

# Call the new handler / 새 핸들러 호출
curl -s http://127.0.0.1:18100/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":1,
    "method":"func_stats",
    "params":{"min_size":100}
  }' | jq .result

# Expected output / 예상 출력
# {
#   "total": 312,
#   "named": 245,
#   "unnamed": 67,
#   "avg_size": 487,
#   "min_size_filter": 100
# }
```

---

## 3. JEB Handler / JEB 핸들러

JEB handlers are **instance methods** (with `self`) because they need access to the JEB engine context. And they MUST use **Jython 2.7 syntax** — no f-strings, no type hints.

JEB 핸들러는 JEB 엔진 컨텍스트에 접근해야 하므로 **인스턴스 메서드**(self 포함)입니다. **Jython 2.7 문법**만 사용해야 합니다 — f-string, 타입 힌트 금지.

### Step 1: Write the Handler / 핸들러 작성

```python
# revkit/tools/engines/jeb/server/handlers/analysis.py
# ⚠️ JYTHON 2.7 — no f-strings, no type hints, no walrus operator

def _handle_class_stats(self, params):
    """Return class statistics for the current project.
    현재 프로젝트의 클래스 통계를 반환합니다.
    """
    package_filter = params.get("package", None)

    total = 0
    with_methods = 0
    method_counts = []

    for unit in self.prj.findUnits(self.DexUnit):
        for cls in unit.getClasses():
            sig = cls.getSignature(False)

            # Apply package filter / 패키지 필터 적용
            if package_filter and package_filter not in sig:
                continue

            total += 1
            methods = cls.getMethods()
            mc = len(methods) if methods else 0
            method_counts.append(mc)
            if mc > 0:
                with_methods += 1

    avg_methods = sum(method_counts) // len(method_counts) if method_counts else 0

    return {
        "total": total,
        "with_methods": with_methods,
        "avg_methods": avg_methods,
    }
```

### Step 2: Register in framework.py / framework.py에 등록

```python
# revkit/tools/engines/jeb/server/framework.py

_METHODS = {
    "decompile":    "_handle_decompile",
    "classes":      "_handle_classes",
    "class_stats":  "_handle_class_stats",    # ← ADD THIS / 이것을 추가
    # ...
}
```

Note: JEB uses **string method names** (not function references) because handlers are instance methods resolved via `getattr(self, name)`.

참고: JEB는 핸들러가 `getattr(self, name)`으로 해결되는 인스턴스 메서드이므로 **문자열 메서드 이름**을 사용합니다 (함수 참조가 아님).

### Step 3: Test with curl / curl로 테스트

```bash
# Start JEB server / JEB 서버 시작
$RK jeb start Samples/APK/sample.apk && $RK jeb wait

# Call the new handler / 새 핸들러 호출
curl -s http://127.0.0.1:18200/jsonrpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":1,
    "method":"class_stats",
    "params":{"package":"com/example"}
  }' | jq .result
```

---

## 4. Error Handling / 에러 처리

### IDA — Raise RpcError / RpcError 발생

```python
# revkit/tools/engines/ida/server/handlers/analysis.py
from ..exceptions import RpcError

def _handle_func_stats(params):
    addr = params.get("addr")
    if addr is None:
        raise RpcError(-32602, "Missing required parameter: addr")

    func = ida_funcs.get_func(int(addr, 16))
    if func is None:
        raise RpcError(-32000, "No function at address: %s" % addr)

    return {"name": idc.get_func_name(func.start_ea)}
```

### JEB — Raise RpcError (Jython 2.7) / RpcError 발생 (Jython 2.7)

```python
# revkit/tools/engines/jeb/server/handlers/analysis.py
from ..exceptions import RpcError

def _handle_class_info(self, params):
    sig = params.get("class_sig") or params.get("class")
    if sig is None:
        raise RpcError(-32602, "Missing required parameter: class_sig")

    cls = self._find_class(sig)
    if cls is None:
        raise RpcError(-32000, "Class not found: %s" % sig)

    return {"signature": cls.getSignature(False)}
```

---

## 5. IDA vs JEB Comparison / IDA vs JEB 비교

| Aspect / 측면 | IDA | JEB |
|---|---|---|
| Handler type / 핸들러 타입 | Module-level function / 모듈 함수 | Instance method (`self`) / 인스턴스 메서드 |
| Syntax / 문법 | Python 3.10+ | Jython 2.7 only |
| Registration / 등록 | `dispatch.py` `_METHODS` dict (function ref) | `framework.py` `_METHODS` dict (string name) |
| Handler dir / 핸들러 디렉토리 | `ida/server/handlers/` | `jeb/server/handlers/` |
| Exception / 예외 | `from ..exceptions import RpcError` | Same / 동일 |
| Context access / 컨텍스트 접근 | Global IDA API (idautils, idc) | `self.prj`, `self.DexUnit`, etc. |
| Endpoint / 엔드포인트 | `POST /rpc` | `POST /jsonrpc` |

---

## 6. Adding a Handler Module / 핸들러 모듈 추가

If your handler doesn't fit existing modules, create a new one.

기존 모듈에 맞지 않으면 새 모듈을 생성합니다.

### IDA

```python
# 1. Create: ida/server/handlers/statistics.py
def _handle_func_stats(params):
    ...

def _handle_segment_stats(params):
    ...

# 2. Import in ida/server/handlers/__init__.py
from .statistics import _handle_func_stats, _handle_segment_stats

# 3. Register in dispatch.py
from .statistics import _handle_func_stats, _handle_segment_stats
_METHODS["func_stats"] = _handle_func_stats
_METHODS["segment_stats"] = _handle_segment_stats
```

### JEB

```python
# 1. Create: jeb/server/handlers/statistics.py (Jython 2.7!)
def _handle_class_stats(self, params):
    ...

# 2. Add method to the handler class in framework.py
#    or import and bind in the handler class

# 3. Register string name in _METHODS
_METHODS["class_stats"] = "_handle_class_stats"
```

---

## 7. Testing Checklist / 테스트 체크리스트

- [ ] Handler returns a dict (not a list, not None) / 핸들러가 dict를 반환 (list나 None 아님)
- [ ] Missing params raise `RpcError(-32602, ...)` / 누락된 매개변수가 `RpcError(-32602, ...)` 발생
- [ ] Invalid input raises `RpcError(-32000, ...)` / 잘못된 입력이 `RpcError(-32000, ...)` 발생
- [ ] Registered in `_METHODS` / `_METHODS`에 등록됨
- [ ] curl test returns expected JSON / curl 테스트가 예상 JSON 반환
- [ ] Corresponding CLI command works end-to-end / 대응하는 CLI 명령이 end-to-end 동작
- [ ] JEB handler uses Jython 2.7 syntax only / JEB 핸들러가 Jython 2.7 문법만 사용

---

## 8. Full Example: End-to-End / 전체 예시: End-to-End

Adding `func-stats` to IDA — complete file changes:

IDA에 `func-stats` 추가 — 전체 파일 변경:

```
Modified files / 수정 파일:
  engines/ida/server/handlers/analysis.py    ← _handle_func_stats()
  engines/ida/server/handlers/dispatch.py    ← _METHODS entry
  engines/ida/commands/analysis.py           ← cmd_func_stats()
  engines/ida/commands/__init__.py           ← export
  engines/ida/engine.py                      ← subparser registration
```

Verify:

검증:

```bash
# Help text / 도움말
$RK ida func-stats --help

# Actual run / 실제 실행
$RK ida start Samples/EXE/notepad.exe && $RK ida wait
$RK ida func-stats --min-size 100
$RK ida func-stats --min-size 100 --json | jq .

# Direct RPC / 직접 RPC
curl -s http://127.0.0.1:18100/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"func_stats","params":{"min_size":100}}' | jq .

$RK ida stop
```

---

**Next / 다음**: [12-gateway-setup.md](12-gateway-setup.md) — Gateway deployment and security / Gateway 배포 + 보안
