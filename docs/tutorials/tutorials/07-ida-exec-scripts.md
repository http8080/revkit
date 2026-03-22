# Tutorial 07: IDA Exec Scripts / IDA exec 스크립트 작성

Run arbitrary IDA Python code on a live headless server — from one-liners to full analysis scripts.

라이브 headless 서버에서 임의의 IDA Python 코드를 실행합니다 — 한 줄 코드부터 전체 분석 스크립트까지.

> **Prerequisites / 사전 준비**: A running IDA instance (`$RK ida start` + `$RK ida wait`) / 실행 중인 IDA 인스턴스

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. Inline Exec / 인라인 실행

Pass a Python expression directly with `exec`. The code runs inside the IDA headless server process with full API access.

`exec`으로 Python 표현식을 직접 전달합니다. 코드는 전체 API 접근이 가능한 IDA headless 서버 프로세스 내에서 실행됩니다.

```bash
# Count all functions / 전체 함수 수 세기
$RK ida exec "print(len(list(idautils.Functions())))"
# → 521

# Get processor type / 프로세서 타입 확인
$RK ida exec "print(ida_ida.inf_get_procname())"
# → metapc

# List first 5 function names / 처음 5개 함수 이름 출력
$RK ida exec "
for i, ea in enumerate(idautils.Functions()):
    if i >= 5: break
    print(hex(ea), idc.get_func_name(ea))
"
```

> **Security / 보안**: `exec` is disabled by default. Set `security.exec_enabled: true` (or `ida.security.exec_enabled: true`) in `~/.revkit/config.json`.
>
> `exec`은 기본 비활성화. `~/.revkit/config.json`에서 `security.exec_enabled: true` 설정 필요.

---

## 2. IDA Python API Overview / IDA Python API 개요

The following modules are always available inside exec. No imports needed — the server pre-loads them.

아래 모듈은 exec 내부에서 항상 사용 가능합니다. import 불필요 — 서버가 미리 로드합니다.

| Module / 모듈 | Purpose / 용도 | Key Functions / 주요 함수 |
|---|---|---|
| `idautils` | Iteration helpers / 반복 헬퍼 | `Functions()`, `Segments()`, `XrefsTo()`, `XrefsFrom()` |
| `idc` | Classic IDA scripting / 클래식 스크립팅 | `get_func_name()`, `get_segm_name()`, `get_bytes()` |
| `ida_funcs` | Function objects / 함수 객체 | `get_func()`, `get_func_name()` |
| `ida_hexrays` | Decompiler / 디컴파일러 | `decompile()`, `cfunc_t`, `citem_t` |
| `ida_bytes` | Raw data access / 원시 데이터 | `get_bytes()`, `patch_byte()` |
| `ida_name` | Names/labels / 이름/레이블 | `get_name()`, `set_name()` |
| `ida_segment` | Segment info / 세그먼트 정보 | `get_segm_by_name()`, `getseg()` |
| `ida_ida` | Database info / DB 정보 | `inf_get_procname()`, `inf_get_min_ea()` |

---

## 3. Shell Mode / 셸 모드

Pipe code via stdin for quick testing. Useful in shell scripts and automation pipelines.

stdin으로 코드를 파이프하여 빠르게 테스트합니다. 셸 스크립트와 자동화 파이프라인에서 유용합니다.

```bash
# Simple pipe / 간단한 파이프
echo "print(42)" | $RK ida shell

# Multi-line script via heredoc / heredoc으로 멀티라인 스크립트
$RK ida shell <<'EOF'
count = 0
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if name.startswith("sub_"):
        count += 1
print("Unnamed functions: %d" % count)
EOF
# → Unnamed functions: 87
```

---

## 4. Script Files / 스크립트 파일

For reusable analysis, save scripts to `~/.revkit/scripts/ida/`. Organize by purpose.

재사용 가능한 분석을 위해 스크립트를 `~/.revkit/scripts/ida/`에 저장합니다. 목적별로 분류하세요.

```
~/.revkit/scripts/ida/
├── analysis/
│   ├── find_crypto_consts.py
│   └── list_large_funcs.py
├── search/
│   └── find_suspicious_strings.py
└── export/
    └── dump_all_names.py
```

Run a script file with `exec`:

스크립트 파일을 `exec`으로 실행:

```bash
# Run a script file (pass the .py path as the code argument)
# 스크립트 파일 실행 (.py 경로를 code 인자로 전달)
$RK ida exec ~/.revkit/scripts/ida/analysis/find_crypto_consts.py

# Short path — relative to ~/.revkit/scripts/ida/
# 짧은 경로 — ~/.revkit/scripts/ida/ 기준 상대 경로
$RK ida exec analysis/find_crypto_consts.py
```

---

## 5. Example: find_crypto_consts.py / 암호화 상수 탐지

Searches for well-known cryptographic constants (AES S-box, SHA-256 init vectors, etc.) in binary data segments.

바이너리 데이터 세그먼트에서 잘 알려진 암호화 상수(AES S-box, SHA-256 초기 벡터 등)를 검색합니다.

```python
# ~/.revkit/scripts/ida/analysis/find_crypto_consts.py
# Find cryptographic constants in data segments
# 데이터 세그먼트에서 암호화 상수 탐지

CRYPTO_CONSTS = {
    "AES S-box":    b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5",
    "SHA-256 init": b"\x67\xe6\x09\x6a\x85\xae\x67\xbb",
    "RC4 init":     b"\x00\x01\x02\x03\x04\x05\x06\x07",
}

results = []
for seg_ea in idautils.Segments():
    seg = ida_segment.getseg(seg_ea)
    seg_name = idc.get_segm_name(seg_ea)
    seg_bytes = idc.get_bytes(seg.start_ea, seg.size())
    if seg_bytes is None:
        continue
    for name, pattern in CRYPTO_CONSTS.items():
        offset = seg_bytes.find(pattern)
        if offset >= 0:
            addr = seg.start_ea + offset
            results.append((name, seg_name, hex(addr)))

if results:
    print("Crypto constants found / 암호화 상수 발견:")
    for name, seg, addr in results:
        print("  [%s] %s at %s" % (seg, name, addr))
else:
    print("No crypto constants found / 암호화 상수 없음")
```

---

## 6. Example: list_large_funcs.py / 대형 함수 목록

Lists functions above a size threshold — useful for finding complex logic.

크기 임계값을 초과하는 함수를 나열합니다 — 복잡한 로직을 찾는 데 유용합니다.

```python
# ~/.revkit/scripts/ida/analysis/list_large_funcs.py
# List functions larger than THRESHOLD bytes
# THRESHOLD 바이트보다 큰 함수 목록

THRESHOLD = 1024  # bytes

large = []
for ea in idautils.Functions():
    func = ida_funcs.get_func(ea)
    if func and (func.end_ea - func.start_ea) > THRESHOLD:
        name = idc.get_func_name(ea)
        size = func.end_ea - func.start_ea
        large.append((size, name, ea))

large.sort(reverse=True)
print("Functions > %d bytes (%d found):" % (THRESHOLD, len(large)))
for size, name, ea in large[:20]:
    print("  %6d  %s  %s" % (size, hex(ea), name))
```

---

## 7. Example: find_suspicious_strings.py / 의심 문자열 탐지

Scans strings for suspicious patterns — URLs, IP addresses, registry keys, shell commands.

문자열에서 의심스러운 패턴(URL, IP 주소, 레지스트리 키, 셸 명령)을 검색합니다.

```python
# ~/.revkit/scripts/ida/search/find_suspicious_strings.py
# Find suspicious strings in binary
# 바이너리에서 의심 문자열 탐색

import re

PATTERNS = {
    "URL":          re.compile(r"https?://[\w./\-?=&]+"),
    "IP address":   re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "Registry key": re.compile(r"HKEY_[\w\\]+"),
    "Shell cmd":    re.compile(r"(cmd\.exe|powershell|/bin/sh|/bin/bash)"),
}

print("Scanning strings for suspicious patterns...")
for s in idautils.Strings():
    text = str(s)
    for label, pattern in PATTERNS.items():
        if pattern.search(text):
            ea = s.ea
            refs = list(idautils.XrefsTo(ea))
            ref_str = ", ".join(hex(x.frm) for x in refs[:3])
            print("  [%s] %s @ %s  (refs: %s)" % (label, text[:80], hex(ea), ref_str))
```

---

## 8. Tips / 팁

**Return values**: `exec` captures stdout. Use `print()` for output. Return values are not captured.

**반환값**: `exec`은 stdout을 캡처합니다. 출력에는 `print()`를 사용하세요. 반환값은 캡처되지 않습니다.

**JSON output**: For machine-readable output, print JSON and parse it with `--json` or `jq`.

**JSON 출력**: 기계 가독성을 위해 JSON을 출력하고 `--json` 또는 `jq`로 파싱하세요.

```bash
# Output JSON from exec / exec에서 JSON 출력
$RK ida exec "
import json
funcs = [{'name': idc.get_func_name(ea), 'addr': hex(ea)}
         for ea in list(idautils.Functions())[:10]]
print(json.dumps(funcs, indent=2))
"
```

**Error handling**: Exceptions in exec code are caught and returned as error messages.

**에러 처리**: exec 코드의 예외는 포착되어 에러 메시지로 반환됩니다.

**Performance**: Long-running scripts block the RPC server. For heavy analysis, consider `batch` or `decompile-all`.

**성능**: 장시간 실행 스크립트는 RPC 서버를 블로킹합니다. 무거운 분석에는 `batch` 또는 `decompile-all`을 고려하세요.

---

**Next / 다음**: [08-jeb-exec-scripts.md](08-jeb-exec-scripts.md) — JEB exec scripting with Jython 2.7 / Jython 2.7 기반 JEB exec 스크립트
