# Tutorial 08: JEB Exec Scripts / JEB exec 스크립트 작성

Run custom analysis code on a live JEB headless server. JEB scripts run under Jython 2.7 — pay attention to syntax constraints.

라이브 JEB headless 서버에서 커스텀 분석 코드를 실행합니다. JEB 스크립트는 Jython 2.7에서 실행되므로 문법 제약에 주의하세요.

> **Prerequisites / 사전 준비**: A running JEB instance (`$RK jeb start` + `$RK jeb wait`) / 실행 중인 JEB 인스턴스

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. Jython 2.7 Constraints / Jython 2.7 제약 사항

JEB's embedded scripting engine uses Jython 2.7, not CPython 3. This affects all code inside `exec`.

JEB의 내장 스크립팅 엔진은 CPython 3이 아닌 Jython 2.7을 사용합니다. `exec` 내의 모든 코드에 영향을 미칩니다.

```python
# ❌ FORBIDDEN — Python 3 syntax / 금지 — Python 3 문법
f"hello {name}"              # f-strings
def foo(x: int) -> str:      # type hints
result := compute()          # walrus operator
print("x", flush=True)       # flush keyword

# ✅ ALLOWED — Jython 2.7 syntax / 허용 — Jython 2.7 문법
"hello %s" % name            # %-formatting
"hello {}".format(name)      # .format()
def foo(x):                  # no type hints
result = compute()           # normal assignment
print("x")                   # no flush
```

---

## 2. Inline Exec / 인라인 실행

Pass Jython code to the JEB server. The JEB API is fully accessible.

Jython 코드를 JEB 서버에 전달합니다. JEB API에 완전히 접근 가능합니다.

```bash
# Count all classes / 전체 클래스 수 세기
$RK jeb exec "
units = prj.findUnits(DexDecompilerUnit)
for dex in units:
    classes = dex.getDecompiledClasses()
    print('Classes: %d' % len(classes))
"

# List package names / 패키지 이름 나열
$RK jeb exec "
seen = set()
for unit in prj.findUnits(DexUnit):
    for cls in unit.getClasses():
        sig = cls.getSignature(False)
        pkg = sig.rsplit('/', 1)[0] if '/' in sig else '(default)'
        seen.add(pkg)
for pkg in sorted(seen)[:10]:
    print(pkg)
"
```

> **Security / 보안**: `exec` requires `security.exec_enabled: true` (or `jeb.security.exec_enabled: true`) in `~/.revkit/config.json`. Default is `false`.
>
> `exec`은 `~/.revkit/config.json`에서 `security.exec_enabled: true` 설정이 필요합니다. 기본값은 `false`.

---

## 3. Available Context Variables / 사용 가능한 컨텍스트 변수

Inside `exec`, the JEB server injects these variables automatically.

`exec` 내부에서 JEB 서버가 자동으로 주입하는 변수들입니다.

| Variable / 변수 | Type / 타입 | Description / 설명 |
|---|---|---|
| `prj` | `IRuntimeProject` | Current project / 현재 프로젝트 |
| `ctx` | `IEnginesContext` | Engines context / 엔진 컨텍스트 |
| `DexUnit` | class | DEX unit type / DEX 유닛 타입 |
| `DexDecompilerUnit` | class | Decompiler unit type / 디컴파일러 유닛 타입 |

---

## 4. Using server.dispatch() for RPC / server.dispatch()로 RPC 호출

Inside exec scripts, you can call any registered RPC method using `server.dispatch()`. This is useful for combining built-in operations with custom logic.

exec 스크립트 내에서 `server.dispatch()`를 사용하여 등록된 RPC 메서드를 호출할 수 있습니다. 내장 작업과 커스텀 로직을 결합할 때 유용합니다.

```bash
$RK jeb exec "
# Decompile a class via RPC / RPC로 클래스 디컴파일
result = server.dispatch('decompile', {'class_sig': 'Lcom/example/MainActivity;'})
print(result.get('code', 'No code'))
"

$RK jeb exec "
# Get xrefs then do custom processing / xrefs 조회 후 커스텀 처리
refs = server.dispatch('xrefs', {
    'sig': 'Lcom/example/Foo;->bar()V',
    'direction': 'to'
})
for ref in refs.get('xrefs', []):
    print('Caller: %s' % ref.get('from', 'unknown'))
"
```

---

## 5. Script Files / 스크립트 파일

Save reusable scripts to `~/.revkit/scripts/jeb/`. Remember: Jython 2.7 only.

재사용 가능한 스크립트를 `~/.revkit/scripts/jeb/`에 저장하세요. Jython 2.7만 사용 가능합니다.

```
~/.revkit/scripts/jeb/
├── analysis/
│   ├── list_activities.py
│   └── find_native_methods.py
├── security/
│   └── check_permissions.py
└── export/
    └── dump_class_hierarchy.py
```

```bash
# Run a script file (pass the .py path as the code argument)
# 스크립트 파일 실행 (.py 경로를 code 인자로 전달)
$RK jeb exec ~/.revkit/scripts/jeb/analysis/find_native_methods.py

# Short path — relative to ~/.revkit/scripts/jeb/
# 짧은 경로 — ~/.revkit/scripts/jeb/ 기준 상대 경로
$RK jeb exec analysis/find_native_methods.py
```

---

## 6. Example: find_native_methods.py / 네이티브 메서드 탐지

Lists all JNI native methods — potential entry points to native libraries.

모든 JNI 네이티브 메서드를 나열합니다 — 네이티브 라이브러리의 잠재적 진입점입니다.

```python
# ~/.revkit/scripts/jeb/analysis/find_native_methods.py
# Find all native methods in DEX / DEX에서 모든 네이티브 메서드 찾기
# Jython 2.7 — no f-strings, no type hints

count = 0
for unit in prj.findUnits(DexUnit):
    for cls in unit.getClasses():
        for method in cls.getMethods():
            flags = method.getAccessFlags()
            # ACC_NATIVE = 0x0100
            if flags & 0x0100:
                sig = method.getSignature(False)
                print("  NATIVE: %s" % sig)
                count += 1

print("\nTotal native methods: %d" % count)
```

---

## 7. Example: check_permissions.py / 권한 검사

Checks AndroidManifest.xml for dangerous permissions.

AndroidManifest.xml에서 위험한 권한을 확인합니다.

```python
# ~/.revkit/scripts/jeb/security/check_permissions.py
# Check for dangerous Android permissions / 위험한 Android 권한 확인
# Jython 2.7

DANGEROUS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.INSTALL_PACKAGES",
]

# Use RPC to get permissions / RPC로 권한 조회
result = server.dispatch("permissions", {})
perms = result.get("permissions", [])

print("=== Permission Audit / 권한 감사 ===")
print("Total permissions: %d" % len(perms))

found = []
for p in perms:
    name = p if isinstance(p, str) else p.get("name", "")
    if name in DANGEROUS:
        found.append(name)

if found:
    print("\nDANGEROUS permissions found / 위험 권한 발견:")
    for p in found:
        print("  [!] %s" % p)
else:
    print("\nNo dangerous permissions / 위험 권한 없음")
```

---

## 8. Example: dump_class_hierarchy.py / 클래스 계층 추출

```python
# ~/.revkit/scripts/jeb/export/dump_class_hierarchy.py
# Dump class inheritance tree / 클래스 상속 트리 추출
# Jython 2.7

hierarchy = {}
for unit in prj.findUnits(DexUnit):
    for cls in unit.getClasses():
        sig = cls.getSignature(False)
        superSig = cls.getSuperSignature()
        if superSig:
            hierarchy.setdefault(superSig, []).append(sig)

# Print tree for common base classes / 공통 베이스 클래스의 트리 출력
for base, children in sorted(hierarchy.items()):
    if len(children) >= 3:
        print("%s (%d subclasses)" % (base, len(children)))
        for child in children[:5]:
            print("  +-- %s" % child)
        if len(children) > 5:
            print("  ... and %d more" % (len(children) - 5))
```

---

## 9. Common Pitfalls / 자주 하는 실수

| Mistake / 실수 | Fix / 해결 |
|---|---|
| Using `f"..."` strings | Use `"...%s" % val` or `"...{}".format(val)` |
| `print(x, flush=True)` | `print(x)` only (no flush kwarg in Jython) |
| `from typing import ...` | Remove type hints entirely / 타입 힌트 완전 제거 |
| `x := expr` | `x = expr` |
| `dict | other_dict` | `d = dict(a); d.update(b)` |
| Unicode errors on Windows | Use ASCII strings in print / print에서 ASCII 문자열 사용 |

---

## 10. Tips / 팁

**Output format**: Use `print()` for output. The server captures stdout and returns it as the exec result.

**출력 형식**: 출력에는 `print()`를 사용하세요. 서버가 stdout을 캡처하여 exec 결과로 반환합니다.

**Timeout**: Long-running scripts may hit the RPC timeout (default 60s). For heavy analysis, use `batch` or `decompile-all`.

**타임아웃**: 장시간 실행 스크립트는 RPC 타임아웃(기본 60초)에 걸릴 수 있습니다. 무거운 분석에는 `batch` 또는 `decompile-all`을 사용하세요.

**Debugging**: Test small snippets inline before putting them in script files.

**디버깅**: 스크립트 파일에 넣기 전에 작은 코드 조각을 인라인으로 테스트하세요.

---

**Next / 다음**: [09-rpc-automation.md](09-rpc-automation.md) — Direct RPC calls with curl / curl로 RPC 직접 호출
