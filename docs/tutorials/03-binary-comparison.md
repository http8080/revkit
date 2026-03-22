# Tutorial 03: Binary Comparison / 바이너리 비교

Step-by-step guide to comparing two binaries using revkit + IDA Pro.

revkit + IDA Pro로 두 바이너리를 비교하는 단계별 가이드.

> **Prerequisites / 사전 준비**: [01-first-ida-analysis.md](01-first-ida-analysis.md) completed / 완료

---

## Concept / 개념

When analyzing patched or updated binaries, you often need to find what changed. revkit supports running multiple IDA instances simultaneously and comparing them.

패치되거나 업데이트된 바이너리를 분석할 때 변경된 부분을 찾아야 합니다. revkit은 여러 IDA 인스턴스를 동시에 실행하고 비교할 수 있습니다.

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. Start Two Instances / 두 인스턴스 시작

```bash
# Start instance for the original binary / 원본 바이너리 인스턴스 시작
$RK ida start Samples/EXE/notepad.exe
# → [+] Started ida (id=a1b2, pid=11111, spawn=default)

# Start instance for the patched binary / 패치된 바이너리 인스턴스 시작
$RK ida start Samples/EXE/notepad_patched.exe
# → [+] Started ida (id=c3d4, pid=22222, spawn=default)

# Wait for both / 둘 다 대기
$RK ida wait --timeout 180
# → [+] a1b2 is ready
# → [+] c3d4 is ready
```

---

## 2. Multi-Instance Management / 다중 인스턴스 관리

With multiple instances running, use the `-i` flag to target a specific one.

여러 인스턴스가 실행 중일 때 `-i` 플래그로 특정 인스턴스를 지정합니다.

```bash
# List all active instances / 모든 활성 인스턴스 목록
$RK ida list
# ID    PID    Binary                   Port   Status
# a1b2  11111  notepad.exe              18100  ready
# c3d4  22222  notepad_patched.exe      18101  ready

# Target a specific instance with -i / -i로 특정 인스턴스 지정
$RK ida summary -i a1b2
# Binary:    notepad.exe
# Functions: 521

$RK ida summary -i c3d4
# Binary:    notepad_patched.exe
# Functions: 523

# Status of a specific instance / 특정 인스턴스 상태
$RK ida status -i c3d4
# Instance:  c3d4
# Binary:    notepad_patched.exe
# Uptime:    45s
# Functions: 523
```

> **Tip**: Without `-i`, commands target the most recently started instance.
>
> **팁**: `-i` 없이 실행하면 가장 최근 시작된 인스턴스가 대상입니다.

---

## 3. Diff / 차이점 비교

### Quick Diff / 빠른 비교

```bash
# Compare two instances / 두 인스턴스 비교
$RK ida diff a1b2 c3d4
# Summary:
#   Matched:     498 functions
#   Modified:    15 functions
#   Added:       8 functions (in target)
#   Removed:     6 functions (in source)
#
# Modified Functions:
#   0x140010108  wWinMain         (similarity: 87%)
#   0x14001A200  DialogProc       (similarity: 72%)
#   ...
```

The diff command gives you a high-level overview of what changed between the two binaries.

diff 명령은 두 바이너리 간 변경 사항의 개요를 제공합니다.

---

### Code Diff / 코드 차이점

```bash
# Compare decompiled code of a specific function / 특정 함수의 디컴파일 코드 비교
$RK ida code-diff a1b2 c3d4 --functions wWinMain
# --- a1b2/wWinMain
# +++ c3d4/wWinMain
# @@ -12,7 +12,9 @@
#    hWnd = CreateWindowExW(0, ...);
# -  if ( !hWnd )
# -    return 0;
# +  if ( !hWnd ) {
# +    LogError("Window creation failed");
# +    return -1;
# +  }
```

This shows a unified diff of the decompiled C code, making it easy to spot exact changes.

디컴파일된 C 코드의 통합 diff를 보여주어 정확한 변경점을 쉽게 파악할 수 있습니다.

---

### Compare / 상세 비교

```bash
# Detailed comparison with similarity scores / 유사도 점수와 상세 비교
$RK ida compare Samples/EXE/notepad.exe Samples/EXE/notepad_patched.exe
# ┌─────────────┬──────────┬──────────┬────────────┐
# │ Function    │ Source   │ Target   │ Similarity │
# ├─────────────┼──────────┼──────────┼────────────┤
# │ wWinMain    │ 0x14001… │ 0x14001… │ 87%        │
# │ DialogProc  │ 0x1400A… │ 0x1400A… │ 72%        │
# │ ParseCmd    │ 0x1400B… │ 0x1400B… │ 95%        │
# └─────────────┴──────────┴──────────┴────────────┘

# Save comparison report / 비교 리포트 저장
$RK ida compare Samples/EXE/notepad.exe Samples/EXE/notepad_patched.exe --out comparison_report.md
# → [*] Output saved to comparison_report.md
```

---

## 4. Investigating Differences / 차이점 조사

Once you identify changed functions, dig deeper with standard commands.

변경된 함수를 식별하면 기본 명령으로 더 깊이 조사합니다.

```bash
# Decompile the modified function in each instance / 각 인스턴스에서 수정된 함수 디컴파일
$RK ida decompile 0x140010108 -i a1b2 --out original_main.c
$RK ida decompile 0x140010108 -i c3d4 --out patched_main.c

# Check cross-references in the patched version / 패치 버전의 교차 참조 확인
$RK ida xrefs 0x14001A200 -i c3d4 --direction both
# → New callers found from added functions / 추가된 함수에서 새 호출자 발견

# Examine a newly added function / 새로 추가된 함수 조사
$RK ida func-info 0x14001C000 -i c3d4
# → Name: LogError (new function / 새 함수)
```

---

## 5. Stop All / 전체 종료

```bash
# Stop individual instances / 개별 인스턴스 종료
$RK ida stop -i a1b2
# → [+] Stopped a1b2

$RK ida stop -i c3d4
# → [+] Stopped c3d4

# Verify / 확인
$RK ida list
# → [*] No active instances.
```

---

## Summary / 요약

```
start binary_a → start binary_b → diff → code-diff → compare → stop

시작(A) → 시작(B) → 차이비교 → 코드비교 → 상세비교 → 종료
```

| What you learned / 배운 것 | Commands / 명령 |
| --- | --- |
| Multi-instance / 다중 인스턴스 | `start` (multiple), `list`, `-i` flag |
| Quick diff / 빠른 비교 | `diff IID1 IID2` |
| Code-level diff / 코드 수준 비교 | `code-diff IID1 IID2 --functions` |
| Detailed comparison / 상세 비교 | `compare BINARY_A BINARY_B` |
| Cleanup / 정리 | `stop -i IID` |

---

## Next / 다음

- [04-batch-analysis.md](04-batch-analysis.md) -- Batch analysis / 일괄 분석
- [05-type-system.md](05-type-system.md) -- IDA type system / IDA 타입 시스템
