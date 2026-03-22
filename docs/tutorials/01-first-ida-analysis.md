# Tutorial 01: First IDA Binary Analysis / 첫 IDA 바이너리 분석

Step-by-step guide to analyzing a Windows PE binary with revkit + IDA Pro.

revkit + IDA Pro로 Windows PE 바이너리를 분석하는 단계별 가이드.

> **Prerequisites / 사전 준비**: [00-install-setup.md](00-install-setup.md) completed / 완료

---

## Sample / 샘플

This tutorial uses `Samples/EXE/notepad.exe`. Replace with your own binary.

이 튜토리얼은 `Samples/EXE/notepad.exe`를 사용합니다. 자신의 바이너리로 대체 가능.

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. Start + Wait / 시작 + 대기

```bash
# Start the IDA headless server / IDA headless 서버 시작
$RK ida start Samples/EXE/notepad.exe
# → [+] Started ida (id=a3k2, pid=12345, spawn=default)
# id=a3k2 — this is your instance ID / 이것이 인스턴스 ID

# Wait for analysis to complete / 분석 완료 대기
$RK ida wait --timeout 180
# → [+] a3k2 is ready
```

> **How long?** For small binaries (~1MB), 3-10 seconds. Large binaries may take minutes.
>
> **얼마나?** 작은 바이너리(~1MB)는 3-10초. 큰 바이너리는 수 분 소요.

---

## 2. Explore / 탐색

### Summary / 요약

```bash
$RK ida summary
# Binary:      notepad.exe
# Functions:   521
# Strings:     621
# Imports:     340
# Segments:    10개 (.text, .rdata, .data, ...)
```

### Find Functions / 함수 찾기

```bash
# Search by name / 이름으로 검색
$RK ida find-func "main"
# → 4 matches: __scrt_common_main_seh, wWinMain, ...

# Search by regex / 정규식으로 검색
$RK ida find-func --regex "^sub_"
# → 0 matches (notepad has symbols / notepad은 심볼 있음)
# Stripped binaries will have many sub_ functions
# 스트립된 바이너리에서는 sub_ 함수가 많이 나옴
```

### Function Info / 함수 정보

```bash
$RK ida func-info 0x140010108
# Name:       wWinMain
# Address:    0x140010108 - 0x1400104A7
# Size:       927
# Return:     int
# Args:       HINSTANCE hInstance, ...
```

---

## 3. Decompile / 디컴파일

```bash
# Basic decompile / 기본 디컴파일
$RK ida decompile 0x140010108
# → C source code output (92 lines)
# → C 소스코드 출력 (92줄)

# With cross-references / 교차 참조 포함
$RK ida decompile 0x140010108 --with-xrefs
# → Code + "// --- Callers (2) ---" + "// --- Callees (13) ---"

# Save to file / 파일로 저장
$RK ida decompile 0x140010108 --out my_function.c
# → [*] Output saved to my_function.c

# Raw (no header comment) / 헤더 주석 없이
$RK ida decompile 0x140010108 --raw
```

### Disassembly / 디스어셈블리

```bash
$RK ida disasm 0x140010108 --count 20
# 0x140010108  48 89 5C 24 10  mov  [rsp-8+arg_8], rbx
# 0x14001010D  55              push rbp
# ...
```

### Bytes / 바이트

```bash
$RK ida bytes 0x140010108 --size 16
# Hex:    48 89 5C 24 10 55 56 57 ...
# Base64: SIlcJBBVVlc...
```

---

## 4. Cross-References / 교차 참조

```bash
# Both directions / 양방향
$RK ida xrefs 0x140010108 --direction both
# Xrefs TO (2): __scrt_common_main_seh, ...
# Xrefs FROM (1): ...

# Callers only / 호출자만
$RK ida callers 0x140010108

# Callees only / 피호출자만
$RK ida callees 0x140010108

# Call graph / 콜그래프
$RK ida callgraph 0x140010108 --depth 3
# → Mermaid format: graph LR, Nodes: 89, Edges: 261
```

---

## 5. Modify / 수정

### Rename / 이름 변경

```bash
$RK ida rename 0x140010108 my_main_function
# → [+] Renamed 0x140010108 -> my_main_function

# Verify / 확인
$RK ida func-info 0x140010108
# → Name: my_main_function
```

### Comment / 코멘트

```bash
$RK ida comment 0x140010108 "This is the main entry point"
# → [+] Comment set at 0x140010108

# Verify / 확인
$RK ida comments 0x140010108
# → Comment: This is the main entry point
```

### Batch Rename / 일괄 이름 변경

```bash
# Create JSON file / JSON 파일 생성
echo '[
  {"addr": "0x140010108", "name": "main_func"},
  {"addr": "0x1400019B0", "name": "crt_startup"}
]' > renames.json

$RK ida rename-batch --file renames.json
# → Total: 2, Success: 2, Failed: 0
```

---

## 6. Save + Stop / 저장 + 종료

```bash
# Save IDB / IDB 저장
$RK ida save
# → [+] Database saved: ...notepad.i64

# Stop instance / 인스턴스 종료
$RK ida stop
# → [*] Database saved for a3k2
# → [+] Stopped a3k2

# Verify no processes remain / 프로세스 잔존 확인
$RK ida list
# → [*] No active instances.
```

---

## 7. Error Handling / 에러 처리

Try these to learn how errors look / 에러가 어떻게 보이는지 체험:

```bash
# Invalid address / 잘못된 주소
$RK ida decompile 0xDEADBEEF
# → [-] RPC error: No function at 0xDEADBEEF

# Nonexistent file / 존재하지 않는 파일
$RK ida start /nonexistent/file.exe
# → [-] File not found: /nonexistent/file.exe

# No instance running / 인스턴스 없이 실행
$RK ida decompile 0x401000
# → [-] No active instances. Use 'start' first.
```

All errors are clean messages, not Python tracebacks.

모든 에러는 깔끔한 메시지이며 Python traceback이 아닙니다.

---

## 8. Useful Options / 유용한 옵션

```bash
# JSON output / JSON 출력
$RK --json ida list
# → {"ok": true, "engine": "ida", "command": "list", "data": [...]}

# Save output to file / 출력을 파일에 저장
$RK --out result.txt ida summary

# Verbose logging / 상세 로깅
$RK -v ida list
# → DEBUG level logs shown / DEBUG 레벨 로그 표시

# Quiet mode / 조용한 모드
$RK -q ida list
# → No output / 출력 없음
```

---

## Summary / 요약

```
start → wait → [explore/modify/decompile] → save → stop

시작 → 대기 → [탐색/수정/디컴파일] → 저장 → 종료
```

| What you learned / 배운 것 | Commands / 명령 |
| --- | --- |
| Instance lifecycle / 인스턴스 생명주기 | `start`, `wait`, `stop`, `list`, `status` |
| Function discovery / 함수 탐색 | `summary`, `find-func`, `func-info` |
| Decompilation / 디컴파일 | `decompile`, `disasm`, `bytes` |
| Cross-references / 교차 참조 | `xrefs`, `callers`, `callees`, `callgraph` |
| Modification / 수정 | `rename`, `comment`, `rename-batch` |
| Error handling / 에러 처리 | Clean error messages / 깔끔한 에러 메시지 |

---

## Next / 다음

- [02-first-jeb-analysis.md](02-first-jeb-analysis.md) — JEB APK analysis / JEB APK 분석
- [03-binary-comparison.md](03-binary-comparison.md) — Comparing binaries / 바이너리 비교
