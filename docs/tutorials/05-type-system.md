# Tutorial 05: IDA Type System / IDA 타입 시스템

Step-by-step guide to working with structs, enums, vtables, and type signatures in IDA via revkit.

revkit을 통해 IDA에서 구조체, 열거형, vtable, 타입 시그니처를 다루는 단계별 가이드.

> **Prerequisites / 사전 준비**: [01-first-ida-analysis.md](01-first-ida-analysis.md) completed / 완료

---

## Concept / 개념

Reverse engineering often requires defining custom types to make decompiled code readable. IDA's type system supports structs, enums, vtables, and function signatures.

리버스 엔지니어링에서는 디컴파일된 코드를 읽기 좋게 만들기 위해 커스텀 타입 정의가 필요합니다. IDA 타입 시스템은 구조체, 열거형, vtable, 함수 시그니처를 지원합니다.

```bash
RK="python -m revkit.tools.cli.main"

# Start an instance / 인스턴스 시작
$RK ida start Samples/EXE/notepad.exe
$RK ida wait
```

---

## 1. Structs / 구조체

### List Structs / 구조체 목록

```bash
# List all defined structs / 정의된 모든 구조체 목록
$RK ida structs
# Name              Size    Members
# WNDCLASSEXW       80      12
# LOGFONTW          92      14
# RECT              16      4
# CREATESTRUCTW     48      11
```

### Create and Show / 생성 및 확인

```bash
# Create a new struct / 새 구조체 생성
$RK ida structs --action create --name "MyConfig" --members magic:DWORD version:WORD flags:WORD size:DWORD
# → [+] Created struct MyConfig (12 bytes, 4 members)

# Show struct details / 구조체 상세 정보
$RK ida structs --action show --name "MyConfig"
# Offset  Type    Name
# 0x00    DWORD   magic
# 0x04    WORD    version
# 0x06    WORD    flags
# 0x08    DWORD   size
# Total size: 12 bytes
```

---

## 2. Enums / 열거형

### List Enums / 열거형 목록

```bash
# List all defined enums / 정의된 모든 열거형 목록
$RK ida enums
# Name              Members
# BOOL              2
# SW_SHOW           11
```

### Create and Show / 생성 및 확인

```bash
# Create a new enum / 새 열거형 생성
$RK ida enums --action create --name "ConfigFlags" --members FLAG_NONE=0 FLAG_DEBUG=1 FLAG_VERBOSE=2 FLAG_TRACE=4
# → [+] Created enum ConfigFlags (4 members)

# Show enum details / 열거형 상세 정보
$RK ida enums --action show --name "ConfigFlags"
# Value   Name
# 0x0     FLAG_NONE
# 0x1     FLAG_DEBUG
# 0x2     FLAG_VERBOSE
# 0x4     FLAG_TRACE
```

---

## 3. Type Info / 타입 정보

```bash
# Get type information for a function / 함수의 타입 정보 조회
$RK ida type-info 0x140010108
# Type:     int __fastcall(HINSTANCE hInstance, HINSTANCE hPrevInstance,
#           LPWSTR lpCmdLine, int nShowCmd)
# Size:     927 bytes
# Locals:   12

# Set function type signature / 함수 타입 시그니처 설정
$RK ida set-type 0x140010108 "int __cdecl myMain(int argc, char **argv)"
# → [+] Type set at 0x140010108

# Verify the change / 변경 확인
$RK ida type-info 0x140010108
# Type:     int __cdecl myMain(int argc, char **argv)
```

---

## 4. VTables / 가상 함수 테이블

```bash
# List detected vtables / 감지된 vtable 목록
$RK ida vtables
# Address       Class           Entries
# 0x140020100   CMainWindow     12
# 0x140020180   CDialogHelper   5

# Show all vtable entries / 모든 vtable 항목 표시
$RK ida vtables
# Index  Address       Name
# 0      0x14000A100   CMainWindow::OnCreate
# 1      0x14000A200   CMainWindow::OnDestroy
# 2      0x14000A300   CMainWindow::OnPaint
# ...
```

Vtable recovery helps reconstruct C++ class hierarchies in stripped binaries.

vtable 복구는 스트립된 바이너리에서 C++ 클래스 계층 구조를 재구성하는 데 도움이 됩니다.

---

## 5. Signatures / 시그니처

```bash
# List applied signature libraries / 적용된 시그니처 라이브러리 목록
$RK ida sigs
# Name                  Matches
# vc64_14               142
# msvcrt_14             89

# Apply a new signature library / 새 시그니처 라이브러리 적용
$RK ida sigs --action apply vc64_14
# → [+] Applied vc64_14: 142 functions matched

# List signature libraries / 시그니처 라이브러리 목록
$RK ida sigs --action list
# Name                  Matches
# vc64_14               142
# msvcrt_14             89
```

---

## 6. Code Structure / 코드 구조

### Basic Blocks / 기본 블록

```bash
# List basic blocks of a function / 함수의 기본 블록 목록
$RK ida basic-blocks 0x140010108
# Block     Start        End          Size   Successors
# 0         0x140010108  0x140010142  58     1, 2
# 1         0x140010142  0x140010180  62     3
# 2         0x140010180  0x1400101A0  32     4
# ...
# Total: 24 blocks
```

Basic block analysis is useful for understanding control flow and code coverage.

기본 블록 분석은 제어 흐름과 코드 커버리지를 이해하는 데 유용합니다.

### Stack Frame / 스택 프레임

```bash
# Show stack frame layout / 스택 프레임 레이아웃 표시
$RK ida stack-frame 0x140010108
# Offset   Size  Type       Name
# -0x80    8     __int64    var_80
# -0x78    8     __int64    var_78
# -0x70    4     int        nCmdShow
# ...
# +0x08    8     __int64    arg_0
# +0x10    8     __int64    arg_8
# Frame size: 0x90
```

---

## 7. Cleanup / 정리

```bash
$RK ida save
# → [+] Database saved

$RK ida stop
# → [+] Stopped
```

---

## Summary / 요약

```
structs → enums → set-type → vtables → sigs → basic-blocks → stack-frame

구조체 → 열거형 → 타입 설정 → vtable → 시그니처 → 기본 블록 → 스택 프레임
```

| What you learned / 배운 것 | Commands / 명령 |
| --- | --- |
| Struct management / 구조체 관리 | `structs --action create`, `structs --action show` |
| Enum management / 열거형 관리 | `enums --action create`, `enums --action show` |
| Type setting / 타입 설정 | `type-info`, `set-type` |
| VTable analysis / vtable 분석 | `vtables` |
| Signature matching / 시그니처 매칭 | `sigs --action apply`, `sigs --action list` |
| Code structure / 코드 구조 | `basic-blocks`, `stack-frame` |

---

## Next / 다음

- [06-annotations-snapshots.md](06-annotations-snapshots.md) -- Annotations & snapshots / 주석 & 스냅샷
- [03-binary-comparison.md](03-binary-comparison.md) -- Binary comparison / 바이너리 비교
