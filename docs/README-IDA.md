# revkit — IDA Pro Engine

Detailed documentation for IDA Pro engine commands, RPC methods, and configuration.

IDA Pro 엔진 명령어, RPC 메서드, 설정에 대한 상세 문서.

---

## Table of Contents

- [Overview / 개요](#overview--개요)
- [Setup / 설정](#setup--설정)
- [Instance Management / 인스턴스 관리](#instance-management--인스턴스-관리)
- [Analysis Commands / 분석 명령어](#analysis-commands--분석-명령어)
- [Modification Commands / 수정 명령어](#modification-commands--수정-명령어)
- [Type Commands / 타입 명령어](#type-commands--타입-명령어)
- [Advanced Commands / 고급 명령어](#advanced-commands--고급-명령어)
- [Diff Commands / 비교 명령어](#diff-commands--비교-명령어)
- [Report Commands / 보고서 명령어](#report-commands--보고서-명령어)
- [Batch Commands / 배치 명령어](#batch-commands--배치-명령어)
- [Utility Commands / 유틸리티 명령어](#utility-commands--유틸리티-명령어)
- [RPC Methods / RPC 메서드](#rpc-methods--rpc-메서드)
- [Configuration / 설정 상세](#configuration--설정-상세)

---

## Overview / 개요

The IDA engine provides headless binary analysis for PE, ELF, and Mach-O binaries through IDAPython (idalib).

IDA 엔진은 IDAPython(idalib)을 통해 PE, ELF, Mach-O 바이너리의 headless 분석을 제공한다.

| Feature | Value |
| ------- | ----- |
| Supported formats / 지원 포맷 | PE, ELF, Mach-O |
| DB extension / DB 확장자 | `.i64` |
| Identifier / 식별자 | Memory address (`0x401000`) |
| Instance ID / 인스턴스 ID | 4-digit hex (`a3f2`) |
| Server runtime / 서버 런타임 | CPython 3.12+ |
| Command modules / 명령어 모듈 | 9 |

### Architecture / 아키텍처

```text
revkit ida <command> [options]
       │
       ▼
  CmdContext(args, config, config_path, engine)
       │
       ▼
  cmd_proxy_*() ──── HTTP POST ──── IDA Server (JSON-RPC)
       │                                    │
       ▼                                    ▼
  CLI output / file save           IDAPython API (ida_*)
```

### Performance / 성능

IDA 서버는 다중 캐시 레이어를 사용하여 반복 연산을 최적화한다.

| Cache | Size | Invalidation |
|-------|------|-------------|
| Decompiler cache (LRU) | 500 functions | rename, set_type, batch rename |
| Function name cache (LRU) | 5,000 entries | rename, batch rename |
| Callee memoization | per-session | callgraph request |

캐시 적중 시 디컴파일: ~0.1ms (cold: 10-100ms). 콜그래프/xref 조회 시 함수명 룩업 0.001ms.

---

## Setup / 설정

### Prerequisites / 사전 요구사항

- **IDA Pro 9.3+** with idalib (headless API)
- **Python 3.12+**
- **License**: IDA Pro commercial license required / IDA Pro 상용 라이선스 필요

### Configuration / 설정

`~/.revkit/config.json`:

```json
{
    "ida": {
        "install_dir": "/opt/ida",
        "security": { "exec_enabled": true }
    }
}
```

| Key | Description / 설명 | Default |
| --- | ------------------ | ------- |
| `ida.install_dir` | IDA Pro installation directory / 설치 경로 | (required) |
| `ida.security.exec_enabled` | Allow `exec` / `shell` command for this engine / 이 엔진에서 exec 명령 허용 | inherits `security.exec_enabled` |

### Verify Installation / 설치 확인

```bash
# Check idalib is importable / import 가능 여부 확인
python -c "import ida_loader; print('OK')"

# Verify via revkit / revkit으로 확인
revkit ida check
```

> idalib is bundled with IDA Pro 9.3+. It includes `ida_loader`, `ida_hexrays`, `ida_funcs`, etc.
>
> idalib은 IDA Pro 9.3+에 번들되며, `ida_loader`, `ida_hexrays`, `ida_funcs` 등의 모듈을 포함한다.

---

## Instance Management / 인스턴스 관리

### `start` — Start Analysis Server / 분석 서버 시작

```bash
revkit ida start <binary> [--force] [--fresh] [--arch HINT] [--idb-dir DIR]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `binary` | Path to PE/ELF/Mach-O binary / 바이너리 경로 |
| `--force` | Overwrite existing IDB / 기존 IDB 무시 |
| `--fresh` | Create new IDB from scratch / IDB 새로 생성 |
| `--arch HINT` | Architecture hint / 아키텍처 힌트 |
| `--idb-dir DIR` | Custom IDB directory / 커스텀 IDB 경로 |

```bash
# Examples
revkit ida start /path/to/sample.exe
revkit ida start firmware.bin --arch arm64 --fresh
```

### `stop` — Stop Instance / 인스턴스 중지

```bash
revkit ida stop -i <instance_id>
revkit ida stop -b sample.exe     # resolve by binary name / 바이너리명으로 해석
```

Sends `save_db` RPC (with `analysis.stop_timeout` timeout) before `stop` to ensure the IDB is saved. Waits for process exit via polling-based `_wait_for_exit` (default: `analysis.stop_timeout` = 30s); force kills the **entire process tree** on timeout (`psutil.children(recursive=True)` + `taskkill /F /T`). This ensures IDA temp files (`.id0/.id1/.id2/.nam/.til`) are cleaned up properly.

중지 전에 `save_db` RPC를 호출하여 IDB를 저장한다 (`analysis.stop_timeout` 타임아웃 적용). 폴링 방식으로 프로세스 종료를 대기하며 (기본: 30초), 타임아웃 시 **프로세스 트리 전체**를 강제 종료한다 (`psutil.children(recursive=True)` + `taskkill /F /T`).

> **Save guarantee / 저장 보장**: IDA uses `atexit.register(cleanup)` with `close_database(save=True)`, so the database is saved regardless of how the process terminates. / IDA는 `atexit.register(cleanup)` + `close_database(save=True)`로 프로세스 종료 방식에 관계없이 DB 저장을 보장한다.

### `restart` — Restart Instance / 인스턴스 재시작

```bash
revkit ida restart -i <id> [--fresh]
```

### `list` — List Active Instances / 활성 인스턴스 목록

```bash
revkit ida list [--json]
```

Output / 출력:

```text
ID     State    PID    Port    Binary
a3f2   ready    12345  18861   sample.exe
b1c4   analyzing 12346 18862   firmware.bin
```

### `status` — Instance Status / 인스턴스 상태

```bash
revkit ida status -i <id>
```

When the server is in `ready` state, queries the RPC `status` method and shows live server info: `func_count`, `ida_version`, `decompiler_available`, `uptime`, `binary_md5`.

서버가 `ready` 상태이면 RPC `status` 메서드를 쿼리하여 실시간 서버 정보를 표시한다.

### `wait` — Wait for Ready / ready 대기

```bash
revkit ida wait -i <id> [--timeout 300]
```

### `logs` — View Logs / 로그 조회

```bash
revkit ida logs -i <id> [--tail 50] [--follow]
```

### `cleanup` — Clean Stale Resources / 오래된 리소스 정리

```bash
revkit ida cleanup [--dry-run]
```

Kills orphaned `ida_server` processes not tracked in the registry (via `psutil`), cleans IDA temp files (`.id0/.id1/.id2/.nam/.til`) from inactive IDB directories, and removes stale registry entries.

레지스트리에 없는 고아 `ida_server` 프로세스를 종료하고, 비활성 IDB 디렉터리에서 IDA 임시 파일(`.id0/.id1/.id2/.nam/.til`)을 정리하며, 오래된 레지스트리 항목을 제거한다.

### `init` — Initialize Directories / 디렉터리 초기화

```bash
revkit ida init
```

### `check` — Verify Environment / 환경 검증

```bash
revkit ida check
```

Checks / 검증 항목: Python version, IDA installation, idalib availability, dependencies.

---

## Analysis Commands / 분석 명령어

### `decompile` — Decompile Function / 함수 decompile

```bash
revkit ida decompile <addr> [-i ID] [--with-xrefs] [--raw] [--markdown] [--out PATH]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `addr` | Function address (hex) / 함수 주소 |
| `--with-xrefs` | Include callers/callees / 호출자·피호출자 포함 |
| `--raw` | Raw output without header / 헤더 없이 출력 |
| `--markdown` | Markdown format output / Markdown 형식 출력 |
| `--out PATH` | Save to file / 파일로 저장 |

```bash
revkit ida decompile 0x401000
revkit ida decompile 0x401000 --with-xrefs --out func.c
```

Returns / 반환: `{addr, name, code, callers?, callees?, saved_to?}`

### `decompile-batch` — Batch Decompile / 배치 decompile

```bash
revkit ida decompile-batch <addr1> <addr2> ... [--out FILE]
```

### `decompile-all` — Decompile All Functions / 전체 함수 decompile

```bash
revkit ida decompile-all --out output.c [--filter PATTERN] [--split] [--include-thunks] [--include-libs]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `--out` | Output file path / 출력 파일 경로 |
| `--filter` | Function name filter / 함수 이름 필터 |
| `--split` | Split into separate files / 개별 파일로 분리 |
| `--include-thunks` | Include thunk functions / thunk 함수 포함 |
| `--include-libs` | Include library functions / 라이브러리 함수 포함 |

### `disasm` — Disassembly / 디스어셈블리

```bash
revkit ida disasm <addr> [--count 10] [--out FILE]
```

Returns / 반환: `{addr, count, lines: [{addr, bytes, insn}]}`

### `segments` — Memory Segments / 메모리 세그먼트 목록

```bash
revkit ida segments [--out PATH]
```

Returns / 반환: `{data: [{start_addr, end_addr, name, class, size, perm}]}`

### `imagebase` — Get Image Base / 바이너리 기본 주소

```bash
revkit ida imagebase
```

### `func-info` — Function Info / 함수 상세 정보

```bash
revkit ida func-info <addr>
```

Returns / 반환: `{name, start_ea, end_ea, size, is_thunk, calling_convention, return_type, args}`

### `find-func` — Search Function by Name / 함수 이름으로 검색

```bash
revkit ida find-func <name> [--regex] [--max N] [--out PATH]
```

기본 동작은 **대소문자 무시 substring 매칭**. `--regex` 옵션을 명시해야 정규식 매칭이 활성화됨.

```bash
# substring 검색 (기본) — "sub"가 포함된 모든 함수
revkit ida find-func "sub"

# regex 검색 — ^sub_로 시작하는 함수 (IDA 자동 이름)
revkit ida find-func --regex "^sub_"
```

> **주의**: `--regex` 없이 `^sub_`를 검색하면 substring 매칭이 적용되어 문자 그대로 `^sub_`를
> 찾으므로 0 matches가 됨. PDB 심볼이 완비된 바이너리(notepad.exe 등)에서는 `sub_` 접두사
> 함수가 없어 `--regex "^sub_"`도 0 matches가 정상. stripped SO/Mach-O에서는 `sub_` 함수가 존재함.

### `bytes` — Read Bytes / 바이트 읽기

```bash
revkit ida bytes <addr> [--size 16]
```

Returns / 반환: `{addr, hex, raw_b64}`

### `find-pattern` — Pattern Search / 패턴 검색

```bash
revkit ida find-pattern "48 89 C3" [--max N] [--out PATH]
```

### `xrefs` — Cross References

```bash
revkit ida xrefs <addr> [--direction to|from|both]
```

### `callers` — Get Callers / 호출자 목록

```bash
revkit ida callers <addr>
```

### `callees` — Get Callees / 피호출자 목록

```bash
revkit ida callees <addr>
```

### `comments` — Get Comments / 주석 조회

```bash
revkit ida comments <addr>
```

### `summary` — Binary Summary / 바이너리 종합 분석

```bash
revkit ida summary
```

### `methods` — List Available RPC Methods / RPC 메서드 목록

```bash
revkit ida methods
```

### `shell` — Interactive IDAPython REPL

```bash
revkit ida shell -i <id>
```

Interactive Python environment with full IDAPython API access. Variables persist across lines within the session.

IDAPython API에 대한 전체 접근 권한을 가진 대화형 Python 환경. 세션 내에서 변수가 호출 간 유지된다.

```bash
# Pipe mode (non-interactive) / 파이프 모드 (비대화형)
echo -e "x = 42\nprint(x)\nexit" | revkit ida shell -i <id>
# → 42
# → Shell closed.
```

> **변수 유지**: `shell`과 `exec`는 공유 globals를 사용하므로, 이전 exec 호출에서 정의한 변수를 다음 호출에서 참조할 수 있다.
> 인스턴스를 재시작하면 변수는 초기화된다.

### `exec` — Execute IDAPython Code / IDAPython 코드 실행

```bash
revkit ida exec "<code>" [--out PATH]
```

Executes arbitrary IDAPython code on the running instance. Requires `ida.security.exec_enabled: true` (or global `security.exec_enabled: true`) in config. The per-engine setting takes precedence.

실행 중인 인스턴스에서 임의의 IDAPython 코드를 실행한다. config에 `ida.security.exec_enabled: true` (또는 전역 `security.exec_enabled: true`) 필요. 엔진별 설정이 우선 적용된다.

> **변수 영속**: 서버 프로세스가 살아 있는 동안 exec 호출 간 변수가 유지된다. / Variables persist across exec calls while the server process is alive.

---

## Modification Commands / 수정 명령어

### `rename` — Rename Symbol / 심볼 이름 변경

```bash
revkit ida rename <addr> <new_name>
```

### `set-type` — Set Type / 타입 설정

```bash
revkit ida set-type <addr> "int __fastcall myfunc(int a1, char *a2)"
```

> **주의**: IDA 타입 파서는 풀 선언(리턴타입 + 호출규약 + 함수이름 + 인자)을 요구함.
> `"int(int)"` 같은 간략 형식은 파싱 실패. 반드시 아래 형식 준수:
> `"리턴타입 __호출규약 함수이름(인자타입 인자이름, ...)"`

### `comment` — Set Comment / 주석 설정

```bash
revkit ida comment <addr> <text> [--repeatable] [--type TYPE]
```

### `patch` — Patch Bytes / 바이트 패치

```bash
revkit ida patch <addr> <hex_bytes> [hex_bytes ...]
```

Returns / 반환: `{addr, original, patched, size}`

### `search-const` — Search Constants / 상수 검색

```bash
revkit ida search-const <value> [--max N] [--out PATH]
```

### `auto-rename` — Heuristic Auto-Rename / 자동 이름 변경

```bash
revkit ida auto-rename [--apply] [--max-funcs N]
```

Preview mode by default. Use `--apply` to actually rename. Automatically renames `sub_` prefixed functions based on heuristics.

기본적으로 미리보기 모드. `--apply`로 실제 이름 변경을 수행한다. 휴리스틱 기반으로 `sub_` 접두사 함수를 자동으로 이름 변경한다.

### `rename-batch` — Batch Rename / 배치 이름 변경

```bash
revkit ida rename-batch --file <entries.json|entries.csv>
```

Accepts JSON or CSV format / JSON 또는 CSV 형식:

```json
// 배열 형식
[{"addr": "0x401000", "name": "main"}, {"addr": "0x401100", "name": "init_crypto"}]

// entries 래퍼 형식
{"entries": [{"addr": "0x401000", "name": "main"}]}

// key-value 형식
{"0x401000": "main", "0x401100": "init_crypto"}
```

### `save` — Save IDB / IDB 저장

```bash
revkit ida save -i <id>
```

---

## Type Commands / 타입 명령어

### Structs / 구조체

```bash
# List structs / 구조체 목록
revkit ida structs [--action list] [--filter PATTERN] [--offset N] [--count N]

# Show struct detail / 구조체 상세
revkit ida structs --action show --name <name>

# Create struct / 구조체 생성
# --members: name:size(바이트) 또는 name:type(C타입) 모두 가능
revkit ida structs --action create --name <name> [--union] [--members f1:4 f2:8]
revkit ida structs --action create --name <name> [--members f1:int f2:short]
```

Returns (show) / 반환: `{name, is_union, size, members: [{offset, name, size, type}]}`

### Enums / 열거형

```bash
# List enums / 열거형 목록
revkit ida enums [--action list] [--filter PATTERN]

# Show enum detail / 열거형 상세
revkit ida enums --action show --name <name>

# Create enum / 열거형 생성
revkit ida enums --action create --name <name> [--members CONST_A=0 CONST_B=1]
```

### Local Types / 로컬 타입

```bash
# List types / 타입 목록
revkit ida type-info [--action list] [--filter PATTERN] [--kind struct|enum|typedef]

# Show type detail / 타입 상세
revkit ida type-info --action show --name <name>
```

Returns (show) / 반환: `{name, size, declaration, is_struct, is_union, is_enum, is_typedef, is_funcptr, return_type, args}`

### VTables / 가상 테이블

```bash
revkit ida vtables [--max N] [--min-entries N]
```

### FLIRT Signatures / FLIRT 시그니처

```bash
# List signatures / 시그니처 목록
revkit ida sigs [--action list]

# Apply signature / 시그니처 적용
revkit ida sigs --action apply <sig_name>
```

---

## Advanced Commands / 고급 명령어

### `callgraph` — Function Call Graph / 함수 호출 그래프

```bash
revkit ida callgraph <addr> [--depth 3] [--direction callees|callers] [--format mermaid|dot] [--out FILE]
```

```bash
# Example: Generate call graph from main()
revkit ida callgraph 0x401000 --depth 5 --format mermaid --out callgraph.md
```

### `cross-refs` — Multi-Level Xref Chain / 다단계 xref 추적

```bash
revkit ida cross-refs <addr> [--depth 3] [--direction to|from] [--format mermaid|dot] [--out FILE]
```

### `search-code` — Search Decompiled Code / 의사코드 검색

```bash
revkit ida search-code <query> [--max N] [--max-funcs N] [--case-sensitive]
```

### `strings-xrefs` — Strings with References / 문자열 + 참조 함수

```bash
revkit ida strings-xrefs [--filter PATTERN] [--max N] [--min-refs N] [--out PATH]
```

### `func-similarity` — Function Similarity / 함수 유사도 비교

```bash
revkit ida func-similarity <addr_a> <addr_b>
```

Returns / 반환: `{func_a, func_b, similarity: {size_ratio, block_ratio, callee_jaccard, overall}, common_callees}`

### `data-refs` — Data Segment References / 데이터 세그먼트 참조

```bash
revkit ida data-refs [--filter PATTERN] [--segment NAME] [--max N] [--out PATH]
```

### `basic-blocks` — Basic Blocks & CFG / 기본 블록 + 제어흐름도

```bash
revkit ida basic-blocks <addr> [--format mermaid|dot] [--graph-only] [--out FILE]
```

### `stack-frame` — Stack Frame Layout / 스택 프레임 레이아웃

```bash
revkit ida stack-frame <addr>
```

Returns / 반환: `{name, addr, frame_size, locals_size, args_size, members: [{offset, size, name, type, kind}]}`

### `switch-table` — Switch/Jump Table Analysis / Switch 테이블 분석

```bash
revkit ida switch-table <addr>
```

---

## Diff Commands / 비교 명령어

### `diff` — Compare Two Instances / 두 인스턴스 비교

```bash
revkit ida diff <instance_a> <instance_b>
```

Compares function lists between two running instances.

두 실행 중인 인스턴스 간 함수 목록을 비교한다.

### `compare` — Patch Comparison / 패치 비교

```bash
revkit ida compare <binary_a> <binary_b> [--idb-dir DIR] [--out FILE]
```

Automatically starts both binaries, compares, and outputs patch diff.

두 바이너리를 자동 시작하여 비교하고 패치 diff를 출력한다.

### `code-diff` — Decompiled Code Diff / decompile 코드 비교

```bash
revkit ida code-diff <instance_a> <instance_b> [--functions FUNC1,FUNC2] [--out FILE]
```

Produces unified diff of decompiled code between two instances.

두 인스턴스의 decompile 코드를 unified diff로 출력한다.

---

## Report Commands / 보고서 명령어

### `report` — Generate Analysis Report / 분석 보고서 생성

```bash
revkit ida report <output_path> [--functions ADDR1 ADDR2 ...]
```

The output path is positional (`.md` or `.html`). Generates Markdown/HTML report with binary summary, imports, strings, and optional decompiled code.

출력 경로는 위치 인자 (`.md` 또는 `.html`). 바이너리 요약, import, 문자열, decompile 코드(선택)를 포함한 보고서를 생성한다.

### `annotations` — Export/Import Annotations / Annotation 내보내기·가져오기

```bash
# Export / 내보내기
revkit ida annotations [--action export] [--out annotations.json]

# Import / 가져오기
revkit ida annotations --action import <annotations.json>
```

> Import 시 `idc.get_type()`이 반환하는 이름 없는 프로토타입(`void __cdecl()` 등)은
> 자동으로 더미 이름을 삽입하여 `parse_decl()`이 처리할 수 있도록 함.
> 이름/코멘트/타입 모두 정상 import됨 (PE, ELF SO, Mach-O 검증 완료).

### `snapshot` — IDB Snapshot Management / IDB 스냅샷 관리

```bash
# Save snapshot / 스냅샷 저장
revkit ida snapshot --action save [--description "before patch"]

# List snapshots / 스냅샷 목록
revkit ida snapshot [--action list]

# Restore snapshot / 스냅샷 복원
revkit ida snapshot --action restore <filename>
```

### `export-script` — Export as IDAPython Script / IDAPython 스크립트 내보내기

```bash
revkit ida export-script [--out analysis.py]
```

Exports all analysis results (renames, comments, types) as a reproducible IDAPython script.

분석 결과(이름 변경, 주석, 타입)를 재현 가능한 IDAPython 스크립트로 내보낸다.

### `bookmark` — Bookmark Management / 북마크 관리

```bash
# Add bookmark / 북마크 추가
revkit ida bookmark --action add <addr> <tag> [--note "buffer overflow"]

# List bookmarks / 북마크 목록
revkit ida bookmark [--action list]

# Remove bookmark / 북마크 제거
revkit ida bookmark --action remove <addr>
```

### `profile` — Run Analysis Profile / 분석 프로필 실행

```bash
# List profiles / 프로필 목록
revkit ida profile [--action list]

# Run profile / 프로필 실행
revkit ida profile --action run <malware|firmware|vuln> [--out-dir DIR]
```

Built-in profiles / 내장 프로필:

| Profile | Focus / 초점 |
| ------- | ----------- |
| `malware` | C2 communication, encryption, anti-analysis / C2, 암호화, 반분석 |
| `firmware` | UART, SPI, GPIO, boot sequence / UART, SPI, GPIO, 부팅 |
| `vuln` | Dangerous functions, buffer overflow / 위험 함수, BOF |

---

## Batch Commands / 배치 명령어

### `batch` — Batch Analyze Directory / 디렉터리 배치 분석

```bash
revkit ida batch <directory> [--idb-dir DIR] [--fresh] [--timeout 300] [--keep]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `directory` | Directory containing binaries / 바이너리가 들어있는 디렉터리 |
| `--idb-dir` | Custom IDB output directory / IDB 출력 디렉터리 |
| `--fresh` | Create fresh IDB for each / 각각 새 IDB 생성 |
| `--timeout` | Timeout per binary (default: 300s) / 바이너리당 타임아웃 |
| `--keep` | Keep instances running / 인스턴스 유지 |

---

## Utility Commands / 유틸리티 명령어

### `update` — Auto Update / 자동 업데이트

```bash
revkit ida update
```

### `completions` — Shell Completion / 셸 자동완성

```bash
revkit ida completions [--shell bash|zsh|powershell]
```

---

## RPC Methods / RPC 메서드

Full list of RPC methods available on the IDA server.

IDA 서버에서 사용 가능한 전체 RPC 메서드 목록.

### Auth Token / 인증 토큰

RPC 직접 호출 시 **Bearer 인증 토큰**이 필수. 서버 시작 시 자동 생성되어 `~/.revkit/auth_tokens.json`에 저장됨.

```
# auth_tokens.json 형식 (인스턴스ID:포트:토큰)
s2oe:5327:THx9M1Nbkjen3n3WW8VseNoTy1ZRx77Lofo-pIToOKU
mg5z:4756:cpRFKlrfwyzIf854SfiiAZLiErqCz39PfbWoAYKKDkQ
```

```bash
# RPC 직접 호출 예시
TOKEN=$(grep "^s2oe:" ~/.revkit/auth_tokens.json | cut -d: -f3)
curl -X POST http://127.0.0.1:5327/api \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}'
```

> **주의**: CLI (`revkit ida ...`)는 auth token을 자동 처리하므로 별도 설정 불필요.
> RPC를 직접 호출하는 경우(curl, Python requests 등)에만 토큰을 수동으로 전달해야 함.

### RPC 에러 응답 구조

에러 시 `result` 대신 `error` 객체가 반환됨. 에러 코드는 `error.code`, 메시지는 `error.message`에 분리되어 있음.

```json
{
  "error": {
    "code": "SIG_NOT_FOUND",
    "message": "Signature file not found: nonexist_sig",
    "suggestion": null
  },
  "id": 1
}
```

> **주의**: 스크립트에서 에러를 판별할 때 `error.message`가 아닌 `error.code`를 사용할 것.
> `message`는 사람이 읽기 위한 텍스트이고, `code`가 프로그래밍적 식별자.

### RPC 응답 키 이름 주의사항

RPC마다 응답 키 이름이 다르므로, 스크립트 작성 시 실제 응답을 먼저 확인할 것.

| RPC | 총 개수 키 | 데이터 키 | 비고 |
|-----|-----------|----------|------|
| `get_functions` | `total` | `data` | |
| `get_strings` | `total` | `data` | `total_strings` 아님 |
| `get_imports` | `total` | `data` | `total_imports` 아님 |
| `get_exports` | `total` | `data` | `total_exports` 아님 |
| `summary` | `func_count`, `total_strings`, `total_imports` | - | `functions` 아님 |
| `decompile_batch` | `total`, `success`, `failed` | `functions` | `results` 아님 |
| `get_xrefs_to/from` | - | `refs` | `xrefs` 아님 |
| `find_func` | `total` | `matches` | |
| `find_bytes` | - | `matches` | |
| `callgraph` | `nodes` (int) | `dot`, `mermaid` | `nodes`/`edges`는 개수(int), 리스트 아님 |
| `cross_refs` | `nodes` (int) | `chain`, `edge_details` | `nodes`/`edges`는 개수(int), 리스트 아님 |
| `func_similarity` | - | `similarity.overall` | nested: `r["similarity"]["overall"]`, 최상위 아님 |
| `exec` | - | `stdout` | `output` 아님 |
| `auto_rename` | `total` | `renames` | `sub_` 함수만 대상. 심볼 완비 바이너리에서 0건 정상 |
| `decompile_diff` | - | `code` | 단일 함수 추출용, 두 함수 비교 아님 |
| `decompile_all` | `total`, `success` | - | `output` 파라미터 필수 (파일 저장 경로) |
| `apply_sig` | - | `ok`, `result` | 미존재 sig → `SIG_NOT_FOUND` 에러. 실존 sig → `ok:true` |
| `search_const` | `total` | `results` | `value`는 검색한 상수값(hex) |
| `detect_vtables` | `total` | `vtables` | `total` = vtable 수, `entries` = 함수 포인터 수 |
| `stack_frame` | `member_count` | `members` | 크기: `frame_size`, `locals_size`, `args_size` |
| `switch_table` | `switch_count` | `switches` | 각 switch에 `case_count`(int), `cases`(list) |
| `basic_blocks` | `block_count`, `edge_count` | `blocks` | count는 int, `dot`/`mermaid` 포함 |
| `export_script` | `renames`, `comments`, `types` | `saved_to` | 3개 모두 **int 개수** (리스트 아님!) |
| `strings_xrefs` | `total` | `results` | 각 result에 `ref_count`(int) + `refs`(list) 중첩 |
| `data_refs` | `total` | `results` | 각 result에 `ref_count`(int) + `refs`(list) 중첩 |

> **응답 hint 필드**: 아래 RPC 응답에 `hint` 필드가 포함됩니다. 혼동하기 쉬운 응답 구조를
> 설명하는 용도이며, 스크립트에서 무시해도 됩니다.
>
> | 대상 RPC | hint 내용 |
> |---------|----------|
> | `auto_rename` | sub_ 함수 없으면 왜 0건인지 설명 |
> | `decompile_diff` | 단일 함수 추출용, 비교 아님 |
> | `func_similarity` | overall이 similarity 하위에 nested |
> | `callgraph` | nodes/edges는 int 개수, dot/mermaid에 그래프 데이터 |
> | `cross_refs` | nodes/edges는 int 개수, chain/edge_details에 구조화 데이터 |
> | `basic_blocks` | block_count/edge_count는 int, blocks 배열에 데이터 |
> | `export_script` | renames/comments/types는 int 개수, 실제 스크립트는 saved_to 파일 |
> | `decompile_all` | 모든 값 int 개수, output 파라미터 필수 |
> | `search_code` | functions_scanned은 스캔 수, total은 매칭 수 |
> | `search_const` | value는 hex 포맷 상수값 |
> | `strings_xrefs` | 각 result에 ref_count(int)와 refs(list) 중첩 |
> | `data_refs` | 각 result에 ref_count(int)와 refs(list) 중첩 |
> | `detect_vtables` | total은 vtable 수, entries는 함수 포인터 수 |
> | `stack_frame` | member_count는 int, members 배열에 레이아웃 |
> | `switch_table` | switch_count는 int, 각 switch에 case_count(int)와 cases(list) |

### Core / 핵심

| Method | Description / 설명 |
| ------ | ------------------ |
| `ping` | Connection test / 연결 확인 |
| `status` | Server status / 서버 상태 |
| `stop` | Shutdown server / 서버 종료 |
| `methods` | List available methods / 사용 가능한 메서드 목록 |
| `summary` | Binary overview / 바이너리 종합 분석 |

### Listing / 목록 조회

| Method | Description / 설명 |
| ------ | ------------------ |
| `get_functions` | All functions / 전체 함수 목록 |
| `get_strings` | All strings / 전체 문자열 목록 |
| `get_imports` | Import table / import 테이블 |
| `get_exports` | Export table / export 테이블 |
| `get_segments` | Memory segments / 메모리 세그먼트 |

### Analysis / 분석

| Method | Description / 설명 |
| ------ | ------------------ |
| `decompile` | Decompile function / 함수 decompile |
| `decompile_with_xrefs` | Decompile + xrefs / decompile + 참조 |
| `decompile_batch` | Batch decompile / 배치 decompile |
| `decompile_all` | All functions / 전체 decompile |
| `decompile_diff` | Extract decompiled code for diffing / diff용 단일 함수 코드 추출 (비교 아님) |
| `disasm` | Disassembly / 디스어셈블리 |
| `get_xrefs_to` | Xrefs to address / 주소로의 참조 |
| `get_xrefs_from` | Xrefs from address / 주소에서의 참조 |
| `find_func` | Search function / 함수 검색 |
| `get_func_info` | Function detail / 함수 상세 |
| `get_imagebase` | Image base address / 기본 주소 |
| `get_bytes` | Read bytes / 바이트 읽기 |
| `find_bytes` | Pattern search / 패턴 검색 |

### Modification / 수정

| Method | Description / 설명 |
| ------ | ------------------ |
| `set_name` | Rename symbol / 심볼 이름 변경 |
| `set_type` | Set type / 타입 설정 |
| `set_comment` | Set comment / 주석 설정 |
| `get_comments` | Get comments / 주석 조회 |
| `patch_bytes` | Patch bytes / 바이트 패치 |
| `rename_batch` | Batch rename / 배치 이름 변경 |
| `save_db` | Save IDB / IDB 저장 |
| `exec` | Execute IDAPython code / IDAPython 코드 실행 |

### Types / 타입

| Method | Description / 설명 |
| ------ | ------------------ |
| `list_structs` | List structs / 구조체 목록 |
| `get_struct` | Struct detail / 구조체 상세 |
| `create_struct` | Create struct / 구조체 생성 |
| `list_enums` | List enums / 열거형 목록 |
| `get_enum` | Enum detail / 열거형 상세 |
| `create_enum` | Create enum / 열거형 생성 |
| `list_types` | List local types / 로컬 타입 목록 |
| `get_type` | Type detail / 타입 상세 |
| `detect_vtables` | Detect vtables / 가상 테이블 감지 |
| `apply_sig` | Apply FLIRT signature / FLIRT 시그니처 적용 |
| `list_sigs` | List signatures / 시그니처 목록 |

### Graph / 그래프

| Method | Description / 설명 |
| ------ | ------------------ |
| `callgraph` | Call graph / 호출 그래프 |
| `cross_refs` | Multi-level xref / 다단계 xref |
| `basic_blocks` | Basic blocks + CFG / 기본 블록 + 제어흐름도 |
| `stack_frame` | Stack frame layout / 스택 프레임 |
| `switch_table` | Switch/jump table / Switch 테이블 |

### Advanced / 고급

| Method | Description / 설명 |
| ------ | ------------------ |
| `search_const` | Search constants / 상수 검색 |
| `search_code` | Search decompiled code / 의사코드 검색 |
| `auto_rename` | Heuristic rename / 휴리스틱 이름 변경 |
| `decompile_all` | All functions / 전체 decompile |
| `strings_xrefs` | Strings + refs / 문자열 + 참조 |
| `func_similarity` | Function similarity / 함수 유사도 |
| `data_refs` | Data references / 데이터 참조 |
| `export_script` | Export as script / 스크립트 내보내기 |

### Snapshot

| Method | Description / 설명 |
| ------ | ------------------ |
| `snapshot_save` | Save snapshot / 스냅샷 저장 |
| `snapshot_list` | List snapshots / 스냅샷 목록 |
| `snapshot_restore` | Restore snapshot / 스냅샷 복원 |

### Annotation

| Method | Description / 설명 |
| ------ | ------------------ |
| `export_annotations` | Export annotations / Annotation 내보내기 |
| `import_annotations` | Import annotations / Annotation 가져오기 |

---

## Configuration / 설정 상세

### Full Config Example / 전체 설정 예시

```json
{
    "paths": {
        "idb_dir": "~/.revkit/ida/idb",
        "log_dir": "~/.revkit/logs",
        "registry": "~/.revkit/ida/registry.json",
        "output_dir": "~/.revkit/output"
    },
    "ida": {
        "install_dir": "C:/Program Files/IDA Professional 9.3",
        "security": { "exec_enabled": true }
    },
    "security": { "exec_enabled": false },
    "log": { "max_size_mb": 10, "backup_count": 3, "stderr_capture": true }
}
```

### Server Constants / 서버 상수

| Constant | Default | Description / 설명 |
| -------- | ------- | ------------------ |
| `MAX_BATCH_DECOMPILE` | - | Max addresses per batch / 배치당 최대 주소 수 |
| `MAX_DISASM_LINES` | 500 | Max disassembly lines / 최대 디스어셈블리 줄 수 |
| `MAX_READ_BYTES` | - | Max bytes to read / 최대 읽기 바이트 |
| `MAX_FIND_RESULTS` | - | Max search results / 최대 검색 결과 |

### IDB Storage / IDB 저장 경로

Default IDB directory / 기본 IDB 경로: `~/.revkit/ida/idb/`

Custom via / 커스텀 설정: `--idb-dir` flag or `config.json`

### Log Files / 로그 파일

Instance logs / 인스턴스 로그: `~/.revkit/logs/ida/instances/{iid}.jsonl`

Instance stderr / 인스턴스 stderr: `~/.revkit/logs/ida/instances/{iid}.stderr`

Engine log / 엔진 로그: `~/.revkit/logs/ida/engine.jsonl`

See **[docs/README-Logging.md](README-Logging.md)** for full logging documentation.

전체 로깅 문서는 **[docs/README-Logging.md](README-Logging.md)** 를 참조.
