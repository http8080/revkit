# revkit — JEB Pro Engine

Detailed documentation for JEB Pro engine commands, RPC methods, and configuration.

JEB Pro 엔진 명령어, RPC 메서드, 설정에 대한 상세 문서.

---

## Table of Contents

- [Overview / 개요](#overview--개요)
- [Setup / 설정](#setup--설정)
- [Instance Management / 인스턴스 관리](#instance-management--인스턴스-관리)
- [Analysis Commands / 분석 명령어](#analysis-commands--분석-명령어)
- [Modification Commands / 수정 명령어](#modification-commands--수정-명령어)
- [Recon Commands / 정찰 명령어](#recon-commands--정찰-명령어)
- [Search Commands / 검색 명령어](#search-commands--검색-명령어)
- [Xrefs Commands / Xref 명령어](#xrefs-commands--xref-명령어)
- [Security Commands / 보안 명령어](#security-commands--보안-명령어)
- [Tooling Commands / 도구 명령어](#tooling-commands--도구-명령어)
- [Report Commands / 보고서 명령어](#report-commands--보고서-명령어)
- [Batch Commands / 배치 명령어](#batch-commands--배치-명령어)
- [Config Commands / 설정 명령어](#config-commands--설정-명령어)
- [Utility Commands / 유틸리티 명령어](#utility-commands--유틸리티-명령어)
- [RPC Methods / RPC 메서드](#rpc-methods--rpc-메서드)
- [Configuration / 설정 상세](#configuration--설정-상세)

---

## Overview / 개요

The JEB engine provides headless APK/DEX/JAR analysis through JEB Pro's Java API.

JEB 엔진은 JEB Pro의 Java API를 통해 APK/DEX/JAR 의 headless 분석을 제공한다.

| Feature | Value |
| ------- | ----- |
| Supported formats / 지원 포맷 | APK, DEX, JAR |
| DB extension / DB 확장자 | `.jdb2` |
| Identifier / 식별자 | DEX signature (`Lcom/example/Foo;`) |
| Instance ID / 인스턴스 ID | `{name}_{4hex}` (`app-a3f2`) |
| Server runtime / 서버 런타임 | Java 11+ (revkit-jeb-server.jar) |
| Command modules / 명령어 모듈 | 13 |
| Total commands / 전체 명령어 | 72 |

### Architecture / 아키텍처

```text
revkit jeb <command> [options]
       │
       ▼
  CmdContext(args, config, config_path, engine)
       │
       ▼
  cmd_*() ──── HTTP POST ──── JEB Server (JSON-RPC)
       │                             │
       ▼                             ▼
  CLI output / file save        Java API (JEB Core)
```

### DEX Signature Format / DEX 시그니처 형식

JEB uses DEX-style signatures to identify classes, methods, and fields.

JEB는 DEX 스타일 시그니처로 클래스, 메서드, 필드를 식별한다.

```text
Class:  Lcom/example/MainActivity;
Method: Lcom/example/MainActivity;->onCreate(Landroid/os/Bundle;)V
Field:  Lcom/example/MainActivity;->mFlag:Z
```

> Short name resolution is supported: `MainActivity` → `Lcom/example/MainActivity;`
>
> 짧은 이름 자동 해석 지원: `MainActivity` → `Lcom/example/MainActivity;`

### Server Architecture / 서버 아키텍처

JEB 서버는 **Java로 구현**되어 JEB Pro API를 직접 호출한다 (`revkit-jeb-server.jar`).

- **현재**: Java 서버 (`server/java/`) — 네이티브 JEB API, 고성능
- **레거시**: Jython 서버 (`server/legacy/`) — 롤백용 보존, 삭제하지 않음

빌드: `revkit jeb gen-runner` (JebScriptRunner + Java 서버 JAR 자동 빌드)

상태 확인: `revkit jeb check` (Java 서버 JAR 크기/날짜/server_type 표시)

### JEB 서버 레지스트리 형식

- CLI core: `[]` (list) 형식으로 저장 (`~/.revkit/jeb/registry.json`)
- JEB 서버: `{}` (dict) 형식으로 저장 (레거시 호환)
- CLI core의 `load_registry()`가 양쪽 형식 모두 자동 변환

---

## Setup / 설정

### Prerequisites / 사전 요구사항

- **JEB Pro** with headless API license / JEB Pro headless API 라이선스
- **Java 17+**
- **Python 3.12+** (CLI side / CLI 측)

### Configuration / 설정

`~/.revkit/config.json`:

```json
{
    "jeb": {
        "install_dir": "/opt/jeb",
        "registry": "~/.revkit/jeb/registry.json",
        "server_type": "java",
        "spawn_method": "wrapper",
        "java_home": "/usr/lib/jvm/java-17",
        "jvm_opts": ["-XX:+UseG1GC", "-Dfile.encoding=UTF-8"],
        "security": { "exec_enabled": false },
        "heap": {
            "auto": true,
            "default": "4G",
            "max": "16G"
        }
    }
}
```

| Key | Description / 설명 | Default |
| --- | ------------------ | ------- |
| `jeb.install_dir` | JEB Pro installation directory / 설치 경로 | (required) |
| `jeb.registry` | JEB instance registry path / JEB 레지스트리 경로 | `~/.revkit/jeb/registry.json` |
| `jeb.server_type` | Server implementation: `java` or `jython` / 서버 구현체 | `jython` |
| `jeb.spawn_method` | Launch method: `wrapper` or `bat` (jython only) / 실행 방식 (jython 전용) | `wrapper` |
| `jeb.java_home` | Java home override / Java 홈 오버라이드. bat 모드에서는 무시됨. | System default |
| `jeb.jvm_opts` | Additional JVM args / 추가 JVM 인자. bat 모드에서는 무시됨 (jvmopt.txt 사용). | `[]` |
| `jeb.heap.auto` | Auto heap sizing based on RAM / RAM 기반 자동 힙 | `true` |
| `jeb.heap.default` | Default heap size / 기본 힙 크기 | `4G` |
| `jeb.heap.max` | Maximum heap size / 최대 힙 크기 | `16G` |

### Verify Installation / 설치 확인

```bash
# Verify JEB CLI / JEB CLI 확인
/opt/jeb/jeb_wincon.bat --version   # Windows
/opt/jeb/jeb_linux.sh --version    # Linux
/opt/jeb/jeb_macos.sh --version    # macOS

# Verify via revkit / revkit으로 확인
revkit jeb check
```

### Spawn Methods / 실행 방식

Server type is selected by `jeb.server_type`. Spawn method (`jeb.spawn_method`) only applies when `server_type` is `jython`.

서버 유형은 `jeb.server_type`으로 선택. `jeb.spawn_method`는 `server_type`이 `jython`일 때만 적용.

| Method | Description / 설명 |
| ------ | ------------------ |
| `java` | **Recommended.** Pure Java RPC server (`revkit-jeb-server.jar`). No Jython overhead, faster startup, better stability. Set `server_type: "java"`. Uses `java_home` and `jvm_opts`. / **권장.** 순수 Java RPC 서버. Jython 오버헤드 없음, 빠른 시작, 높은 안정성. `server_type: "java"` 설정. `java_home`과 `jvm_opts` 사용. |
| `wrapper` | Jython-based JebScriptRunner execution via `java` command. Uses `java_home` and `jvm_opts` from config. **Works on all platforms.** / Jython 기반 JebScriptRunner 직접 실행. config의 `java_home`과 `jvm_opts` 사용. **모든 플랫폼 지원.** |
| `bat` | Uses JEB's batch launcher (`jeb_wincon.bat`). Requires `patch` first. Ignores `java_home`/`jvm_opts` (reads `jvmopt.txt`). **Windows only.** / JEB 배치 런처 사용. `patch` 선행 필요. `java_home`/`jvm_opts` 무시. **Windows 전용.** |

> **Platform availability / 플랫폼별 지원:**
>
> | Platform | `java` | `wrapper` | `bat` |
> | --- | --- | --- | --- |
> | Windows | ✅ | ✅ | ✅ (requires `patch`) |
> | Linux | ✅ | ✅ | ❌ (`jeb_wincon.bat` 없음) |
> | macOS | ✅ | ✅ | ❌ |

> The active server type / spawn method is logged in CLI output, lifecycle JSONL logs (`instance.start` event), and debug logs for every spawn path (`start`, `restart`, `batch`).
>
> 활성 서버 유형 / `spawn_method`는 CLI 출력, 라이프사이클 JSONL 로그 (`instance.start` 이벤트), 그리고 모든 스폰 경로(`start`, `restart`, `batch`)의 디버그 로그에 기록된다.

---

## Instance Management / 인스턴스 관리

### `start` — Start Analysis Server / 분석 서버 시작

```bash
revkit jeb start <binary> [--force] [--fresh] [--project-dir DIR] [--xmx 8G] [--wait]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `binary` | Path to APK/DEX/JAR (or split APK directory) / 바이너리 경로 |
| `--force` | Overwrite existing project / 기존 프로젝트 덮어쓰기 |
| `--fresh` | Create new project from scratch / 프로젝트 새로 생성 |
| `--project-dir DIR` | Custom project directory / 커스텀 프로젝트 경로 |
| `--xmx 8G` | Heap size override / 힙 크기 지정 |
| `--wait` | Wait for analysis to complete / 분석 완료까지 대기 |

```bash
# Single APK
revkit jeb start /path/to/app.apk

# Split APKs (auto-merge via APKEditor)
# Split APK (APKEditor로 자동 병합)
revkit jeb start /path/to/split_apk_dir/

# Large APK with custom heap
revkit jeb start large_app.apk --xmx 12G --wait
```

> When a directory is provided, split APKs are automatically merged using APKEditor before analysis.
>
> 디렉터리를 지정하면 분석 전에 APKEditor를 사용하여 split APK를 자동 병합한다.

### `stop` — Stop Instance / 인스턴스 중지

```bash
revkit jeb stop -i <id>
revkit jeb stop -b app.apk
```

Sends `save_db` RPC (with `analysis.stop_timeout` timeout) before `stop` to persist analysis. Waits for the process to exit via polling-based `_wait_for_exit(pid, timeout)` (default: `analysis.stop_timeout` = 30s); force kills on timeout. Auth token is read from the token file for authenticated RPC calls.

중지 전에 `save_db` RPC를 호출하여 분석을 저장한다 (`analysis.stop_timeout` 타임아웃 적용). `_wait_for_exit(pid, timeout)`로 프로세스 종료를 폴링 방식으로 대기하며 (기본값: `analysis.stop_timeout` = 30초), 타임아웃 시 강제 종료한다.

> **3-layer save guarantee / 3중 저장 보장**: (1) `save_db` RPC → server saves project, (2) `stop` RPC → `_handle_stop` saves again + releases latch, (3) JVM shutdown hook (`CleanupHook`) → final save + registry cleanup. Data loss is virtually impossible.
>
> (1) `save_db` RPC → 서버가 프로젝트 저장, (2) `stop` RPC → `_handle_stop`이 다시 저장 + latch 해제, (3) JVM shutdown hook (`CleanupHook`) → 최종 저장 + 레지스트리 정리. 데이터 손실이 사실상 불가능.

### `restart` — Restart Instance / 인스턴스 재시작

```bash
revkit jeb restart -i <id> [--fresh] [--wait] [--xmx SIZE]
```

### `list` — List Active Instances / 활성 인스턴스 목록

```bash
revkit jeb list [--json]
```

Output / 출력:

```text
ID           State      PID    Port   Binary
app-a3f2     ready      12345  18861  com.example.app.apk
test-b1c4    analyzing  12346  18862  test.dex
```

### `status` — Instance Status / 인스턴스 상태

```bash
revkit jeb status -i <id>
```

When the server is in `ready` state, queries the RPC `status` method and shows live server info: class/method counts, JEB version, memory usage, uptime, and `binary_md5`. Uses auth token for the RPC call.

서버가 `ready` 상태이면 RPC `status` 메서드를 쿼리하여 실시간 정보를 표시한다.

### `wait` — Wait for Ready / ready 대기

```bash
revkit jeb wait -i <id> [--timeout 300]
```

### `logs` — View Logs / 로그 조회

```bash
revkit jeb logs -i <id> [--tail 50] [--follow]
```

### `cleanup` — Clean Stale Resources / 리소스 정리

```bash
revkit jeb cleanup [--dry-run] [--all]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `--dry-run` | Show what would be deleted / 삭제 예정 항목만 표시 |
| `--all` | Force stop and clean ALL instances / 전체 인스턴스 강제 정리 |

### `save` — Save Project / 프로젝트 저장

```bash
revkit jeb save -i <id>
```

### `init` — Initialize Directories / 디렉터리 초기화

```bash
revkit jeb init
```

### `check` — Verify Environment / 환경 검증

```bash
revkit jeb check
```

Checks / 검증 항목: Python version, JEB installation, launcher, JebScriptRunner, jvmopt.txt, dependencies.

---

## Analysis Commands / 분석 명령어

### `decompile` — Decompile Class or Method / 클래스·메서드 decompile

```bash
revkit jeb decompile <sig> [--with-xrefs] [--line-numbers] [--no-limit] [--out PATH] [--auto-out]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `sig` | Class or method signature (supports short names) / 시그니처 (짧은 이름 지원) |
| `--with-xrefs` | Include callers/callees / 호출자·피호출자 포함 |
| `--line-numbers` | Add line numbers / 줄 번호 추가 |
| `--no-limit` | Bypass inline truncation / 인라인 출력 제한 해제 |
| `--out PATH` | Save to file / 파일로 저장 |
| `--auto-out` | Auto-generate filename / 파일명 자동 생성 |

```bash
# Full class signature
revkit jeb decompile "Lcom/example/MainActivity;"

# Short name (auto-resolved)
revkit jeb decompile MainActivity

# Method with xrefs
revkit jeb decompile "Lcom/example/Foo;->decrypt(Ljava/lang/String;)V" --with-xrefs

# Save with auto-generated filename
revkit jeb decompile MainActivity --auto-out
```

### `method` — Decompile Single Method / 단일 메서드 decompile

```bash
revkit jeb method <method_sig> [--with-xrefs] [--out FILE]
```

### `decompile-diff` — Compare Decompiled Code / decompile 코드 비교

```bash
revkit jeb decompile-diff <sig> <diff_file> [--out FILE]
```

Compares current decompiled code with a previously saved version.

현재 decompile 코드를 이전에 저장한 버전과 비교한다.

### `decompile-batch` — Batch Decompile / 배치 decompile

```bash
revkit jeb decompile-batch <sig1> <sig2> ... [--out PATH] [--md-out]
```

Max 20 signatures per batch / 배치당 최대 20개 시그니처.

### `decompile-all` — Decompile All Classes / 전체 클래스 decompile

```bash
revkit jeb decompile-all --out output/ [--split] [--package com.example] [--filter PATTERN]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `--out` | Output path / 출력 경로 |
| `--split` | Split into per-class files / 클래스별 파일 분리 |
| `--package` | Filter by Java package / Java 패키지 필터 (자동으로 DEX 경로 변환) |
| `--filter` | DEX-style package filter / DEX 스타일 패키지 필터 |

### `smali` — Get Smali Bytecode / Smali 바이트코드 조회

```bash
revkit jeb smali <class_or_method_sig> [--out FILE]
```

```bash
# Full class smali
revkit jeb smali "Lcom/example/Crypto;"

# Specific method smali (auto-detected via -> or parentheses)
revkit jeb smali "Lcom/example/Crypto;->encrypt(Ljava/lang/String;)V"
```

### `classes` — List Classes / 클래스 목록

```bash
revkit jeb classes [--limit N] [--offset N] [--tree] [--count-only]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `--tree` | Tree view grouped by package / 패키지별 트리 뷰 |
| `--count-only` | Only show total count / 전체 수만 표시 |

### `methods-of-class` — List Methods of Class / 클래스 메서드 목록

```bash
revkit jeb methods-of-class <class_sig> [--out FILE]
```

### `fields-of-class` — List Fields of Class / 클래스 필드 목록

```bash
revkit jeb fields-of-class <class_sig> [--out FILE]
```

### `method-info` — Method Information / 메서드 정보

```bash
revkit jeb method-info <method_sig>
```

Returns / 반환: name, class, return type, access flags, parameters.

### `native-methods` — List Native Methods / 네이티브 메서드 목록

```bash
revkit jeb native-methods [--filter PATTERN] [--json]
```

Lists native method declarations grouped by class with SO library mapping.

클래스별 네이티브 메서드 선언을 SO 라이브러리 매핑과 함께 나열한다.

### `strings` — List Strings / 문자열 목록

```bash
revkit jeb strings [--limit N] [--offset N] [--min-len N] [--regex PATTERN] [--encoding ENC] [--count-only]
```

### `methods` — List Methods or RPC Methods / 메서드 목록

```bash
# RPC methods
revkit jeb methods

# Methods of a specific class
revkit jeb methods --class-sig "Lcom/example/Foo;"
```

---

## Modification Commands / 수정 명령어

### `rename` — Auto-Detect and Rename / 자동 감지 + 이름 변경

```bash
revkit jeb rename <sig> <new_name> [--preview]
```

Auto-detects target type / 대상 타입 자동 감지:
- Contains `(` → method
- Contains `->` → field
- Otherwise → class

```bash
# Rename class
revkit jeb rename "Lcom/example/a;" DecryptionHelper

# Rename method
revkit jeb rename "Lcom/example/a;->b(Ljava/lang/String;)V" decrypt

# Preview impact before renaming
revkit jeb rename "Lcom/example/a;" DecryptionHelper --preview
```

### `rename-class` — Rename Class / 클래스 이름 변경

```bash
revkit jeb rename-class <class_sig> <new_name>
```

### `rename-method` — Rename Method / 메서드 이름 변경

```bash
revkit jeb rename-method <method_sig> <new_name>
```

### `rename-field` — Rename Field / 필드 이름 변경

```bash
revkit jeb rename-field <field_sig> <new_name>
```

### `rename-batch` — Batch Rename from File / 파일에서 배치 이름 변경

```bash
revkit jeb rename-batch --file <entries.json>
```

JSON format / JSON 형식:

```json
// 배열 형식
[
    {"sig": "Lcom/example/a;", "new_name": "CryptoUtil"},
    {"sig": "Lcom/example/a;->b(Ljava/lang/String;)V", "new_name": "decrypt"}
]

// entries 래퍼 형식
{"entries": [{"sig": "Lcom/example/a;", "new_name": "CryptoUtil"}]}

// key-value 형식
{"Lcom/example/a;": "CryptoUtil"}
```

CSV format / CSV 형식:

```csv
# sig,new_name
Lcom/example/a;,CryptoUtil
Lcom/example/a;->b(Ljava/lang/String;)V,decrypt
```

### `rename-preview` — Preview Rename Impact / 이름 변경 영향 미리보기

```bash
revkit jeb rename-preview <sig>
```

Shows all references that would be affected by the rename.

이름 변경 시 영향 받는 모든 참조를 표시한다.

### `auto-rename` — Heuristic Auto-Rename / 휴리스틱 자동 이름 변경

```bash
revkit jeb auto-rename [--max-classes 100] [--apply]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `--max-classes` | Max suggestions (default: 100) / 최대 제안 수 |
| `--apply` | Apply renames immediately / 즉시 적용 |

### `set-comment` — Set Comment / 주석 설정

```bash
revkit jeb set-comment <addr_or_sig> "comment text" [--type TYPE]
```

### `get-comments` — Get Comments / 주석 조회

```bash
revkit jeb get-comments [addr]
```

### `undo` — Undo Last Modification / 마지막 수정 취소

```bash
revkit jeb undo
```

Supports undo for rename and comment operations. Keeps last 50 entries.

rename, comment 작업의 undo를 지원한다. 최근 50개 항목 유지.

### `bookmark` — Manage Bookmarks / 북마크 관리

```bash
# Add bookmark
revkit jeb bookmark --action add <sig> [--note "interesting method"]

# List bookmarks
revkit jeb bookmark --action list

# Remove bookmark
revkit jeb bookmark --action remove <sig>
```

Storage / 저장 위치: `~/.revkit/jeb/bookmarks.json`

---

## Recon Commands / 정찰 명령어

### `summary` — APK Overview / APK 종합 정보

```bash
revkit jeb summary [--out summary.md]
```

Returns / 반환: class count, method count, strings, permissions, top packages, sample strings.

### `permissions` — Android Permissions / 안드로이드 권한

```bash
revkit jeb permissions [--json]
```

Marks dangerous permissions with warning indicators.

위험 권한을 경고 표시와 함께 표시한다.

### `components` — App Components / 앱 컴포넌트

```bash
revkit jeb components [--type activity|service|receiver|provider] [--json]
```

Returns / 반환: components with exported status.

### `info` — APK Metadata / APK 메타데이터

```bash
revkit jeb info [--json]
```

Returns / 반환: package name, version, SDK levels, DEX count, certificates, permissions.

### `main-activity` — Get Main Activity / 메인 액티비티 조회

```bash
revkit jeb main-activity
```

### `app-class` — Get Application Class / Application 클래스 조회

```bash
revkit jeb app-class
```

### `manifest` — Get AndroidManifest.xml

```bash
revkit jeb manifest [--component FILTER] [--out FILE]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `--component` | Filter by tag or component name / 태그 또는 컴포넌트명 필터 |
| `--out FILE` | Save to file / 파일로 저장 |

### `resources` — List Resource Files / 리소스 파일 목록

```bash
revkit jeb resources [--out FILE]
```

### `resource` — Get Resource Content / 리소스 내용 조회

```bash
revkit jeb resource <path> [--out FILE]
```

```bash
# Example: Get network security config
revkit jeb resource res/xml/network_security_config.xml --out nsc.xml
```

---

## Search Commands / 검색 명령어

### `search-classes` — Search Classes / 클래스 검색

```bash
revkit jeb search-classes <keyword> [--max N] [--regex]
```

```bash
revkit jeb search-classes Crypto
revkit jeb search-classes ".*Decrypt.*" --regex
```

### `search-methods` — Search Methods / 메서드 검색

```bash
revkit jeb search-methods <name> [--max N] [--regex]
```

### `search-code` — Search Source Code / 소스 코드 검색

```bash
revkit jeb search-code <query> [--max-results N] [--case-sensitive] [--context N] [--regex] [--package PACKAGE]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `query` | Search query / 검색 쿼리 |
| `--case-sensitive` | Case-sensitive match / 대소문자 구분 |
| `--context N` | Context lines around match / 매칭 주변 줄 수 |
| `--regex` | Treat as regex pattern / 정규식으로 처리 |
| `--package` | Filter by Java package / 패키지 필터 |

```bash
# Search for hardcoded URLs
revkit jeb search-code "https://" --max-results 50

# Search in specific package
revkit jeb search-code "AES" --package com.example.crypto
```

### `strings-xrefs` — Strings with Cross-References / 문자열 + 참조

```bash
revkit jeb strings-xrefs [--filter PATTERN] [--max N] [--min-refs N]
```

Returns strings with the methods that reference them.

문자열과 이를 참조하는 메서드를 함께 반환한다.

---

## Xrefs Commands / Xref 명령어

### `xrefs` — Show Cross-References / 교차 참조 조회

```bash
revkit jeb xrefs <sig> [--direction to|from|both]
```

### `callers` — Show Callers / 호출자 목록

```bash
revkit jeb callers <sig>
```

### `callees` — Show Callees / 피호출자 목록

```bash
revkit jeb callees <sig>
```

### `callgraph` — Call Graph / 호출 그래프

```bash
revkit jeb callgraph <class_or_method_sig> [--depth 3] [--direction callees|callers] [--exclude PATTERN] [--format mermaid|dot|svg|png] [--out FILE]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `--depth` | Graph depth (default: 3) / 그래프 깊이 |
| `--direction` | `callees` or `callers` (default: `callees`) |
| `--exclude` | Exclude pattern (e.g., `android.*`) / 제외 패턴 |
| `--format` | Output format / 출력 형식 |
| `--out` | Save to file / 파일 저장 |

> SVG/PNG rendering requires graphviz `dot` command.
>
> SVG/PNG 렌더링은 graphviz `dot` 명령이 필요하다.

```bash
# Mermaid call graph
revkit jeb callgraph MainActivity --depth 5 --format mermaid --out cg.md

# PNG call graph
revkit jeb callgraph "Lcom/example/Foo;->init()V" --format png --out cg.png
```

### `cross-refs` — Multi-Level Xref Chain / 다단계 xref 추적

```bash
revkit jeb cross-refs <sig> [--depth 3] [--direction to|from] [--out FILE]
```

---

## Security Commands / 보안 명령어

### `entry-points` — Analyze Attack Surface / 공격 표면 분석

```bash
revkit jeb entry-points
```

Returns / 반환:
- Exported components (activities, services, receivers, providers) / 내보낸 컴포넌트
- Deep links / 딥 링크
- JavaScript interfaces / JavaScript 인터페이스
- Content providers / 콘텐츠 프로바이더
- Dynamic broadcast receivers / 동적 브로드캐스트 리시버

### `security-scan` — Automated Security Scan / 자동 보안 스캔

```bash
revkit jeb security-scan
```

Scans for / 스캔 대상:

| Category | Examples / 예시 |
| -------- | -------------- |
| Crypto issues / 암호화 문제 | Weak algorithms, hardcoded keys / 약한 알고리즘, 하드코딩된 키 |
| Hardcoded secrets / 하드코딩된 시크릿 | API keys, tokens, passwords |
| Dangerous permissions / 위험 권한 | WRITE_EXTERNAL_STORAGE, READ_SMS |
| Insecure storage / 안전하지 않은 저장 | SharedPreferences, SQLite plaintext |
| Network issues / 네트워크 문제 | HTTP usage, certificate pinning bypass |
| WebView issues / WebView 문제 | JavaScript enabled, file access |

---

## Tooling Commands / 도구 명령어

### `merge` — Merge Split APKs / Split APK 병합

Merges a split APK directory (base.apk + split_config.*.apk) into one standalone APK.
Also supports XAPK/APKS files. Output is a single installable `.apk`.

Split APK 디렉토리(base.apk + split_config.*.apk)를 하나의 standalone APK로 합친다.
XAPK/APKS 파일도 지원. 결과물은 `.apk` (단일 설치 가능 APK).

```bash
revkit jeb merge <input> [--out merged.apk] [--start] [--xmx 8G]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `input` | Directory containing split APKs (base + config splits) or XAPK/APKS file / split APK 디렉토리(base + config split들) 또는 XAPK/APKS 파일 |
| `--out` | Output merged APK path / 병합 APK 출력 경로 |
| `--start` | Auto-start JEB analysis after merge / 병합 후 자동 분석 시작 |
| `--xmx` | Heap size for analysis / 분석 힙 크기 |

Uses APKEditor-1.4.7.jar (auto-detected from `tools/libs/`).

`tools/libs/`에서 자동 감지되는 APKEditor-1.4.7.jar 사용.

> **Note**: `--out` is the APK output path, not a text output path. The merged APK is written directly. / `--out`은 APK 출력 경로. 병합된 APK가 직접 저장됨.

```bash
# Merge split APK directory (base.apk + split_config.arm64_v8a.apk + ...)
revkit jeb merge Samples/APK/NICE/ --out tmp/merged.apk

# Merge and immediately start analysis
revkit jeb merge /path/to/split_dir/ --start --xmx 8G

# Individual APK file → hint suggests using directory instead
revkit jeb merge Samples/APK/NICE/com.niceid.nicemypin.apk  # → error + hint
```

### `gen-runner` — Generate JebScriptRunner / JebScriptRunner 생성

```bash
revkit jeb gen-runner [--force] [--no-compile]
```

Auto-detects HeadlessClientContext subclass from jeb.jar and generates JebScriptRunner.

jeb.jar에서 HeadlessClientContext 서브클래스를 자동 감지하여 JebScriptRunner를 생성한다.

### `patch` — Patch jeb.jar / jeb.jar 패치

```bash
revkit jeb patch [--status] [--force]
```

Bytecode-patches Launcher.class to restore `--script=` handling.

`--script=` 처리를 복원하기 위해 Launcher.class를 바이트코드 패치한다.

| Option | Description / 설명 |
| ------ | ------------------ |
| `--status` | Check patch status / 패치 상태 확인 |
| `--force` | Force re-patch / 강제 재패치 |

### `unpatch` — Restore Original jeb.jar / 원본 jeb.jar 복원

```bash
revkit jeb unpatch
```

Restores from `jeb.jar.bak`. / `jeb.jar.bak`에서 복원.

---

## Report Commands / 보고서 명령어

### `report` — Generate Analysis Report / 분석 보고서 생성

```bash
revkit jeb report --out report.md [--decompile SIG1 SIG2 ...]
```

### `annotations` — Export/Import Annotations / Annotation 관리

```bash
# Export
revkit jeb annotations [--action export] [--out annotations.json]

# Import
revkit jeb annotations --action import <annotations.json>
```

Shorthand aliases are also available: `annotations-export`, `annotations-import`.

단축 별칭도 사용 가능: `annotations-export`, `annotations-import`.

### `snapshot` — Project Snapshot Management / 프로젝트 스냅샷 관리

```bash
# Save / 저장
revkit jeb snapshot --action save [--description "before rename"]

# List / 목록
revkit jeb snapshot [--action list]

# Restore / 복원
revkit jeb snapshot --action restore <filename>
```

Shorthand aliases are also available: `snapshot-save`, `snapshot-list`, `snapshot-restore`.

단축 별칭도 사용 가능: `snapshot-save`, `snapshot-list`, `snapshot-restore`.

---

## Batch Commands / 배치 명령어

### `batch` — Batch Analyze Directory / 디렉터리 배치 분석

```bash
revkit jeb batch <directory> [--ext apk] [--keep] [--timeout 300]
```

| Option | Description / 설명 |
| ------ | ------------------ |
| `directory` | Directory containing APK/DEX files / 바이너리 디렉터리 |
| `--ext` | File extension filter (default: `apk`) / 확장자 필터 |
| `--keep` | Keep instances running after analysis / 분석 후 인스턴스 유지 |
| `--timeout` | Wait timeout per file (default: 300s) / 파일당 대기 시간 |

### Batch RPC Methods / 배치 RPC 메서드

These methods use the longer batch timeout:

배치 타임아웃을 사용하는 메서드들:

- `decompile_all`
- `search_code`
- `security_scan`
- `get_strings`
- `get_imports`
- `get_exports`
- `get_all_classes`
- `get_all_methods`

---

## Config Commands / 설정 명령어

### `config-show` — Display Configuration / 설정 표시

```bash
revkit jeb config-show [--json]
```

### `config-set` — Set Configuration Value / 설정 값 변경

```bash
revkit jeb config-set <key> <value>
```

```bash
# Set JEB install directory
revkit jeb config-set jeb.install_dir /opt/jeb-5

# Set heap size
revkit jeb config-set jeb.heap.default 8G

# Enable auto heap
revkit jeb config-set jeb.heap.auto true
```

Value type is auto-detected: bool, int, float, or string.

값 타입은 자동 감지: bool, int, float, 또는 string.

---

## Utility Commands / 유틸리티 명령어

### `exec` — Execute Jython Code / Jython 코드 실행

```bash
revkit jeb exec "<code>" [--out FILE]
revkit jeb exec script.py [--out FILE]
```

> Requires `jeb.security.exec_enabled: true` (or global `security.exec_enabled: true`) in config. The per-engine setting takes precedence. / config에 `jeb.security.exec_enabled: true` (또는 전역 `security.exec_enabled: true`) 필요. 엔진별 설정이 우선 적용된다.

> **변수 영속**: 서버 프로세스가 살아 있는 동안 exec 호출 간 사용자 변수가 유지된다.
> JEB 컨텍스트 객체(`ctx`, `prj`, `dex_units`, `apk_unit`, `server`)는 매 호출마다 자동 갱신되며, 사용자가 실수로 덮어써도 다음 호출에서 복원된다.
>
> Variables persist across exec calls while the server process is alive.
> JEB context objects (`ctx`, `prj`, `dex_units`, `apk_unit`, `server`) are refreshed on every call and protected from accidental overwrite.

### `completion` — Shell Completion / 셸 자동완성

```bash
revkit jeb completion [--shell bash|zsh] [--out FILE]
```

---

## RPC Methods / RPC 메서드

Full list of JSON-RPC methods available on the JEB server.

JEB 서버에서 사용 가능한 전체 JSON-RPC 메서드 목록.

### Core / 핵심

| Method | Description / 설명 |
| ------ | ------------------ |
| `ping` | Connection test / 연결 확인 |
| `status` | Server status (includes `spawn_method`, `java_home`, `jvm_opts`) / 서버 상태 (`spawn_method`, `java_home`, `jvm_opts` 포함) |
| `stop` | Shutdown server / 서버 종료 |
| `methods` | List available methods / 메서드 목록 |
| `summary` | APK overview / APK 종합 분석 |
| `info` | APK metadata / APK 메타데이터 |

### Analysis / 분석

| Method | Description / 설명 |
| ------ | ------------------ |
| `decompile` | Decompile class/method |
| `decompile_with_xrefs` | Decompile + xrefs |
| `decompile_batch` | Batch decompile |
| `decompile_all` | All classes |
| `get_method_by_name` | Single method decompile |
| `get_smali` | Smali bytecode |
| `get_classes` | Class list |
| `get_methods_of_class` | Methods of class |
| `get_fields_of_class` | Fields of class |
| `get_method_info` | Method detail |
| `native_methods` | Native method list |
| `get_strings` | String list |

### Modification / 수정

| Method | Description / 설명 |
| ------ | ------------------ |
| `rename_class` | Rename class |
| `rename_method` | Rename method |
| `rename_field` | Rename field |
| `rename_batch` | Batch rename |
| `auto_rename` | Heuristic rename |
| `set_comment` | Set comment |
| `get_comments` | Get comments |
| `save_project` | Save project |

### Search / 검색

| Method | Description / 설명 |
| ------ | ------------------ |
| `search_classes` | Search classes by keyword |
| `search_methods` | Search methods by name |
| `search_code` | Search in decompiled code |
| `strings_xrefs` | Strings + references |

### Manifest & Recon / 매니페스트 + 정찰

| Method | Description / 설명 |
| ------ | ------------------ |
| `get_manifest` | AndroidManifest.xml |
| `get_main_activity` | Main activity |
| `get_app_class` | Application class |
| `get_resources` | Resource file list |
| `get_resource` | Resource content |

### Xrefs

| Method | Description / 설명 |
| ------ | ------------------ |
| `get_xrefs_to` | Xrefs to target |
| `get_xrefs_from` | Xrefs from target |
| `callgraph` | Call graph |
| `cross_refs` | Multi-level xref chain |

### Security / 보안

| Method | Description / 설명 |
| ------ | ------------------ |
| `entry_points` | Attack surface analysis |
| `security_scan` | Automated security scan |

### Annotation & Snapshot

| Method | Description / 설명 |
| ------ | ------------------ |
| `export_annotations` | Export annotations |
| `import_annotations` | Import annotations |
| `snapshot_save` | Save snapshot |
| `snapshot_list` | List snapshots |
| `snapshot_restore` | Restore snapshot |

### Advanced / 고급

| Method | Description / 설명 |
| ------ | ------------------ |
| `exec` | Execute Jython code |

---

## Configuration / 설정 상세

### Full Config Example / 전체 설정 예시

```json
{
    "jeb": {
        "install_dir": "C:/WorkSpace/bin/JEB-5.38",              // Linux: "~/JEB-5.38"
        "registry": "~/.revkit/jeb/registry.json",
        "server_type": "java",
        "spawn_method": "wrapper",
        "java_home": "C:/Program Files/Java/jdk-21.0.10",        // Linux: "/usr/lib/jvm/java-21"
        "jvm_opts": ["-XX:+UseG1GC", "-Dfile.encoding=UTF-8"],
        "security": { "exec_enabled": false },
        "heap": {
            "auto": true,
            "default": "4G",
            "max": "16G",
            "rules": [
                {"max_mb": 50, "xmx": "2G"},
                {"max_mb": 200, "xmx": "4G"},
                {"max_mb": 500, "xmx": "8G"}
            ]
        }
    },
    "paths": {
        "project_dir": "~/.revkit/jeb/projects",
        "log_dir": "~/.revkit/logs",
        "output_dir": "~/.revkit/output"
    },
    "security": {
        "auth_token_file": "~/.revkit/auth_tokens.json",
        "exec_enabled": false
    },
    "analysis": {
        "max_instances": 3,
        "wait_poll_interval": 1.0,
        "wait_timeout": 120,
        "stale_threshold": 86400,
        "open_db_timeout": 300,
        "heartbeat_interval": 30,
        "auto_save": true,
        "stop_timeout": 30
    },
    "log": { "max_size_mb": 10, "backup_count": 3, "stderr_capture": true }
}
```

### Key Config Sections / 주요 설정 섹션

| Section | Key | Description / 설명 | Default |
| ------- | --- | ------------------ | ------- |
| `jeb` | `install_dir` | JEB installation / 설치 경로 | (required) |
| `jeb` | `registry` | JEB instance registry / JEB 레지스트리 | `~/.revkit/jeb/registry.json` |
| `jeb` | `server_type` | `java` or `jython` | `jython` |
| `jeb` | `spawn_method` | `wrapper` or `bat` (jython only) | `wrapper` |
| `jeb` | `java_home` | Java home / Java 홈 | System default |
| `jeb` | `jvm_opts` | JVM args / JVM 인자 | `[]` |
| `jeb.heap` | `auto` | Auto heap sizing / 자동 힙 | `true` |
| `jeb.heap` | `default` | Default heap / 기본 힙 | `4G` |
| `jeb.heap` | `max` | Max heap / 최대 힙 | `16G` |
| `paths` | `project_dir` | Project DB directory / 프로젝트 DB 경로 | `~/.revkit/jeb/projects` |
| `paths` | `log_dir` | Log directory (base) / 로그 기본 경로 | `~/.revkit/logs` |
| `security` | `exec_enabled` | Allow exec command / exec 명령 허용 | `false` |
| `analysis` | `wait_poll_interval` | Poll interval (seconds) / 폴링 간격 | `1.0` |
| `analysis` | `stale_threshold` | Stale instance threshold / 스테일 기준 | `86400` |
| `tools` | `apkeditor` | APKEditor JAR path / APKEditor 경로 | Auto-detect |

### File Locations / 파일 경로

| File | Path | Description / 설명 |
| ---- | ---- | ------------------ |
| Config | `~/.revkit/config.json` | Main configuration / 메인 설정 |
| Registry | `~/.revkit/jeb/registry.json` | JEB instance registry / JEB 인스턴스 레지스트리 |
| Instance log | `~/.revkit/logs/jeb/instances/{iid}.jsonl` | Per-instance log / 인스턴스별 로그 |
| Instance stderr | `~/.revkit/logs/jeb/instances/{iid}.stderr` | Per-instance stderr capture / stderr 캡처 |
| Engine log | `~/.revkit/logs/jeb/engine.jsonl` | JEB engine log / JEB 엔진 로그 |
| Auth tokens | `~/.revkit/auth_tokens.json` | Authentication tokens / 인증 토큰 |
| Bookmarks | `~/.revkit/jeb/bookmarks.json` | Bookmark storage / 북마크 저장 |
| Undo history | `~/.revkit/jeb/undo_history.json` | Undo stack (max 50) / 실행 취소 스택 |
| APKEditor | `tools/libs/APKEditor-*.jar` | Split APK merge tool / APK 병합 도구 |
