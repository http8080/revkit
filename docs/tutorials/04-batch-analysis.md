# Tutorial 04: Batch Analysis / 일괄 분석

Step-by-step guide to analyzing multiple binaries and APKs in batch mode.

여러 바이너리와 APK를 일괄 모드로 분석하는 단계별 가이드.

> **Prerequisites / 사전 준비**: [01-first-ida-analysis.md](01-first-ida-analysis.md) or [02-first-jeb-analysis.md](02-first-jeb-analysis.md) completed / 완료

---

## Concept / 개념

Batch analysis processes multiple files automatically: start an instance, run analysis, collect results, stop, repeat for each file.

일괄 분석은 여러 파일을 자동으로 처리합니다: 인스턴스 시작, 분석 실행, 결과 수집, 종료를 각 파일마다 반복합니다.

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. IDA Batch / IDA 일괄 분석

### Batch Command / 일괄 명령

```bash
# Batch analyze all ELF binaries in a directory / 디렉토리의 모든 ELF 바이너리 일괄 분석
$RK ida batch Samples/ELF/
# [*] Found 5 binaries in Samples/ELF/
# [*] Processing 1/5: libnative.so
#     Functions: 42, Strings: 18
# [*] Processing 2/5: libcrypto.so
#     Functions: 1203, Strings: 892
# [*] Processing 3/5: busybox
#     Functions: 8521, Strings: 3102
# ...
# [+] Batch complete: 5/5 succeeded
# [*] Results saved to batch_results.json
```

### Batch with Output / 출력과 함께 일괄 분석

```bash
# Save results to a specific location / 특정 위치에 결과 저장
$RK ida batch Samples/ELF/ --out results/ida_batch/
# → Results written to results/ida_batch/
#    results/ida_batch/libnative.so.json
#    results/ida_batch/libcrypto.so.json
#    ...
```

---

## 2. JEB Batch / JEB 일괄 분석

```bash
# Batch analyze all APKs in a directory / 디렉토리의 모든 APK 일괄 분석
$RK jeb batch Samples/APK/UnCrackable/
# [*] Found 3 APKs in Samples/APK/UnCrackable/
# [*] Processing 1/3: UnCrackable-Level1.apk
#     Classes: 8, Methods: 24, Permissions: 2
# [*] Processing 2/3: UnCrackable-Level2.apk
#     Classes: 10, Methods: 31, Permissions: 2
# [*] Processing 3/3: UnCrackable-Level3.apk
#     Classes: 12, Methods: 38, Permissions: 3
# [+] Batch complete: 3/3 succeeded
```

---

## 3. Decompile All / 전체 디컴파일

For a single binary or APK already loaded, decompile every function or class at once.

이미 로드된 단일 바이너리 또는 APK의 모든 함수나 클래스를 한번에 디컴파일합니다.

### IDA Decompile All / IDA 전체 디컴파일

```bash
# Start and wait / 시작 및 대기
$RK ida start Samples/ELF/libnative.so
$RK ida wait

# Decompile all functions to a single file / 모든 함수를 단일 파일로 디컴파일
$RK ida decompile-all --out output/libnative.c
# [*] Decompiling 42 functions...
# [+] Complete: 42/42 saved to output/libnative.c

# Split into one file per function (directory) / 함수별 파일 분리 (디렉토리)
$RK ida decompile-all --out output/libnative/ --split
# [+] Complete: 42/42 saved to output/libnative/

# With filter — only functions matching a pattern / 필터 — 패턴에 맞는 함수만
$RK ida decompile-all --filter "Java_" --out output/jni_funcs.c
# [*] Filter matched 6 functions
# [+] Complete: 6/6 saved to output/jni_funcs.c

$RK ida stop
```

### JEB Decompile All / JEB 전체 디컴파일

```bash
# Start and wait / 시작 및 대기
$RK jeb start Samples/APK/UnCrackable/UnCrackable-Level1.apk
$RK jeb wait

# Decompile all classes to a single file / 모든 클래스를 단일 파일로 디컴파일
$RK jeb decompile-all --out output/uncrackable1.java
# [*] Decompiling 8 classes...
# [+] Complete: 8/8 saved to output/uncrackable1.java

# Split into one file per class (directory) / 클래스별 파일 분리 (디렉토리)
$RK jeb decompile-all --out output/uncrackable1/ --split
# [+] Complete: 8/8 saved to output/uncrackable1/

# With filter — only specific package / 필터 — 특정 패키지만
$RK jeb decompile-all --filter "vantagepoint" --out output/vantagepoint.java
# [*] Filter matched 5 classes
# [+] Complete: 5/5 saved to output/vantagepoint.java

$RK jeb stop
```

---

## 4. Decompile Batch / 디컴파일 일괄 처리

Decompile specific targets from a JSON list, without processing every function/class.

모든 함수/클래스를 처리하지 않고 JSON 목록의 특정 대상만 디컴파일합니다.

### IDA Decompile Batch / IDA 디컴파일 일괄

```bash
# Create a targets file / 대상 파일 생성
echo '[
  {"addr": "0x401000"},
  {"addr": "0x401200"},
  {"addr": "0x401500"}
]' > ida_targets.json

$RK ida decompile-batch --file ida_targets.json --out output/selected/
# [+] Decompiled 3/3 functions
```

### JEB Decompile Batch / JEB 디컴파일 일괄

```bash
# Create a targets file / 대상 파일 생성
echo '[
  {"sig": "Lsg/vantagepoint/uncrackable1/MainActivity;"},
  {"sig": "Lsg/vantagepoint/a/a;"},
  {"sig": "Lsg/vantagepoint/a/b;"}
]' > jeb_targets.json

$RK jeb decompile-batch --file jeb_targets.json --out output/selected_jeb/
# [+] Decompiled 3/3 classes
```

---

## 5. Combining Batch + Report / 일괄 분석 + 리포트 결합

```bash
# Full workflow: batch analyze → generate reports / 전체 워크플로우: 일괄 분석 → 리포트 생성
$RK jeb start Samples/APK/UnCrackable/UnCrackable-Level3.apk --fresh
$RK jeb wait

# Decompile everything / 전체 디컴파일
$RK jeb decompile-all --out output/level3_all.java

# Generate summary report / 요약 리포트 생성
$RK jeb report --out output/level3_report.md

# Cleanup / 정리
$RK jeb stop
```

---

## Summary / 요약

```
batch dir/ → results          (multiple files / 여러 파일)
decompile-all --out file      (single loaded binary, all functions to one file / 단일 바이너리, 전체 함수를 단일 파일로)
decompile-all --out dir/ --split  (one file per function/class / 함수/클래스별 파일 분리)
decompile-batch --file list   (single loaded binary, specific targets / 단일 바이너리, 특정 대상)

일괄(디렉토리) → 결과         (여러 파일 처리)
전체 디컴파일 → 출력 파일      (단일 바이너리, 전체 함수)
전체 디컴파일 → 디렉토리 분리  (--split으로 함수/클래스별)
선택적 디컴파일 → 출력         (단일 바이너리, 지정 대상)
```

| What you learned / 배운 것 | Commands / 명령 |
| --- | --- |
| Directory batch / 디렉토리 일괄 | `batch dir/` |
| Full decompilation / 전체 디컴파일 | `decompile-all --out` |
| Filtered decompilation / 필터 디컴파일 | `decompile-all --filter` |
| Selective batch / 선택적 일괄 | `decompile-batch --file` |
| Report generation / 리포트 생성 | `report --out` |

---

## Next / 다음

- [05-type-system.md](05-type-system.md) -- IDA type system / IDA 타입 시스템
- [06-annotations-snapshots.md](06-annotations-snapshots.md) -- Annotations & snapshots / 주석 & 스냅샷
