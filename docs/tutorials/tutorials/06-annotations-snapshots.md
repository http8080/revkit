# Tutorial 06: Annotations & Snapshots / 주석 & 스냅샷

Step-by-step guide to managing annotations, snapshots, and team collaboration workflows.

주석, 스냅샷, 팀 협업 워크플로우를 관리하는 단계별 가이드.

> **Prerequisites / 사전 준비**: [01-first-ida-analysis.md](01-first-ida-analysis.md) or [02-first-jeb-analysis.md](02-first-jeb-analysis.md) completed / 완료

---

## Concept / 개념

Annotations let you export and import analysis notes (renames, comments, bookmarks). Snapshots let you save and restore the analysis state at any point. Together, they enable team collaboration on reverse engineering projects.

주석은 분석 노트(이름 변경, 코멘트, 북마크)를 내보내고 가져올 수 있게 합니다. 스냅샷은 특정 시점의 분석 상태를 저장하고 복원합니다. 이 둘을 함께 사용하면 리버스 엔지니어링 프로젝트에서 팀 협업이 가능합니다.

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. Annotations — IDA / 주석 — IDA

### Set Up Analysis / 분석 준비

```bash
# Start and prepare / 시작 및 준비
$RK ida start Samples/EXE/notepad.exe
$RK ida wait

# Make some analysis changes / 분석 변경사항 추가
$RK ida rename 0x140010108 "main_entry"
$RK ida comment 0x140010108 "Program entry point"
$RK ida bookmark 0x140010108 --label "Entry"
$RK ida rename 0x14001A200 "dialog_handler"
$RK ida comment 0x14001A200 "Handles print dialog"
```

### Export / 내보내기

```bash
# Export all annotations to a JSON file / 모든 주석을 JSON 파일로 내보내기
$RK ida annotations --action export --out annotations_notepad.json
# → [+] Exported 5 annotations to annotations_notepad.json
#    Renames: 2, Comments: 2, Bookmarks: 1
```

The exported file is a portable JSON format that can be shared with teammates.

내보낸 파일은 팀원과 공유할 수 있는 이동 가능한 JSON 형식입니다.

### Import / 가져오기

```bash
# Import annotations into another instance / 다른 인스턴스에 주석 가져오기
$RK ida annotations --action import annotations_notepad.json
# → [+] Imported 5 annotations
#    Applied: 5, Skipped: 0, Failed: 0
```

---

## 2. Annotations — JEB / 주석 — JEB

```bash
# Start JEB / JEB 시작
$RK jeb start Samples/APK/UnCrackable/UnCrackable-Level3.apk
$RK jeb wait

# Add analysis / 분석 추가
$RK jeb rename-class "Lsg/vantagepoint/a/VerifyLibs;" "IntegrityChecker"
$RK jeb set-comment "Lsg/vantagepoint/uncrackable3/MainActivity;" "Main app entry"

# Export / 내보내기
$RK jeb annotations-export annotations_level3.json
# → [+] Exported annotations to annotations_level3.json

# Import into a fresh session / 새 세션에 가져오기
$RK jeb annotations-import annotations_level3.json
# → [+] Imported annotations successfully
```

---

## 3. Snapshots — IDA / 스냅샷 — IDA

### Save Snapshots / 스냅샷 저장

```bash
# Save initial state / 초기 상태 저장
$RK ida snapshot --action save --description "initial_analysis"
# → [+] Snapshot saved: initial_analysis (id=snap_001)

# Make more changes / 추가 변경
$RK ida auto-rename --max-funcs 50
$RK ida rename 0x14001B000 "crypto_init"

# Save after changes / 변경 후 저장
$RK ida snapshot --action save --description "after_rename"
# → [+] Snapshot saved: after_rename (id=snap_002)
```

### List and Restore / 목록 및 복원

```bash
# List all snapshots / 모든 스냅샷 목록
$RK ida snapshot --action list
# ID        Name               Created              Size
# snap_001  initial_analysis   2026-03-22 10:00:00  2.1 MB
# snap_002  after_rename       2026-03-22 10:15:00  2.3 MB

# Restore to initial state / 초기 상태로 복원
$RK ida snapshot --action restore --name snap_001
# → [+] Restored snapshot: initial_analysis
# → All changes since snap_001 are reverted / snap_001 이후 모든 변경이 되돌려짐
```

---

## 4. Snapshots — JEB / 스냅샷 — JEB

```bash
# Save / 저장
$RK jeb snapshot-save "before_analysis"
# → [+] Snapshot saved: before_analysis

# Do analysis work / 분석 작업 수행
$RK jeb security-scan
$RK jeb rename-class "Lsg/vantagepoint/a/a;" "CryptoHelper"

# Save again / 다시 저장
$RK jeb snapshot-save "after_security_review"

# List snapshots / 스냅샷 목록
$RK jeb snapshot-list
# Name                    Created
# before_analysis         2026-03-22 10:00:00
# after_security_review   2026-03-22 10:30:00

# Restore / 복원
$RK jeb snapshot-restore "before_analysis"
# → [+] Restored: before_analysis
```

---

## 5. Report Generation / 리포트 생성

After analysis is complete, generate a comprehensive report.

분석이 완료되면 포괄적인 리포트를 생성합니다.

```bash
# IDA report / IDA 리포트
$RK ida report --out notepad_analysis.md
# → [*] Output saved to notepad_analysis.md
# Includes: summary, renamed functions, comments, bookmarks
# 포함: 요약, 이름 변경된 함수, 코멘트, 북마크

# JEB report / JEB 리포트
$RK jeb report --out level3_analysis.md
# → [*] Output saved to level3_analysis.md
# Includes: app info, permissions, renamed classes, security findings
# 포함: 앱 정보, 권한, 이름 변경된 클래스, 보안 발견사항
```

---

## 6. Team Collaboration Workflow / 팀 협업 워크플로우

A practical workflow for sharing analysis between team members.

팀원 간 분석을 공유하는 실용적인 워크플로우입니다.

```bash
# === Analyst A: Initial analysis / 분석가 A: 초기 분석 ===
$RK ida start target.exe && $RK ida wait
$RK ida auto-rename --max-funcs 100
$RK ida rename 0x401000 "main_decrypt"
$RK ida comment 0x401000 "AES-256-CBC, key from argv[1]"
$RK ida snapshot --action save --description "analyst_a_pass1"
$RK ida annotations --action export --out shared/analyst_a.json
$RK ida stop

# === Analyst B: Continue analysis / 분석가 B: 분석 계속 ===
$RK ida start target.exe && $RK ida wait
$RK ida annotations --action import shared/analyst_a.json
# → All of Analyst A's renames and comments are applied
# → 분석가 A의 모든 이름 변경과 코멘트가 적용됨
$RK ida rename 0x402000 "network_callback"
$RK ida comment 0x402000 "C2 beacon handler, 60s interval"
$RK ida annotations --action export --out shared/analyst_b.json
$RK ida stop

# === Analyst A: Merge results / 분석가 A: 결과 병합 ===
$RK ida start target.exe && $RK ida wait
$RK ida annotations --action import shared/analyst_b.json
# → Both analysts' work is now combined / 두 분석가의 작업이 합쳐짐
$RK ida report --out shared/final_report.md
$RK ida save && $RK ida stop
```

---

## 7. Cleanup / 정리

```bash
$RK ida stop
$RK jeb stop
```

---

## Summary / 요약

```
analyze → annotate → export → [share] → import → snapshot → report

분석 → 주석달기 → 내보내기 → [공유] → 가져오기 → 스냅샷 → 리포트
```

| What you learned / 배운 것 | Commands / 명령 |
| --- | --- |
| IDA annotations / IDA 주석 | `annotations --action export`, `annotations --action import` |
| JEB annotations / JEB 주석 | `annotations-export`, `annotations-import` |
| IDA snapshots / IDA 스냅샷 | `snapshot --action save`, `snapshot --action list`, `snapshot --action restore` |
| JEB snapshots / JEB 스냅샷 | `snapshot-save`, `snapshot-list`, `snapshot-restore` |
| Report generation / 리포트 생성 | `report --out` |
| Team workflow / 팀 워크플로우 | Export + Import annotation cycle |

---

## Next / 다음

- [01-first-ida-analysis.md](01-first-ida-analysis.md) -- Back to IDA basics / IDA 기초로 돌아가기
- [02-first-jeb-analysis.md](02-first-jeb-analysis.md) -- JEB basics / JEB 기초
