# Tutorial 02: First JEB APK Analysis / 첫 JEB APK 분석

Step-by-step guide to analyzing an Android APK with revkit + JEB.

revkit + JEB로 Android APK를 분석하는 단계별 가이드.

> **Prerequisites / 사전 준비**: [00-install-setup.md](00-install-setup.md) completed / 완료

---

## Sample / 샘플

This tutorial uses `Samples/APK/UnCrackable/UnCrackable-Level3.apk`.

이 튜토리얼은 `Samples/APK/UnCrackable/UnCrackable-Level3.apk`를 사용합니다.

```bash
RK="python -m revkit.tools.cli.main"
```

---

## DEX Signature Format / DEX 시그니처 형식

JEB uses DEX-style signatures instead of addresses. Understanding this format is essential.

JEB는 주소 대신 DEX 스타일 시그니처를 사용합니다. 이 형식의 이해가 필수적입니다.

```
Class:    Lcom/example/MyClass;
Method:   Lcom/example/MyClass;->doWork(Ljava/lang/String;I)V
Field:    Lcom/example/MyClass;->count:I

L         = class prefix / 클래스 접두사
;         = class terminator / 클래스 종결자
->        = member separator / 멤버 구분자
(...)     = parameter types / 매개변수 타입
V=void  I=int  Z=boolean  Ljava/lang/String;=String
```

---

## 1. Start + Wait / 시작 + 대기

```bash
# Start JEB headless server with fresh analysis / 새로운 분석으로 JEB 서버 시작
$RK jeb start Samples/APK/UnCrackable/UnCrackable-Level3.apk --fresh
# → [+] Started jeb (id=b7m9, pid=54321, spawn=wrapper)

# Wait for analysis to complete / 분석 완료 대기
$RK jeb wait --timeout 180
# → [+] b7m9 is ready
```

> **--fresh** skips cached project and re-analyzes from scratch.
>
> **--fresh**는 캐시된 프로젝트를 건너뛰고 처음부터 다시 분석합니다.

---

## 2. Recon / 정찰

### App Info / 앱 정보

```bash
# Basic APK info / 기본 APK 정보
$RK jeb info
# Package:     sg.vantagepoint.uncrackable3
# Version:     1.0
# Min SDK:     19
# Target SDK:  28

# Permissions / 권한
$RK jeb permissions
# android.permission.WRITE_EXTERNAL_STORAGE
# android.permission.INTERNET

# Components / 컴포넌트
$RK jeb components
# Activities:  MainActivity
# Services:    0
# Receivers:   0
# Providers:   0

# Full manifest / 전체 매니페스트
$RK jeb manifest
# → AndroidManifest.xml content / 내용 출력
```

---

## 3. Explore Classes / 클래스 탐색

```bash
# List all classes / 전체 클래스 목록
$RK jeb classes
# → Lsg/vantagepoint/uncrackable3/MainActivity;
# → Lsg/vantagepoint/uncrackable3/CodeCheck;
# → Lsg/vantagepoint/a/VerifyLibs;
# → ... (total 12 classes / 총 12개 클래스)
```

---

## 4. Decompile / 디컴파일

```bash
# Decompile a class / 클래스 디컴파일
$RK jeb decompile "Lsg/vantagepoint/uncrackable3/MainActivity;"
# → Java source code output / Java 소스코드 출력

# Decompile a specific method / 특정 메서드 디컴파일
$RK jeb method "Lsg/vantagepoint/uncrackable3/MainActivity;->onCreate(Landroid/os/Bundle;)V"
# → Method source with onCreate logic / onCreate 로직 소스

# View Smali bytecode / Smali 바이트코드 확인
$RK jeb smali "Lsg/vantagepoint/uncrackable3/MainActivity;->onCreate(Landroid/os/Bundle;)V"
# → .method public onCreate(Landroid/os/Bundle;)V
# →   .locals 4
# →   invoke-super ...
```

---

## 5. Native Methods + Strings / 네이티브 메서드 + 문자열

```bash
# List native methods (JNI) / 네이티브 메서드 목록 (JNI)
$RK jeb native-methods
# → Lsg/vantagepoint/uncrackable3/CodeCheck;->bar([B)Z  (native)
# → Lsg/vantagepoint/uncrackable3/MainActivity;->init([B[B)V  (native)
# These are implemented in libfoo.so / 이것들은 libfoo.so에 구현됨

# Search strings / 문자열 검색
$RK jeb strings
# → "Tampering detected!" (used in root detection / 루트 감지에 사용)
# → "libfoo.so"
# → "pizza"
```

---

## 6. Modify / 수정

### Rename Class / 클래스 이름 변경

```bash
# Rename an obfuscated class / 난독화된 클래스 이름 변경
$RK jeb rename-class "Lsg/vantagepoint/a/VerifyLibs;" "IntegrityChecker"
# → [+] Renamed class → IntegrityChecker

# Verify / 확인
$RK jeb classes
# → Lsg/vantagepoint/a/IntegrityChecker;  (renamed / 이름 변경됨)
```

---

## 7. Security Analysis / 보안 분석

```bash
# Full security scan / 전체 보안 스캔
$RK jeb security-scan
# → [!] Root detection found in MainActivity
# → [!] Native library loading: libfoo.so
# → [!] Anti-tampering checks detected

# Find entry points / 진입점 탐색
$RK jeb entry-points
# → MainActivity.onCreate
# → CodeCheck.bar (native)
# → Application.attachBaseContext
```

---

## 8. Report + Save + Stop / 리포트 + 저장 + 종료

```bash
# Generate analysis report / 분석 리포트 생성
$RK jeb report --out uncrackable3_report.md
# → [*] Output saved to uncrackable3_report.md

# Save project / 프로젝트 저장
$RK jeb save
# → [+] Project saved

# Stop instance / 인스턴스 종료
$RK jeb stop
# → [+] Stopped b7m9

# Verify / 확인
$RK jeb list
# → [*] No active instances.
```

---

## 9. Error Handling / 에러 처리

Try these to learn how errors look / 에러가 어떻게 보이는지 체험:

```bash
# Nonexistent class / 존재하지 않는 클래스
$RK jeb decompile "Lcom/fake/DoesNotExist;"
# → [-] RPC error: Class not found: Lcom/fake/DoesNotExist;

# Non-APK file / APK가 아닌 파일
$RK jeb start /tmp/readme.txt
# → [-] File is not a valid APK: /tmp/readme.txt

# No instance running / 인스턴스 없이 실행
$RK jeb classes
# → [-] No active instances. Use 'start' first.
```

---

## Summary / 요약

```
start --fresh → wait → [recon/decompile/modify/scan] → report → save → stop

시작 → 대기 → [정찰/디컴파일/수정/스캔] → 리포트 → 저장 → 종료
```

| What you learned / 배운 것 | Commands / 명령 |
| --- | --- |
| DEX signatures / DEX 시그니처 | `Lpackage/Class;->method(params)RetType` |
| APK recon / APK 정찰 | `info`, `permissions`, `components`, `manifest` |
| Class exploration / 클래스 탐색 | `classes`, `decompile`, `method`, `smali` |
| Native analysis / 네이티브 분석 | `native-methods`, `strings` |
| Modification / 수정 | `rename-class` |
| Security / 보안 | `security-scan`, `entry-points` |

---

## Next / 다음

- [03-binary-comparison.md](03-binary-comparison.md) -- Binary comparison / 바이너리 비교
- [04-batch-analysis.md](04-batch-analysis.md) -- Batch analysis / 일괄 분석
