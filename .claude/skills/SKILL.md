# SKILL.md — revkit AI 분석 스킬 가이드

> Claude Code에서 revkit을 활용하여 바이너리/APK를 분석하는 실전 가이드.
> 스킬 목록, 명령 레퍼런스, 분석 워크플로우, 문서 맵.

---

## 1. 스킬 목록

### 분석 스킬 (4개)

| 스킬 | 엔진 | 대상 | 설명 |
| --- | --- | --- | --- |
| `/analyze` | IDA/JEB (자동) | EXE/ELF/APK/DEX | 종합 분석 — 엔진 자동 감지, 요약+디컴파일+리포트 |
| `/decompile` | IDA/JEB | 함수/클래스 | 빠른 디컴파일 — 주소(IDA) 또는 DEX 시그니처(JEB) |
| `/compare` | IDA | 바이너리 2개 | 두 바이너리 비교 — 함수 차이 (`diff IID1 IID2`) |
| `/batch-analyze` | IDA/JEB | 디렉토리 | 디렉토리 내 모든 파일 배치 분석 |

### 보안 스킬 (4개)

| 스킬 | 대상 | 설명 |
| --- | --- | --- |
| `/security-scan` | EXE/APK | 보안 감사 — 취약점, 위험 API, 하드코딩된 값 |
| `/vuln-scan` | EXE/APK | 취약점 연구 — 위험 함수, 입력 핸들러, 공격 표면 |
| `/malware-scan` | EXE/ELF/APK | 악성코드 분석 — C2, 안티디버깅, 암호화, 위험도 점수 |
| `/mobile-audit` | APK/IPA | 모바일 보안 감사 — OWASP MASVS 기준 |

### 전문 분석 스킬 (3개)

| 스킬 | 대상 | 설명 |
| --- | --- | --- |
| `/pe-audit` | EXE/DLL | Windows PE 심층 분석 — import 분류, 보호 메커니즘 |
| `/firmware-scan` | ELF/BIN | 펌웨어 분석 — 메모리 맵, 주변장치, 부트 시퀀스 |
| `/protocol-scan` | EXE/ELF/APK | 네트워크 프로토콜 분석 — 소켓, HTTP, 직렬 통신 |

---

## 2. 엔진 자동 감지

| 확장자 | 엔진 |
| --- | --- |
| `.exe`, `.dll`, `.sys`, `.so`, `.elf`, `.bin`, `.dylib`, `.o`, `.ko` | IDA |
| `.apk`, `.dex` | JEB |

---

## 3. 핵심 명령 레퍼런스

### IDA 명령 (62개 = Tier1 5 + Tier2 22 + Tier3 35)

```bash
# 인스턴스 관리
revkit ida start Samples/EXE/notepad.exe    # 시작
revkit ida wait --timeout 300               # 분석 완료 대기
revkit ida status                           # 상태 조회
revkit ida list                             # 인스턴스 목록
revkit ida stop                             # 종료

# 분석
revkit ida summary                          # 함수/문자열/import 통계
revkit ida find-func "main"                 # 함수 검색
revkit ida func-info 0x140010108            # 함수 상세 정보
revkit ida decompile 0x140010108            # C 디컴파일
revkit ida decompile 0x140010108 --with-xrefs  # xref 포함
revkit ida disasm 0x140010108 --count 50    # 어셈블리
revkit ida segments                         # 세그먼트 목록
revkit ida imagebase                        # 베이스 주소
revkit ida bytes 0x140010108 --size 32      # 바이트 읽기
revkit ida find-pattern "48 89 5C"          # 바이트 패턴 검색
revkit ida xrefs 0x140010108 --direction both  # 크로스레퍼런스
revkit ida callers 0x140010108              # 호출자
revkit ida callees 0x140010108              # 피호출자
revkit ida callgraph 0x140010108 --depth 3  # 콜그래프
revkit ida cross-refs 0x140010108 --depth 2 # xref 체인
revkit ida search-code "if"                 # 디컴파일 코드 검색
revkit ida strings-xrefs                    # 문자열 xref

# 수정
revkit ida rename 0x140010108 my_func       # 이름 변경
revkit ida set-type 0x140010108 "int __fastcall my_func(int a1)"  # 타입 설정
revkit ida comment 0x140010108 "important"  # 코멘트 설정
revkit ida patch 0x140010108 90 90          # 바이트 패치
revkit ida search-const 0xFF                # 상수 검색
revkit ida auto-rename                      # 자동 이름 변경 (dry-run)
revkit ida rename-batch --file renames.json # 일괄 이름 변경

# 타입
revkit ida structs --action list            # 구조체 목록
revkit ida structs --action create --name "MY_STRUCT" --members f1:int f2:short
revkit ida enums --action list              # enum 목록
revkit ida enums --action create --name "MY_ENUM" --members A=0 B=1
revkit ida type-info 0x140010108            # 타입 정보
revkit ida vtables                          # vtable 감지
revkit ida sigs --action list               # FLIRT 시그니처 목록
revkit ida sigs --action apply pc/vc64rtf   # 시그니처 적용

# 비교
revkit ida diff IID1 IID2                   # 두 인스턴스 함수 비교
revkit ida compare binary_a binary_b        # 바이너리 비교
revkit ida code-diff IID1 IID2 --functions func_name  # 코드 비교

# 고급
revkit ida basic-blocks 0x140010108         # 기본 블록
revkit ida stack-frame 0x140010108          # 스택 프레임
revkit ida func-similarity 0x140010108      # 함수 유사도
revkit ida data-refs                        # 데이터 참조
revkit ida switch-table 0x140010108         # switch 분석
revkit ida profile --action run malware     # 프로파일링 (malware/firmware)

# 보고서
revkit ida report /tmp/report.md            # 리포트 생성
revkit ida export-script --out script.py    # IDAPython 스크립트 추출
revkit ida annotations --action export --out annot.json  # 어노테이션 내보내기
revkit ida annotations --action import annot.json        # 어노테이션 가져오기
revkit ida snapshot --action save --description "checkpoint"  # 스냅샷 저장
revkit ida snapshot --action list           # 스냅샷 목록
revkit ida snapshot --action restore snap_001  # 스냅샷 복원
revkit ida save                             # IDB 저장
revkit ida exec "result = idc.get_func_qty()"  # Python 코드 실행
```

### JEB 명령 (72개 = Tier1 5 + Tier2 22 + Tier3 45)

```bash
# 인스턴스 관리
revkit jeb start Samples/APK/UnCrackable/UnCrackable-Level3.apk --fresh
revkit jeb wait --timeout 300
revkit jeb status / list / stop

# 정찰
revkit jeb info                             # 앱 정보 (패키지, SDK, 액티비티)
revkit jeb permissions                      # 권한 목록
revkit jeb manifest                         # AndroidManifest.xml
revkit jeb components                       # 컴포넌트 (Activity/Service/Receiver/Provider)
revkit jeb main-activity                    # 메인 액티비티
revkit jeb app-class                        # Application 클래스
revkit jeb resources                        # 리소스 목록
revkit jeb resource "AndroidManifest.xml"   # 단일 리소스

# 분석
revkit jeb classes                          # 클래스 목록
revkit jeb classes --filter "Activity"      # 필터
revkit jeb decompile "Lsg/vantagepoint/uncrackable3/MainActivity;"  # Java 디컴파일
revkit jeb smali "Lsg/vantagepoint/uncrackable3/MainActivity;"      # Smali 출력
revkit jeb methods-of-class "Lsg/vantagepoint/uncrackable3/MainActivity;"
revkit jeb fields-of-class "Lsg/vantagepoint/uncrackable3/MainActivity;"
revkit jeb method-info "Lsg/vantagepoint/uncrackable3/MainActivity;->onCreate(Landroid/os/Bundle;)V"
revkit jeb native-methods                   # 네이티브 메서드
revkit jeb strings --filter "http"          # 문자열 검색
revkit jeb summary                          # 통계

# 검색
revkit jeb search-classes "Activity"        # 클래스 검색
revkit jeb search-methods "onCreate"        # 메서드 검색
revkit jeb search-code "getString"          # 코드 검색

# xref
revkit jeb xrefs "Lsg/.../MainActivity;->onCreate(...)V" --direction both
revkit jeb callers "Lsg/.../MainActivity;->onCreate(...)V"
revkit jeb callees "Lsg/.../MainActivity;->onCreate(...)V"
revkit jeb callgraph "Lsg/.../MainActivity;" --depth 2
revkit jeb cross-refs "Lsg/.../MainActivity;->onCreate(...)V" --depth 2

# 수정
revkit jeb rename-class "Lsg/.../a;" "DecryptHelper"
revkit jeb rename-method "Lsg/.../a;->b()V" "decrypt"
revkit jeb rename-field "Lsg/.../a;->c:I" "key_length"
revkit jeb set-comment "Lsg/.../a;->b()V" "decryption routine"
revkit jeb get-comments "Lsg/.../a;->b()V"
revkit jeb undo                             # 마지막 수정 되돌리기

# 보안
revkit jeb security-scan                    # 보안 스캔 (OWASP)
revkit jeb entry-points                     # 진입점 분석

# 보고서
revkit jeb report --out report.md
revkit jeb annotations-export --out annot.json
revkit jeb annotations-import annot.json
revkit jeb snapshot-save --description "checkpoint"
revkit jeb snapshot-list
revkit jeb snapshot-restore snap_001
revkit jeb save
revkit jeb exec "result = 'hello'"          # Jython 2.7 코드 실행
```

### Gateway 관리 명령 (16개) — `revkit -R gateway ...`

```bash
revkit -R gateway info                      # 상태 + uptime + 인스턴스 수
revkit -R gateway config                    # 설정 조회 (api_key 마스킹)
revkit -R gateway config-set key value      # 설정 변경
revkit -R gateway stop-all                  # 전체 인스턴스 정지
revkit -R gateway uploads                   # 업로드 파일 목록
revkit -R gateway uploads-clean             # 업로드 정리
revkit -R gateway audit --tail 50           # 감사 로그
revkit -R gateway system                    # 시스템 정보 (OS/CPU/RAM)
revkit -R gateway disk                      # 디스크 사용량
revkit -R gateway cleanup                   # stale 레지스트리 정리
revkit -R gateway rotate-key                # API 키 교체
revkit -R gateway allow-ip list             # IP 화이트리스트 조회
revkit -R gateway allow-ip add 10.0.0.0/8   # IP 추가
revkit -R gateway allow-ip remove 10.0.0.0/8 # IP 제거
revkit -R gateway connections --tail 10     # 연결 기록
revkit -R gateway download notepad --out /tmp/dl.exe  # 파일 다운로드
revkit -R gateway logs -i INSTANCE_ID --tail 10  # 인스턴스 로그
revkit -R gateway progress -i INSTANCE_ID   # 분석 진행률
```

---

## 4. 분석 워크플로우

### 4-1. EXE 종합 분석

```bash
# /analyze sample.exe 내부 동작
revkit ida start sample.exe
revkit ida wait --timeout 300
revkit ida summary                    # 통계 확인
revkit ida find-func "main"           # 주요 함수 검색
revkit ida decompile MAIN_ADDR        # 디컴파일
revkit ida xrefs MAIN_ADDR --direction both  # 참조 확인
revkit ida search-code "CreateFile"   # 키워드 검색
revkit ida report /tmp/report.md      # 리포트 생성
revkit ida stop
```

### 4-2. APK 보안 감사

```bash
# /security-scan sample.apk 내부 동작
revkit jeb start sample.apk --fresh
revkit jeb wait --timeout 300
revkit jeb info                       # 패키지/SDK 확인
revkit jeb permissions                # 위험 권한 확인
revkit jeb manifest                   # manifest 분석
revkit jeb components                 # 컴포넌트 (exported 확인)
revkit jeb entry-points               # 진입점
revkit jeb security-scan              # OWASP 스캔
revkit jeb native-methods             # JNI 확인
revkit jeb strings --filter "http"    # URL/API 키 검색
revkit jeb report --out /tmp/security_report.md
revkit jeb stop
```

### 4-3. 악성코드 분석

```bash
# /malware-scan sample.exe 내부 동작
revkit ida start sample.exe
revkit ida wait --timeout 300
revkit ida summary
revkit ida profile --action run malware   # C2/crypto/anti-debug 패턴
revkit ida search-code "CreateRemoteThread"  # 인젝션 기법
revkit ida strings-xrefs --filter "http"  # C2 URL
revkit ida callgraph SUSPECT_FUNC --depth 3  # 호출 관계
revkit ida report /tmp/malware_report.md
revkit ida stop
```

### 4-4. 원격 분석 (Gateway 경유)

```bash
# 로컬에 IDA/JEB 없이 원격 서버에서 분석
revkit -R ida start sample.exe           # 자동 업로드 + 시작
revkit -R ida wait --timeout 300
revkit -R ida decompile 0x401000 --out /tmp/result.c  # 결과 로컬 저장
revkit -R ida stop

# 또는 --remote URL 명시
revkit --remote http://192.168.50.100:9932 ida start sample.exe
```

### 4-5. 바이너리 비교

```bash
revkit ida start sample_v1.exe
revkit ida start sample_v2.exe
revkit ida wait -i IID1 --timeout 300
revkit ida wait -i IID2 --timeout 300
revkit ida diff IID1 IID2               # 함수 차이
revkit ida code-diff IID1 IID2 --functions target_func  # 코드 차이
revkit ida stop -i IID1 && revkit ida stop -i IID2
```

---

## 5. 원격 모드

### 활성화 방법 (3가지)

```bash
# 1. -R 플래그 (config gateway.url 사용)
revkit -R ida list

# 2. --remote URL 명시
revkit --remote http://192.168.50.100:9932 ida list

# 3. gateway.mode=auto (플래그 없이 자동)
# config: "gateway": {"mode": "auto", "url": "http://..."}
revkit ida list  # → 자동으로 Gateway 경유
```

### 우선순위

`--remote URL` > `config gateway.url` > 로컬 모드

### 클라이언트 설정

```json
{
  "gateway": {
    "url": "http://192.168.50.100:9932",
    "api_key": "YOUR_API_KEY"
  }
}
```

### LOCAL_ONLY 명령 (원격 불가)

`init`, `check`, `cleanup`, `logs`, `completions/completion`, `update`, `shell`, `compare`, `code-diff`, `batch`, `bookmark`

---

## 6. 보안 설정

```json
{
  "gateway": {
    "api_key": "your-secret-key",
    "allowed_ips": ["192.168.50.0/24"],
    "exec_enabled": false,
    "max_upload_size_mb": 500
  }
}
```

- 인증: `Authorization: Bearer {api_key}` 헤더
- IP 제한: CIDR 지원 (`allowed_ips`)
- exec 제어: gateway 레벨 + engine 레벨 2단계
- `/api/v1/health`는 항상 공개 (인증 불필요)

---

## 7. 문서 맵

### 참조 문서 (`docs/`)

| 문서 | 내용 | 언제 참조 |
| --- | --- | --- |
| [README-Setup.md](docs/README-Setup.md) | 설치, 환경 설정 | 처음 설치할 때 |
| [README-Config.md](docs/README-Config.md) | config.json 전체 키 설명 | 설정 변경할 때 |
| [README-IDA.md](docs/README-IDA.md) | IDA 62개 명령 상세 | IDA 명령 사용법 |
| [README-JEB.md](docs/README-JEB.md) | JEB 72개 명령 상세 | JEB 명령 사용법 |
| [README-RPC.md](docs/README-RPC.md) | JSON-RPC 프로토콜 (IDA 55 + JEB 60 메서드) | RPC 직접 호출 |
| [README-Remote.md](docs/README-Remote.md) | 원격 모드 (-R, --remote) | 원격 분석 설정 |
| [README-Gateway.md](docs/README-Gateway.md) | Gateway 아키텍처, 22개 API, 16개 관리 명령 | Gateway 운영 |
| [README-Security.md](docs/README-Security.md) | 보안 5계층 (인증/IP/exec/업로드/감사) | 보안 설정 |
| [README-Logging.md](docs/README-Logging.md) | JSONL 로깅 시스템 | 로그 확인/디버깅 |

### 튜토리얼 (`docs/tutorials/` — 17개)

| # | 주제 | 난이도 |
| --- | --- | --- |
| 00 | 설치 + 설정 | 초급 |
| 01 | 첫 IDA 분석 | 초급 |
| 02 | 첫 JEB 분석 | 초급 |
| 03 | 바이너리 비교 | 중급 |
| 04 | 배치 분석 | 중급 |
| 05 | 타입 시스템 (struct/enum/sig/vtable) | 중급 |
| 06 | 어노테이션 + 스냅샷 | 중급 |
| 07 | IDA exec 스크립트 | 고급 |
| 08 | JEB exec 스크립트 (Jython 2.7) | 고급 |
| 09 | RPC 자동화 | 고급 |
| 10 | CLI 명령 추가 (개발) | 고급 |
| 11 | RPC 핸들러 추가 (개발) | 고급 |
| 12 | Gateway 배포 | 고급 |
| 13 | AI 에이전트 분석 | 고급 |
| 14 | Gateway 원격 분석 (-R 모드) | 중급 |
| 15 | Gateway 관리 명령 (16개) | 중급 |
| 16 | 보안 설정 + 다중 인스턴스 | 고급 |

### 개발 가이드 (`guide/`)

| 세션 | 내용 |
| --- | --- |
| `test-sessions/` | IDA/JEB 321개 로컬 테스트 |
| `remote-test-sessions/` | Gateway 227개 원격 테스트 |
| `Tutorial-Sessions/` | 튜토리얼 생성 에이전트 설계서 |

---

## 8. 클라이언트-서버 구조

```
┌─────────────────────────────────┐     ┌──────────────────────────────────┐
│  Client (Windows/Mac/Linux)     │     │  Server (Linux)                  │
│                                 │     │                                  │
│  revkit CLI만 설치              │     │  revkit + IDA Pro + JEB Pro      │
│  IDA/JEB 불필요                 │     │  Gateway 데몬 실행 중            │
│                                 │     │                                  │
│  revkit -R ida start sample.exe │────→│  업로드 → IDA 분석 → RPC 응답   │
│                                 │     │                                  │
│  결과 출력 (터미널/파일)        │←────│  JSON 응답                       │
└─────────────────────────────────┘     └──────────────────────────────────┘
```

### 파일 흐름

```
클라이언트                          서버
────────                          ────
sample.apk (로컬)
    │
    ├─ revkit -R jeb start ──→  ~/uploads/sample.apk
    │                              │
    │                              ├─ JEB 분석 → .jdb2 프로젝트
    │                              │
    ├─ revkit -R jeb decompile ←── JSON 응답
    │
    ├─ revkit -R jeb report
    │   --out report.md ────────── 클라이언트에서 report.md 저장
    │
    └─ report.md (로컬)
```

---

## 9. 지원 파일 형식

| 형식 | 확장자 | 엔진 | 스킬 |
| --- | --- | --- | --- |
| Windows PE | `.exe`, `.dll`, `.sys` | IDA | analyze, security-scan, malware-scan, pe-audit |
| Linux ELF | `.so`, `.elf`, `.o`, `.ko` | IDA | analyze, security-scan, malware-scan, firmware-scan |
| macOS Mach-O | `.dylib`, `.macho` | IDA | analyze, security-scan |
| Firmware | `.bin`, `.efi` | IDA | firmware-scan, analyze |
| Android | `.apk`, `.dex` | JEB | analyze, security-scan, mobile-audit, malware-scan |
| iOS | `.ipa` (내부 Mach-O) | IDA | mobile-audit, analyze |

---

## 10. 주의사항

```
■ DEX 시그니처 형식 (JEB)
  클래스:  Lcom/example/Foo;
  메서드:  Lcom/example/Foo;->bar(Ljava/lang/String;)V
  필드:    Lcom/example/Foo;->field:I

■ IDA 주소 형식
  16진수: 0x140010108, 0x401000

■ JEB exec = Jython 2.7
  f-string 불가, type hint 불가, flush=True 불가

■ 인스턴스 관리
  분석 후 반드시 stop (서버 리소스 해제)
  max_instances 초과 시 start 거부
  gateway stop-all로 전체 정리

■ 원격 모드
  --out 사용 시 클라이언트 로컬에 저장 (서버 아님)
  Gateway가 모든 RPC 메서드를 프록시 (기능 손실 없음)
  LOCAL_ONLY 명령은 원격 불가 (init, check, cleanup, shell, compare, batch, bookmark 등)
```
