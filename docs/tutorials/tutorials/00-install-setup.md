# Tutorial 00: Installation & Setup / 설치 + 환경 구성

Install revkit and configure IDA Pro / JEB Pro on your platform.

revkit을 설치하고 IDA Pro / JEB Pro를 설정합니다.

---

## Prerequisites / 사전 요구사항

| Requirement / 요구사항 | Version / 버전 | Notes / 비고 |
| --- | --- | --- |
| Python | 3.10+ | Must be on PATH / PATH에 있어야 함 |
| IDA Pro | 9.3+ | License required / 라이선스 필요 |
| JEB Pro | 5.x | License required / 라이선스 필요 |
| Java | 17+ (21 recommended) | For JEB engine / JEB 엔진용 |

You need at least one of IDA Pro or JEB Pro. Both are not required.

IDA Pro 또는 JEB Pro 중 최소 하나가 필요합니다. 둘 다 필요하지 않습니다.

---

## Step 1: Install Python packages / Python 패키지 설치

```bash
# Install revkit (from project root)
# revkit 설치 (프로젝트 루트에서)
pip install -e .

# Install dependencies / 의존성 설치
pip install requests psutil
```

Verify / 확인:

```bash
python -m revkit.tools.cli.main --help
# Expected: usage: revkit [-h] ... {ida,jeb} ...
# 기대: {ida,jeb} 서브커맨드 표시
```

---

## Step 2: Configure IDA Pro / IDA Pro 설정

### Windows

```bash
# Config / 설정
cat > ~/.revkit/config.json << 'EOF'
{
    "ida": {
        "install_dir": "C:/Program Files/IDA Professional 9.3"
    }
}
EOF
```

### Linux

```bash
# 1. Install idalib / idalib 설치
pip install ~/ida-pro-9.3/idalib/python/idapro-*.whl

# 2. Activate (REQUIRED on Linux — without this, ida_loader won't load)
#    활성화 (Linux 필수 — 안 하면 ida_loader를 찾을 수 없음)
python ~/ida-pro-9.3/idalib/python/py-activate-idalib.py -d ~/ida-pro-9.3

# 3. Config / 설정
mkdir -p ~/.revkit
cat > ~/.revkit/config.json << 'EOF'
{
    "ida": {
        "install_dir": "~/ida-pro-9.3"
    }
}
EOF
```

### Verify / 확인

```bash
python -m revkit.tools.cli.main ida init
python -m revkit.tools.cli.main ida check
# Expected: [+] All checks passed
# 기대: [+] All checks passed
```

> **Troubleshooting**: If `ida check` passes but `ida start` fails with `ModuleNotFoundError: No module named 'ida_loader'`, you forgot the activate step on Linux.
>
> **트러블슈팅**: `ida check`는 통과하지만 `ida start`가 `ida_loader` 에러로 실패하면 Linux에서 activate 단계를 빠뜨린 것입니다.

---

## Step 3: Configure JEB Pro / JEB Pro 설정

### Windows

```json
{
    "jeb": {
        "install_dir": "C:/WorkSpace/bin/JEB-5.38",
        "spawn_method": "wrapper",
        "java_home": "C:/Program Files/Java/jdk-21"
    }
}
```

### Linux

```bash
# Config / 설정 (add to existing config.json / 기존 config.json에 추가)
# jeb section:
{
    "jeb": {
        "install_dir": "~/JEB-5.38",
        "spawn_method": "wrapper",
        "java_home": "/usr/lib/jvm/java-21-openjdk-amd64"
    }
}
```

> **Important / 중요**: `spawn_method` must be `"wrapper"` on Linux. `"bat"` mode is Windows-only.
>
> Linux에서 `spawn_method`는 반드시 `"wrapper"`. `"bat"` 모드는 Windows 전용.

### Generate Script Runner / 스크립트 러너 생성

```bash
# MUST run once / 반드시 1회 실행
python -m revkit.tools.cli.main jeb gen-runner
# Expected: [+] Compiled: JebScriptRunner.class
```

### Verify / 확인

```bash
python -m revkit.tools.cli.main jeb init
python -m revkit.tools.cli.main jeb check
# Expected: Launcher: OK, Runner: OK, [+] All checks passed
```

---

## Step 4: First Analysis / 첫 분석

### IDA — Binary Analysis / 바이너리 분석

```bash
RK="python -m revkit.tools.cli.main"

# Start analysis server / 분석 서버 시작
$RK ida start path/to/binary.exe

# Wait for analysis to complete / 분석 완료 대기
$RK ida wait --timeout 180

# Decompile a function / 함수 디컴파일
$RK ida decompile 0x401000

# Stop server / 서버 종료
$RK ida stop
```

### JEB — APK Analysis / APK 분석

```bash
# Start with fresh analysis / 새 분석으로 시작
$RK jeb start path/to/app.apk --fresh

# Wait (JEB takes longer — JVM boot + DEX parsing)
# 대기 (JEB는 더 오래 걸림 — JVM 부팅 + DEX 파싱)
$RK jeb wait --timeout 300

# Decompile a class / 클래스 디컴파일
$RK jeb decompile "Lcom/example/MainActivity;"

# Stop / 종료
$RK jeb stop
```

---

## Step 5: Verify Logs / 로그 확인

```bash
# Check log directory / 로그 디렉토리 확인
ls ~/.revkit/logs/

# If something goes wrong, check these:
# 문제 발생 시 확인할 파일:
# 1. Server stderr / 서버 표준 에러
ls ~/.revkit/logs/ida/instances/     # or jeb/instances/

# 2. Global log / 전역 로그
tail -5 ~/.revkit/logs/revkit.jsonl
```

---

## Quick Reference / 빠른 참조

| Command / 명령 | Description / 설명 |
| --- | --- |
| `revkit ida init` | Create data directories / 데이터 디렉토리 생성 |
| `revkit ida check` | Verify IDA installation / IDA 설치 확인 |
| `revkit ida start <binary>` | Start analysis server / 분석 서버 시작 |
| `revkit ida wait` | Wait for server ready / 서버 준비 대기 |
| `revkit ida list` | List active instances / 활성 인스턴스 목록 |
| `revkit ida stop` | Stop instance / 인스턴스 중지 |

Replace `ida` with `jeb` for JEB commands. / JEB 명령은 `ida`를 `jeb`로 변경.

---

## Next / 다음

- [01-first-ida-analysis.md](01-first-ida-analysis.md) — Detailed IDA walkthrough / IDA 상세 실습
- [02-first-jeb-analysis.md](02-first-jeb-analysis.md) — Detailed JEB walkthrough / JEB 상세 실습
