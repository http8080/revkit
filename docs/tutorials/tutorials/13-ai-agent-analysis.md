# Tutorial 13: AI Agent Analysis with Claude Code / Claude Code 자동 분석

Use Claude Code as an AI-powered reverse engineering assistant. Claude reads the codebase context from CLAUDE.md and drives revkit commands automatically.

Claude Code를 AI 기반 리버스 엔지니어링 어시스턴트로 사용합니다. Claude가 CLAUDE.md에서 코드베이스 컨텍스트를 읽고 revkit 명령을 자동으로 실행합니다.

> **Prerequisites / 사전 준비**: Claude Code installed, revkit configured, IDA/JEB available / Claude Code 설치, revkit 설정, IDA/JEB 사용 가능

```bash
RK="python -m revkit.tools.cli.main"
```

---

## 1. How It Works / 작동 방식

Claude Code reads `CLAUDE.md` at the project root, which contains the full revkit architecture, command reference, and coding conventions. This gives Claude the context to run revkit commands correctly.

Claude Code가 프로젝트 루트의 `CLAUDE.md`를 읽어 revkit의 전체 아키텍처, 명령 참조, 코딩 규칙을 파악합니다. 이를 통해 Claude가 revkit 명령을 올바르게 실행할 수 있습니다.

```
User prompt  →  Claude Code  →  revkit CLI  →  IDA/JEB Server
   "analyze        reads            runs          returns
    this           CLAUDE.md        commands       results
    binary"        for context
```

---

## 2. Basic Usage / 기본 사용법

Start a Claude Code session in the revkit project directory. Claude automatically picks up `CLAUDE.md`.

revkit 프로젝트 디렉토리에서 Claude Code 세션을 시작합니다. Claude가 자동으로 `CLAUDE.md`를 인식합니다.

```bash
# Start Claude Code in the revkit directory / revkit 디렉토리에서 Claude Code 시작
cd /path/to/revkit
claude
```

Then ask Claude to analyze a binary:

그런 다음 Claude에게 바이너리 분석을 요청합니다:

```
User: Start IDA on Samples/EXE/notepad.exe and give me a summary of the binary.

Claude will:
1. Run: $RK ida start Samples/EXE/notepad.exe
2. Run: $RK ida wait
3. Run: $RK ida summary
4. Present a human-readable summary of the results
```

---

## 3. Analysis Prompts / 분석 프롬프트

### Binary Overview / 바이너리 개요

```
Prompt: "Start IDA on notepad.exe, wait for analysis, then tell me:
- How many functions are there?
- What are the main entry points?
- Are there any interesting string references?"
```

### Function Deep-Dive / 함수 심층 분석

```
Prompt: "Decompile the function at 0x140010108 and explain what it does.
Then show me all callers and callees."
```

Claude will run `decompile`, `callers`, and `callees` commands and synthesize the results.

Claude가 `decompile`, `callers`, `callees` 명령을 실행하고 결과를 종합합니다.

### APK Analysis / APK 분석

```
Prompt: "Start JEB on sample.apk. Show me the manifest, list all permissions,
and find the main activity class. Then decompile it."
```

---

## 4. Security Audit Prompts / 보안 감사 프롬프트

Claude can perform systematic security analysis using revkit commands.

Claude는 revkit 명령을 사용하여 체계적인 보안 분석을 수행할 수 있습니다.

### IDA Binary Audit / IDA 바이너리 감사

```
Prompt: "Perform a security audit of this binary:
1. Find functions with 'crypt', 'hash', 'key' in their names
2. Search for suspicious strings (URLs, IPs, registry keys)
3. Check for dangerous API calls (VirtualAlloc, CreateRemoteThread, WriteProcessMemory)
4. List all imported DLLs and flag unusual ones
5. Summarize findings with risk levels."
```

### JEB APK Audit / JEB APK 감사

```
Prompt: "Security scan this APK:
1. List all permissions and flag dangerous ones
2. Find all native methods (JNI bridge)
3. Search for hardcoded URLs and API keys in strings
4. Check for obfuscation indicators
5. List all exported components (activities, services, receivers)
6. Provide a security risk summary."
```

---

## 5. Batch + AI Summary Pipeline / 배치 + AI 요약 파이프라인

Combine revkit batch operations with Claude's analysis capabilities.

revkit 배치 작업과 Claude의 분석 능력을 결합합니다.

### Multi-Binary Comparison / 다중 바이너리 비교

```
Prompt: "I have two versions of a binary: v1.exe and v2.exe.
Start IDA on both, then:
1. Compare function counts
2. Use diff to find changed functions
3. Decompile the top 3 most-changed functions from each version
4. Summarize what changed between versions."
```

### Bulk APK Triage / 대량 APK 분류

```
Prompt: "I have 5 APK files in Samples/APK/. For each one:
1. Start JEB and get basic info (package name, permissions, components)
2. Flag any with dangerous permissions
3. Create a summary table ranking them by risk.
Use batch mode where possible to speed this up."
```

---

## 6. CLAUDE.md as Project Context / CLAUDE.md를 프로젝트 컨텍스트로

The `CLAUDE.md` file at the project root is the key to effective AI analysis. It provides:

프로젝트 루트의 `CLAUDE.md` 파일이 효과적인 AI 분석의 핵심입니다. 제공하는 정보:

| Section / 섹션 | What Claude Learns / Claude가 학습하는 것 |
|---|---|
| Project overview / 개요 | Architecture, file layout / 아키텍처, 파일 구조 |
| Command tiers / 명령 계층 | Which commands exist, IDA vs JEB differences / 존재하는 명령, IDA vs JEB 차이 |
| Core API | Shared modules, config structure / 공유 모듈, 설정 구조 |
| Bug patterns / 버그 패턴 | Known issues to avoid / 피해야 할 알려진 이슈 |
| Test procedures / 테스트 절차 | How to verify commands work / 명령 동작 확인 방법 |

For your own projects, create a similar `CLAUDE.md` with analysis-specific context:

자신의 프로젝트를 위해 분석 특화 컨텍스트를 포함한 유사한 `CLAUDE.md`를 생성하세요:

```markdown
# CLAUDE.md for malware analysis project
## Target: suspicious_sample.exe
## Known indicators: connects to 185.x.x.x, drops payload to %TEMP%
## Analysis goals: find C2 protocol, extract config, identify packer
## revkit instance: already running on port 18100
```

---

## 7. Prompt Templates / 프롬프트 템플릿

Copy-paste these templates for common analysis tasks.

일반적인 분석 작업을 위해 이 템플릿을 복사하여 사용하세요.

### Template: Quick Triage / 빠른 분류

```
Start {ida|jeb} on {file_path} and provide a quick triage:
- File type, size, architecture
- Number of functions/classes
- Notable strings (URLs, IPs, crypto-related)
- Import/export summary
- Initial risk assessment (1-5 scale)
```

### Template: Function Analysis / 함수 분석

```
For the function at {addr|sig}:
1. Decompile and explain the logic
2. Show all cross-references (callers + callees)
3. Identify the data structures it uses
4. Rate complexity (simple/moderate/complex)
5. Flag any security concerns
```

### Template: Comparison Report / 비교 보고서

```
Compare {file_a} and {file_b}:
1. Start instances for both
2. Compare function counts and names
3. Identify added/removed/changed functions
4. Decompile the most significant changes
5. Generate a diff report in markdown format
```

### Template: Full Security Report / 전체 보안 보고서

```
Perform a comprehensive security analysis of {file_path}:
1. Basic info and structure
2. Permission/import analysis
3. String analysis (hardcoded secrets, URLs, commands)
4. Crypto usage detection
5. Anti-analysis technique detection
6. Network communication patterns
7. Generate a structured report with findings and risk ratings
```

---

## 8. Tips for Effective AI Analysis / 효과적인 AI 분석 팁

**Be specific**: Tell Claude exactly what you want to analyze and what format you expect.

**구체적으로**: 분석할 대상과 원하는 형식을 정확히 알려주세요.

**Iterate**: Start broad (summary), then drill down into specific functions or patterns.

**반복적으로**: 넓은 범위(요약)에서 시작하여 특정 함수나 패턴으로 좁혀가세요.

**Use JSON output**: Ask Claude to use `--json` for machine-readable output that's easier to process.

**JSON 출력 사용**: 처리하기 쉬운 기계 가독 출력을 위해 `--json`을 사용하도록 요청하세요.

**Save state**: Ask Claude to use `snapshot` and `bookmark` to save important findings.

**상태 저장**: 중요한 발견을 저장하기 위해 `snapshot`과 `bookmark`을 사용하도록 요청하세요.

**Batch when possible**: For operations across many functions/classes, use `batch`, `decompile-all`, or `decompile-batch` instead of individual calls.

**가능하면 배치로**: 많은 함수/클래스에 걸친 작업에는 개별 호출 대신 `batch`, `decompile-all`, `decompile-batch`를 사용하세요.

**Context matters**: The more context you provide in your prompt (known indicators, analysis goals, target platform), the better Claude's analysis will be.

**컨텍스트가 중요합니다**: 프롬프트에 더 많은 컨텍스트(알려진 지표, 분석 목표, 대상 플랫폼)를 제공할수록 Claude의 분석이 더 나아집니다.

---

**Previous / 이전**: [12-gateway-setup.md](12-gateway-setup.md) — Gateway deployment and security / Gateway 배포 + 보안
