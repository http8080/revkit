---
description: Analyze a binary/APK file with revkit (auto-detect engine)
---

Analyze the file at path: $ARGUMENTS

Steps:
1. Detect engine from file extension:
   - .exe/.dll/.so/.elf/.bin/.sys/.dylib/.mach/.macho/.o/.ko/.efi → use `ida`
   - .apk/.dex → use `jeb`
   - .ipa → extract Mach-O from IPA, use `ida`
2. If user specified `-R` or remote mode, prefix all revkit commands with `-R`
3. Run: `revkit {-R} {engine} start {path}` (add `--fresh` for JEB)
4. Run: `revkit {-R} {engine} wait --timeout 300`
5. For IDA (binary):
   - `revkit {-R} ida summary`
   - `revkit {-R} ida find-func "main"`
   - Decompile main function: `revkit {-R} ida decompile {addr}`
   - `revkit {-R} ida strings-xrefs`
   - `revkit {-R} ida profile --action run vuln`
6. For JEB (APK/DEX):
   - `revkit {-R} jeb info`
   - `revkit {-R} jeb permissions`
   - `revkit {-R} jeb components`
   - `revkit {-R} jeb classes --count-only`
   - Decompile main activity: `revkit {-R} jeb decompile {main_activity_sig}`
   - `revkit {-R} jeb native-methods`
   - `revkit {-R} jeb security-scan`
   - `revkit {-R} jeb entry-points`
7. Generate a markdown analysis report with all findings
8. `revkit {-R} {engine} stop`
9. Save report to `tmp/analysis_{filename}.md`

Important:
- Always stop the instance when done
- If start fails, check `revkit {engine} check` first
- For JEB, use `--fresh` flag to ensure clean analysis
- For remote mode (-R), file is auto-uploaded to server
- `--out` saves to local machine even in remote mode
