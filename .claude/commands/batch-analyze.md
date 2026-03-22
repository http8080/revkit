---
description: Batch analyze all files in a directory
---

Batch analyze files in: $ARGUMENTS

Steps:
1. List files in the directory
2. If user specified `-R` or remote mode, prefix all revkit commands with `-R`
3. For each file, detect engine from extension:
   - .exe/.dll/.so/.elf/.bin → ida
   - .apk/.dex → jeb
   - Skip unsupported extensions
4. For IDA binaries: `revkit {-R} ida batch {dir} --timeout 120`
5. For JEB APKs: `revkit {-R} jeb batch {dir} --timeout 120`
6. If directory has mixed types (EXE + APK), run IDA batch first, then JEB batch
7. Collect results for each file: success/failure, function/class count
8. Create summary comparison table:
   | File | Engine | Functions/Classes | Imports | Strings | Size |
9. Stop all instances after batch completes
10. Clean up: `revkit {-R} ida list` and `revkit {-R} jeb list` → should show "No active instances"
