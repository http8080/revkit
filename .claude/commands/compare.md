---
description: Compare two binaries with revkit diff
---

Compare these two files: $ARGUMENTS

The two file paths should be space-separated (e.g., file1.exe file2.elf).

Steps:
1. If user specified `-R` or remote mode, prefix all revkit commands with `-R`
2. Start IDA for both files:
   `revkit {-R} ida start {file1}`
   `revkit {-R} ida start {file2}`
3. Wait for both: `revkit {-R} ida wait -i {id1}` and `revkit {-R} ida wait -i {id2}`
4. Get instance IDs from `revkit {-R} ida list`
5. Run `revkit {-R} ida diff {id1} {id2}` → function-level comparison
6. Run `revkit {-R} ida code-diff {id1} {id2}` → code-level diff
7. Run `revkit {-R} ida summary` on each → comparison table
8. Create comparison report:
   - Architecture differences
   - Function count comparison
   - Common vs unique functions
   - Code differences in shared functions
9. Stop both: `revkit {-R} ida stop -i {id1}` and `revkit {-R} ida stop -i {id2}`
