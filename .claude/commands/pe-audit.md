---
description: Deep Windows PE binary analysis (EXE/DLL)
---

Analyze Windows PE binary: $ARGUMENTS

Steps:
1. If user specified `-R` or remote mode, prefix all revkit commands with `-R`
2. Start IDA: `revkit {-R} ida start {path}`
3. Wait: `revkit {-R} ida wait --timeout 180`
4. Basic info:
   - `revkit {-R} ida summary` → functions, strings, imports
   - `revkit {-R} ida imagebase` → ASLR check
   - `revkit {-R} ida segments` → section layout (.text, .rdata, .data, .rsrc)
5. Import analysis by category:
   - File I/O: CreateFile, ReadFile, WriteFile, DeleteFile
   - Registry: RegOpenKey, RegSetValue, RegQueryValue
   - Process: CreateProcess, OpenProcess, VirtualAlloc, WriteProcessMemory
   - Network: socket, connect, send, recv, InternetOpen, HttpSendRequest
   - Crypto: CryptEncrypt, BCryptEncrypt
   - Debug: IsDebuggerPresent, CheckRemoteDebuggerPresent
   - Injection: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
   - Service: CreateService, StartService
6. Detect dangerous combinations:
   - VirtualAlloc + WriteProcessMemory + CreateRemoteThread → process injection
   - RegSetValue + "\\Run\\" → persistence
   - socket + connect + send → C2 communication
7. Security mechanisms:
   - ASLR: check for relocation support
   - Stack canary: `revkit {-R} ida find-func "__security_check_cookie"`
   - CFG: `revkit {-R} ida find-func "__guard_check_icall"`
   - DEP/NX: check .text execute permission
8. String analysis: URLs, IPs, registry paths, commands (cmd.exe, powershell)
9. Function stats: `revkit {-R} ida find-func --regex "^sub_"` → stripped count
10. Vulnerability: `revkit {-R} ida profile --action run vuln`
11. Generate PE audit report
12. Stop: `revkit {-R} ida stop`
