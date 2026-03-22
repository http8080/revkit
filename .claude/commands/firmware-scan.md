---
description: Analyze firmware binary for embedded device security
---

Analyze firmware binary: $ARGUMENTS

Steps:
1. If user specified `-R` or remote mode, prefix all revkit commands with `-R`
2. Start IDA: `revkit {-R} ida start {path}`
3. Wait: `revkit {-R} ida wait --timeout 300`
4. Firmware-specific analysis:
   - `revkit {-R} ida summary` → function count, architecture
   - `revkit {-R} ida segments` → memory map (ROM/RAM/MMIO regions)
   - `revkit {-R} ida imagebase` → load address
   - `revkit {-R} ida profile --action run firmware` → peripheral, protocol, boot analysis
   - `revkit {-R} ida find-func --regex "uart|spi|i2c|gpio"` → peripheral drivers
   - `revkit {-R} ida strings-xrefs` → search for: login, password, shell, root, UART commands
   - `revkit {-R} ida find-pattern "55 AA"` → boot signatures
   - `revkit {-R} ida search-code "memcpy"` → potential buffer overflows in firmware
5. Identify: bootloader, RTOS, communication protocols, debug interfaces
6. Generate firmware analysis report
7. Stop: `revkit {-R} ida stop`
