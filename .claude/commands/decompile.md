---
description: Quick decompile a function/class from a binary or APK
---

Decompile from: $ARGUMENTS

First argument = file path, second = address (IDA) or DEX signature (JEB).
JEB DEX signature format: `Lcom/example/Foo;` (class) or `Lcom/example/Foo;->bar()V` (method)

Steps:
1. Detect engine from file extension (.exe/.so → ida, .apk/.dex → jeb)
2. If user specified `-R` or remote mode, prefix all revkit commands with `-R`
3. Start: `revkit {-R} {engine} start {file}` (--fresh for JEB)
4. Wait: `revkit {-R} {engine} wait --timeout 300`
5. For IDA: `revkit {-R} ida decompile {addr} --with-xrefs`
6. For JEB: `revkit {-R} jeb decompile {sig} --with-xrefs`
7. Show the decompiled code
8. Explain what the code does -- logic, key operations, potential issues
9. Stop: `revkit {-R} {engine} stop`

If no address/signature is given:
- IDA: run `revkit {-R} ida find-func "main"` and decompile the first result
- JEB: run `revkit {-R} jeb main-activity` and decompile that class
