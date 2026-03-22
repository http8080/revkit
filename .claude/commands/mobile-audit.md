---
description: Deep mobile app security audit (APK/IPA) with OWASP MASVS
---

Perform mobile app security audit on: $ARGUMENTS

Steps:
1. Detect platform: .apk/.dex → Android (JEB), .ipa → iOS (IDA)
2. If user specified `-R` or remote mode, prefix all revkit commands with `-R`
3. Start and wait: `revkit {-R} {engine} start {path}` (--fresh for JEB), `revkit {-R} {engine} wait --timeout 300`

For Android APK (JEB):
- `revkit {-R} jeb info` → package, main activity, SDK version
- `revkit {-R} jeb permissions` → dangerous permissions
- `revkit {-R} jeb components` → exported components
- `revkit {-R} jeb manifest` → allowBackup, debuggable, minSdkVersion
- `revkit {-R} jeb entry-points` → attack surface
- `revkit {-R} jeb security-scan` → vulnerability scan
- `revkit {-R} jeb native-methods` → JNI interface

OWASP MASVS checks:
- STORAGE: `revkit {-R} jeb search-code "SharedPreferences|getExternalStorage|SQLiteDatabase"`
- CRYPTO: `revkit {-R} jeb search-code "MD5|Cipher|SecretKey"` + `revkit {-R} jeb strings --regex "password|secret|api.key"`
- NETWORK: `revkit {-R} jeb strings --regex "http://"` + `revkit {-R} jeb search-code "X509TrustManager"`
- PLATFORM: `revkit {-R} jeb search-code "setJavaScriptEnabled|addJavascriptInterface|loadUrl"`
- RESILIENCE:
  Root: `revkit {-R} jeb search-code "checkRoot|RootBeer|su |/system/xbin/su|Superuser|magisk"`
  Frida: `revkit {-R} jeb search-code "frida|fridaserver|27042|/proc/self/maps"`
  Debug: `revkit {-R} jeb search-code "isDebuggerConnected|TracerPid|ptrace"`
  Integrity: `revkit {-R} jeb search-code "getPackageInfo.*signatures|CRC|checksumCRC"`
  Emulator: `revkit {-R} jeb search-code "generic|goldfish|sdk|emulator|ro.kernel.qemu"`

For iOS IPA (IDA on Mach-O):
- Extract binary from IPA
- Jailbreak: `revkit {-R} ida find-func "jailbreak|isJailbroken"` + `revkit {-R} ida strings-xrefs --filter "Cydia|/bin/bash"`
- Frida: `revkit {-R} ida strings-xrefs --filter "frida|fridaserver"` + `revkit {-R} ida find-func "sysctl|ptrace"`
- SSL: `revkit {-R} ida find-func "SecTrustEvaluate"` + `revkit {-R} ida strings-xrefs --filter ".cer|.pem"`

4. Classify by OWASP MASVS category
5. Rate protection level (0=none, 1=basic, 2=medium, 3=strong, 4=maximum)
6. Generate audit report with findings and recommendations
7. Stop: `revkit {-R} {engine} stop`
