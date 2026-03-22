---
description: Security audit an APK/binary with revkit
---

Perform a security audit on: $ARGUMENTS

Steps:
1. Detect engine from file extension (.apk/.dex → jeb, others → ida)
2. If user specified `-R` or remote mode, prefix all revkit commands with `-R`
3. Start: `revkit {-R} {engine} start {path}` (--fresh for JEB)
4. Wait: `revkit {-R} {engine} wait --timeout 300`

For JEB (APK):
- `revkit {-R} jeb entry-points` → exported components (attack surface)
- `revkit {-R} jeb security-scan` → vulnerability findings
- `revkit {-R} jeb permissions` → dangerous permissions
- `revkit {-R} jeb native-methods` → JNI interface (native backdoors)
- `revkit {-R} jeb manifest` → check allowBackup, debuggable, minSdkVersion
- `revkit {-R} jeb strings --regex "password|secret|api.key|token"` → hardcoded secrets
- `revkit {-R} jeb search-code "setJavaScriptEnabled"` → WebView JavaScript
- `revkit {-R} jeb search-code "addJavascriptInterface"` → JS→Java bridge (RCE risk)
- `revkit {-R} jeb search-code "X509TrustManager"` → custom cert validation
- `revkit {-R} jeb search-code "DexClassLoader"` → dynamic code loading
- `revkit {-R} jeb search-code "isDebuggerConnected"` → anti-debug detection
- `revkit {-R} jeb search-code "checkRoot"` → root detection

For IDA (binary):
- `revkit {-R} ida profile --action run vuln` → dangerous imports
- `revkit {-R} ida strings-xrefs` → URLs, IPs, paths
- `revkit {-R} ida find-func --regex "debug|anti|vm"` → anti-analysis
- `revkit {-R} ida exec "analysis/find_crypto_consts.py"` → crypto constants
- `revkit {-R} ida search-const 0xFF` → suspicious constants

5. Classify findings by severity: CRITICAL, HIGH, MEDIUM, LOW
6. Generate security audit report with recommendations
7. Stop: `revkit {-R} {engine} stop`
