---
description: Scan for vulnerabilities in a binary or APK
---

Scan for vulnerabilities in: $ARGUMENTS

Steps:
1. Detect engine from file extension
2. If user specified `-R` or remote mode, prefix all revkit commands with `-R`
3. Start and wait: `revkit {-R} {engine} start {path}` (--fresh for JEB), `revkit {-R} {engine} wait --timeout 300`

For IDA (binary):
- `revkit {-R} ida profile --action run vuln` → dangerous imports
- Check for: strcpy, gets, sprintf, system, popen (buffer overflow, command injection)
- Find input handlers: `revkit {-R} ida find-func --regex "recv|read|fread|ReadFile"`
- Trace call paths from input → dangerous function via `revkit {-R} ida callgraph {addr} --depth 5`
- Check security: stack canary (__security_check_cookie), ASLR, CFG (__guard_check_icall)

For JEB (APK):
- `revkit {-R} jeb entry-points` → exported components (attack surface)
- `revkit {-R} jeb search-code "setJavaScriptEnabled"` → WebView JS enabled
- `revkit {-R} jeb search-code "addJavascriptInterface"` → JS→Java bridge (RCE if targetSdk<17)
- `revkit {-R} jeb search-code "X509TrustManager"` → custom cert validation bypass
- `revkit {-R} jeb manifest` → deeplink schemes (URL hijacking)
- `revkit {-R} jeb search-code "getIntent"` → intent data handling without validation

4. Classify: HIGH (RCE potential), MEDIUM (info leak), LOW (best practice)
5. Generate vulnerability report with exploit scenarios
6. Stop: `revkit {-R} {engine} stop`
