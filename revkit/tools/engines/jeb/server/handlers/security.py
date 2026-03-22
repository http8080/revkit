# -*- coding: utf-8 -*-
"""Security handlers -- entry points analysis, security scan.

Runs under Jython 2.7 (Python 2 syntax). No f-strings, no type hints.
"""

from .helpers import (
    _require_apk, _read_manifest_text, _get_decompiler, _to_str,
    _FRAMEWORK_PREFIXES,
)

# Dangerous Android permissions
_DANGEROUS_PERMS = frozenset([
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA", "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS", "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
])

# Patterns for security scan
_CRYPTO_PATTERNS = [
    ("ECB mode", "ECB"),
    ("DES (weak)", "/DES/"),
    ("MD5 (weak hash)", "MD5"),
    ("SHA1 (weak hash)", "\"SHA-1\""),
    ("Static IV", "IvParameterSpec"),
    ("Hardcoded key", "SecretKeySpec"),
]

_SECRET_PATTERNS = [
    ("API key", r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][A-Za-z0-9+/=]{16,}'),
    ("AWS key", r'AKIA[0-9A-Z]{16}'),
    ("Private key", r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
    ("Password", r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}'),
    ("Token", r'(?:token|secret|auth)\s*[:=]\s*["\'][A-Za-z0-9+/=_-]{16,}'),
]


def _handle_entry_points(self, params):
    """Analyze attack surface: exported components, deeplinks, JS interfaces."""
    import re
    _require_apk(self)
    text = _read_manifest_text(self)
    if not text:
        raise self.RpcError("MANIFEST_NOT_FOUND", "Cannot read manifest")

    exported = []
    deeplinks = []
    providers = []

    # Parse activities, services, receivers, providers
    for tag in ["activity", "service", "receiver", "provider"]:
        pattern = r'<' + tag + r'\b([^>]*)(/?>)'
        for m in re.finditer(pattern, text, re.DOTALL):
            attrs = m.group(1)
            name_m = re.search(r'android:name="([^"]*)"', attrs)
            if not name_m:
                continue
            name = name_m.group(1)
            is_exported = 'android:exported="true"' in attrs

            # Find full tag content for intent filters
            start = m.start()
            if m.group(2) == "/>":
                full_content = m.group(0)
            else:
                end_tag = "</" + tag + ">"
                end_pos = text.find(end_tag, start)
                full_content = text[start:end_pos + len(end_tag)] if end_pos > 0 else m.group(0)
                # Exported if has intent-filter (implicit)
                if "intent-filter" in full_content:
                    is_exported = True

            if is_exported:
                comp = {"type": tag, "name": name, "intent_filters": []}
                # Parse intent filters
                for ifm in re.finditer(r'<intent-filter[^>]*>(.*?)</intent-filter>',
                                        full_content, re.DOTALL):
                    if_content = ifm.group(1)
                    actions = re.findall(r'android:name="([^"]*)"', if_content)
                    intent = {}
                    for a in actions:
                        if "action" in a.lower() or "." in a:
                            intent["action"] = a
                    # Deeplink data
                    data_m = re.findall(r'<data\s+([^/]*)/>', if_content)
                    for d in data_m:
                        scheme = re.search(r'android:scheme="([^"]*)"', d)
                        host = re.search(r'android:host="([^"]*)"', d)
                        path = re.search(r'android:path(?:Prefix|Pattern)?"([^"]*)"', d)
                        if scheme:
                            dl = {"scheme": scheme.group(1),
                                  "host": host.group(1) if host else "",
                                  "path": path.group(1) if path else "",
                                  "activity": name}
                            deeplinks.append(dl)
                            intent["data"] = "%s://%s%s" % (
                                dl["scheme"], dl["host"], dl["path"])
                    if intent:
                        comp["intent_filters"].append(intent)
                exported.append(comp)

            if tag == "provider" and is_exported:
                authority_m = re.search(r'android:authorities="([^"]*)"', attrs)
                providers.append({
                    "name": name,
                    "exported": True,
                    "authorities": authority_m.group(1) if authority_m else "",
                })

    # Search for JS interfaces in code
    js_interfaces = []
    for dex in self.dex_units:
        for cls in dex.getClasses():
            sig = cls.getSignature(True)
            if any(sig.startswith(p) for p in _FRAMEWORK_PREFIXES):
                continue
            try:
                decomp = _get_decompiler(self, dex)
                decomp.decompileClass(sig)
                code = decomp.getDecompiledClassText(sig)
                if not code:
                    continue
                code = _to_str(code)
                if "addJavascriptInterface" in code:
                    for line in code.split("\n"):
                        if "addJavascriptInterface" in line:
                            js_interfaces.append({
                                "class": sig,
                                "method": line.strip()[:100],
                            })
            except Exception:
                continue
            if len(js_interfaces) >= 20:
                break

    # Dynamic receivers (registerReceiver calls)
    dyn_receivers = []
    for dex in self.dex_units:
        for cls in dex.getClasses():
            sig = cls.getSignature(True)
            if any(sig.startswith(p) for p in _FRAMEWORK_PREFIXES):
                continue
            try:
                decomp = _get_decompiler(self, dex)
                decomp.decompileClass(sig)
                code = decomp.getDecompiledClassText(sig)
                if not code:
                    continue
                code = _to_str(code)
                if "registerReceiver" in code:
                    for line in code.split("\n"):
                        if "registerReceiver" in line:
                            dyn_receivers.append({
                                "class": sig,
                                "caller": line.strip()[:100],
                            })
            except Exception:
                continue
            if len(dyn_receivers) >= 20:
                break

    return {
        "exported_components": exported,
        "deeplinks": deeplinks,
        "js_interfaces": js_interfaces,
        "content_providers": providers,
        "dynamic_receivers": dyn_receivers,
    }


def _handle_security_scan(self, params):
    """Automated security issue detection."""
    import re

    crypto_issues = []
    hardcoded_secrets = []
    dangerous_permissions = []
    insecure_storage = []
    network_issues = []
    webview_issues = []

    # 1. Check dangerous permissions from manifest
    try:
        text = _read_manifest_text(self)
        if text:
            perms = re.findall(r'<uses-permission\s+android:name="([^"]*)"', text)
            for p in perms:
                if p in _DANGEROUS_PERMS:
                    dangerous_permissions.append({
                        "severity": "MEDIUM",
                        "description": "Dangerous permission: %s" % p,
                        "location": "AndroidManifest.xml",
                    })
            # Check debuggable
            if 'android:debuggable="true"' in text:
                insecure_storage.append({
                    "severity": "HIGH",
                    "description": "Application is debuggable",
                    "location": "AndroidManifest.xml",
                })
            # Check allowBackup
            if 'android:allowBackup="true"' in text:
                insecure_storage.append({
                    "severity": "MEDIUM",
                    "description": "allowBackup=true (data can be extracted via adb backup)",
                    "location": "AndroidManifest.xml",
                })
            # Check cleartext traffic
            if 'android:usesCleartextTraffic="true"' in text:
                network_issues.append({
                    "severity": "MEDIUM",
                    "description": "Cleartext traffic allowed",
                    "location": "AndroidManifest.xml",
                })
    except Exception:
        pass

    # 2. Scan decompiled code for crypto/secrets/network issues
    classes_scanned = 0
    max_classes = 200

    for dex in self.dex_units:
        try:
            decomp = _get_decompiler(self, dex)
        except Exception:
            continue
        for cls in dex.getClasses():
            if classes_scanned >= max_classes:
                break
            sig = cls.getSignature(True)
            if any(sig.startswith(p) for p in _FRAMEWORK_PREFIXES):
                continue
            try:
                decomp.decompileClass(sig)
                code = decomp.getDecompiledClassText(sig)
                if not code:
                    continue
                code = _to_str(code)
            except Exception:
                continue
            classes_scanned += 1

            # Crypto issues
            for desc, pattern in _CRYPTO_PATTERNS:
                if pattern in code:
                    crypto_issues.append({
                        "severity": "HIGH" if "DES" in desc or "ECB" in desc else "MEDIUM",
                        "description": desc,
                        "location": sig,
                    })

            # Hardcoded secrets
            for desc, pattern in _SECRET_PATTERNS:
                if re.search(pattern, code, re.IGNORECASE):
                    crypto_match = re.search(pattern, code, re.IGNORECASE)
                    hardcoded_secrets.append({
                        "severity": "HIGH",
                        "description": "%s found" % desc,
                        "location": sig,
                    })

            # Network issues
            if "http://" in code and "https://" not in code:
                network_issues.append({
                    "severity": "MEDIUM",
                    "description": "HTTP (non-HTTPS) URL found",
                    "location": sig,
                })
            if "TrustAllCertificates" in code or "X509TrustManager" in code:
                if "checkServerTrusted" in code:
                    network_issues.append({
                        "severity": "HIGH",
                        "description": "Custom TrustManager (possible cert pinning bypass)",
                        "location": sig,
                    })
            if "SSLContext" in code and "TLS" not in code:
                network_issues.append({
                    "severity": "MEDIUM",
                    "description": "SSLContext without explicit TLS version",
                    "location": sig,
                })

            # WebView issues
            if "setJavaScriptEnabled" in code:
                webview_issues.append({
                    "severity": "MEDIUM",
                    "description": "WebView JavaScript enabled",
                    "location": sig,
                })
            if "addJavascriptInterface" in code:
                webview_issues.append({
                    "severity": "HIGH",
                    "description": "WebView JavaScript interface (potential RCE on API < 17)",
                    "location": sig,
                })

            # Insecure storage
            if "getSharedPreferences" in code and ("password" in code.lower() or "token" in code.lower()):
                insecure_storage.append({
                    "severity": "MEDIUM",
                    "description": "Sensitive data in SharedPreferences",
                    "location": sig,
                })
            if "MODE_WORLD_READABLE" in code or "MODE_WORLD_WRITEABLE" in code:
                insecure_storage.append({
                    "severity": "HIGH",
                    "description": "World-readable/writeable file mode",
                    "location": sig,
                })

        if classes_scanned >= max_classes:
            break

    return {
        "crypto_issues": crypto_issues,
        "hardcoded_secrets": hardcoded_secrets,
        "dangerous_permissions": dangerous_permissions,
        "insecure_storage": insecure_storage,
        "network_issues": network_issues,
        "webview_issues": webview_issues,
        "classes_scanned": classes_scanned,
    }
