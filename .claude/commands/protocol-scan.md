---
description: Analyze network protocol implementation in a binary or APK
---

Analyze network protocol in: $ARGUMENTS

Steps:
1. Detect engine, start, wait
2. If user specified `-R` or remote mode, prefix all revkit commands with `-R`

For IDA (binary):
- `revkit {-R} ida find-func --regex "send|recv|parse|decode|encode|handle|dispatch"` → protocol functions
- `revkit {-R} ida callgraph {parser_func} --depth 5` → protocol processing flow
- `revkit {-R} ida decompile {parser_func}` → message structure inference
- `revkit {-R} ida strings-xrefs` → protocol keywords (HTTP, GET, POST, Content-Length)
- `revkit {-R} ida search-const` → magic numbers (protocol headers)
- `revkit {-R} ida data-refs` → global tables (command dispatch, handler arrays)

For JEB (APK):
- `revkit {-R} jeb search-code "HttpURLConnection|OkHttp|Retrofit"` → HTTP clients
- `revkit {-R} jeb search-code "JSONObject|Gson|parseJSON"` → request/response structure
- `revkit {-R} jeb search-code "encrypt|decrypt"` → encryption layer
- `revkit {-R} jeb strings --regex "http|https|ws://"` → API endpoints
- `revkit {-R} jeb search-code "WebSocket|Socket"` → real-time communication

3. Map protocol flow: input → parse → process → respond
4. Identify: endpoints, message format, authentication, encryption
5. Generate protocol analysis report
6. Stop: `revkit {-R} {engine} stop`
