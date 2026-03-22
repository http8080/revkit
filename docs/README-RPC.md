# revkit RPC Protocol Reference

JSON-RPC interface reference for IDA and JEB headless analysis servers.

IDA/JEB headless 분석 서버의 JSON-RPC 인터페이스 레퍼런스.

---

## Overview / 개요

| Property / 속성 | IDA | JEB |
| --- | --- | --- |
| Protocol | JSON-RPC 2.0 | JSON-RPC 2.0 |
| Endpoint | `POST /rpc` | `POST /jsonrpc` |
| Auth | `Authorization: Bearer {token}` | Same |
| Token file | `~/.revkit/auth_tokens.json` | Same |
| Token format | `{IID}:{PORT}:{TOKEN}` (line-based) | Same |
| Server runtime | Python 3.10+ (`http.server`) | Jython 2.7 (`com.sun.net.httpserver`) |
| Address format | Integer hex (`0x401000`) | DEX signature (`Lcom/example/Foo;`) |
| Methods | 55 | 60 |

### Request Format / 요청 형식

```json
{
  "jsonrpc": "2.0",
  "method": "decompile",
  "params": {"addr": "0x140010108"},
  "id": 1
}
```

### Response Format / 응답 형식

Success / 성공:
```json
{"result": {"addr": "0x140010108", "code": "void func() {...}"}, "id": 1}
```

Error / 에러:
```json
{"error": {"code": "NOT_FOUND", "message": "No function at 0xDEAD", "suggestion": "..."}, "id": 1}
```

### Authentication / 인증

```bash
# Token is stored on server start / 서버 시작 시 토큰 저장
cat ~/.revkit/auth_tokens.json
# Format: {IID}:{PORT}:{TOKEN}
# Example: a3k2:34241:gnLy7XwcK7...

# Extract token for an instance / 인스턴스 토큰 추출
TOKEN=$(grep "a3k2" ~/.revkit/auth_tokens.json | cut -d: -f3)
```

---

## IDA RPC Methods (59) / IDA RPC 메서드

### System / 시스템

| Method | Params | Response | Description |
| --- | --- | --- | --- |
| `ping` | `{}` | `{ok, state}` | Server health check / 상태 확인 |
| `status` | `{}` | `{func_count, ida_version, uptime, ...}` | Instance status / 인스턴스 상태 |
| `methods` | `{}` | `{methods: [{name, description}]}` | List available methods / 사용 가능 메서드 |
| `stop` | `{}` | `{ok}` | Shutdown (save DB first) / 종료 |
| `save_db` | `{}` | `{ok}` | Save IDB / IDB 저장 |

### Listing / 목록

| Method | Params | Response | Description |
| --- | --- | --- | --- |
| `get_functions` | `{count?, offset?}` | `{total, offset, count, data}` | Function list / 함수 목록 |
| `get_strings` | `{count?, offset?}` | `{total, offset, count, data}` | String list / 문자열 목록 |
| `get_imports` | `{count?, offset?}` | `{total, offset, count, data}` | Import list / Import 목록 |
| `get_exports` | `{count?, offset?}` | `{total, offset, count, data}` | Export list / Export 목록 |
| `get_segments` | `{}` | `{total, offset, count, data}` | Segments / 세그먼트 |
| `summary` | `{}` | `{func_count, total_strings, ...}` | Binary summary / 요약 |

### Analysis / 분석

Decompilation, disassembly, function info, byte-level access, pattern search.

디컴파일, 디스어셈블리, 함수 정보, 바이트 접근, 패턴 검색.

| Method | Params | Response |
| --- | --- | --- |
| `decompile` | `{addr}` | `{addr, code}` |
| `decompile_with_xrefs` | `{addr}` | `{code, callers, callees}` |
| `decompile_batch` | `{addrs: [...]}` | `{total, success, functions}` |
| `decompile_all` | `{filter, output}` | `{total, success, ...}` |
| `decompile_diff` | `{addr}` | `{code}` |
| `disasm` | `{addr, count}` | `{addr, count, lines: [{addr, bytes, insn}]}` |
| `get_func_info` | `{addr}` | `{name, size, start_addr, end_addr}` |
| `get_imagebase` | `{}` | `{imagebase}` |
| `get_bytes` | `{addr, size}` | `{addr, size, hex, raw_b64}` |
| `find_func` | `{name}` | `{query, total, matches}` |
| `find_bytes` | `{pattern}` | `{matches}` |
| `stack_frame` | `{addr}` | `{addr, name, frame_size, members}` |
| `switch_table` | `{addr}` | `{switch_count, switches}` |

### Modification / 수정

Rename, type setting, commenting, patching, exec, search.

리네임, 타입 설정, 코멘트, 패치, 코드 실행, 검색.

| Method | Params | Response |
| --- | --- | --- |
| `set_name` | `{addr, name}` | `{ok, old_name, new_name}` |
| `set_type` | `{addr, type}` | `{ok}` |
| `set_comment` | `{addr, comment}` | `{ok}` |
| `get_comments` | `{addr}` | `{addr, comment, repeatable_comment}` |
| `patch_bytes` | `{addr, bytes}` | `{ok, old_bytes}` |
| `rename_batch` | `{entries: [{addr, name}]}` | `{success, failed}` |
| `exec` | `{code}` | `{stdout, stderr}` |
| `search_const` | `{value}` | `{matches}` |
| `search_code` | `{query, max_funcs?}` | `[{func_name, matching_line}]` |
| `auto_rename` | `{dry_run?, max_funcs?}` | `{suggestions, applied}` |
| `export_script` | `{}` | `{script}` |

### Types / 타입

Struct, enum, type info, vtable, signature management.

구조체, 열거형, 타입 정보, vtable, 시그니처 관리.

| Method | Params | Response |
| --- | --- | --- |
| `list_structs` | `{}` | `[{name, size, members}]` |
| `get_struct` | `{name}` | `{name, size, members}` |
| `create_struct` | `{name, members}` | `{ok}` |
| `list_enums` | `{}` | `[{name, members}]` |
| `get_enum` | `{name}` | `{name, members}` |
| `create_enum` | `{name, members}` | `{ok}` |
| `list_types` | `{count?}` | `[{name, size}]` |
| `get_type` | `{name}` | `{name, size, declaration}` |
| `detect_vtables` | `{}` | `[{addr, entries}]` |
| `list_sigs` | `{}` | `{signatures}` |
| `apply_sig` | `{name}` | `{applied}` |

### Graph / 그래프

Cross-references, call graph, basic blocks, similarity, data references.

교차 참조, 콜그래프, 기본 블록, 유사도, 데이터 참조.

| Method | Params | Response |
| --- | --- | --- |
| `get_xrefs_to` | `{addr}` | `{refs}` |
| `get_xrefs_from` | `{addr}` | `{refs}` |
| `callgraph` | `{addr, depth?, direction?}` | `{nodes, edges}` |
| `cross_refs` | `{addr, depth?}` | `{nodes, edges}` |
| `basic_blocks` | `{addr}` | `{blocks, edges}` |
| `func_similarity` | `{addr_a, addr_b}` | `{score, ...}` |
| `data_refs` | `{addr?}` | `{refs}` |
| `strings_xrefs` | `{max_results?}` | `[{string, refs}]` |

### Annotations + Snapshot / 어노테이션 + 스냅샷

| Method | Params | Response |
| --- | --- | --- |
| `export_annotations` | `{}` | `{names, comments, types}` |
| `import_annotations` | `{data: {names, comments, types}}` | `{ok}` |
| `snapshot_save` | `{description}` | `{filename}` |
| `snapshot_list` | `{}` | `{snapshots}` |
| `snapshot_restore` | `{filename}` | `{ok}` |

---

## JEB RPC Methods (57) / JEB RPC 메서드

### System / 시스템

| Method | Params | Response |
| --- | --- | --- |
| `ping` | `{}` | `{ok, state}` |
| `status` | `{}` | `{class_count, method_count, jeb_version, ...}` |
| `methods` | `{}` | `{methods: [{name, description}]}` |
| `stop` | `{}` | `{ok}` |
| `save` | `{}` | `{ok}` |

### Listing / 목록

| Method | Params | Response |
| --- | --- | --- |
| `get_classes` | `{filter?}` | `{total, data}` |
| `get_methods_of_class` | `{class_sig}` | `[{name, signature, access}]` |
| `get_fields_of_class` | `{class_sig}` | `[{name, type, access}]` |
| `get_method_info` | `{method_sig}` | `{signature, access, return_type}` |
| `get_imports` | `{}` | `[...]` |
| `get_exports` | `{}` | `[...]` |
| `get_strings` | `{min_len?, regex?, count?}` | `{total, data}` |
| `native_methods` | `{}` | `[{class, method, library}]` |
| `get_resources_list` | `{}` | `{total, data: [{path, type, size}]}` |
| `get_resource` | `{path}` | `{path, size, content_b64}` |

### Analysis / 분석

| Method | Params | Response |
| --- | --- | --- |
| `decompile` / `get_class_source` | `{class_sig}` | `{code}` |
| `decompile_with_xrefs` | `{class_sig}` | `{code, callers, callees}` |
| `decompile_batch` | `{class_sigs: [...]}` | `{total, success, functions}` |
| `decompile_all` | `{filter, output}` | `{total, success}` |
| `get_method_by_name` | `{method_sig}` | `{code}` |
| `get_smali` | `{class_sig}` | `{smali}` |
| `get_manifest` | `{}` | `{content}` |
| `info` | `{}` | `{package, main_activity, ...}` |
| `summary` | `{}` | `{class_count, method_count, ...}` |
| `get_main_activity` | `{}` | `{activity}` |
| `get_app_classes` | `{}` | `[...]` |

### Search / 검색

| Method | Params | Response |
| --- | --- | --- |
| `search_classes` | `{keyword}` | `{matches}` |
| `search_methods` | `{name}` | `{matches}` |
| `search_code` | `{query}` | `[{class, matching_line}]` |

### Graph / 그래프

| Method | Params | Response |
| --- | --- | --- |
| `get_xrefs` | `{sig, direction}` | `{refs}` |
| `callgraph` | `{sig, depth?}` | `{nodes, edges}` |
| `cross_refs` | `{sig, depth?}` | `{refs}` |
| `strings_xrefs` | `{filter?}` | `[{string, refs}]` |

### Modification / 수정

| Method | Params | Response |
| --- | --- | --- |
| `rename` | `{sig, new_name}` | `{ok, old_name, new_name}` |
| `rename_class` | `{class_sig, new_name}` | `{ok, new_name}` |
| `rename_method` | `{method_sig, new_name}` | `{ok, new_name}` |
| `rename_field` | `{field_sig, new_name}` | `{ok, new_name}` |
| `rename_batch` | `{entries: [{sig, new_name}]}` | `{success, failed}` |
| `set_comment` | `{addr, comment}` | `{ok}` |
| `get_comments` | `{addr}` | `{comment}` |
| `auto_rename` | `{dry_run?}` | `{suggestions, applied}` |
| `exec` | `{code}` | `{stdout, stderr}` |
| `undo` | `{}` | `{ok}` |

### Annotations + Snapshot / 어노테이션 + 스냅샷

| Method | Params | Response |
| --- | --- | --- |
| `export_annotations` | `{}` | `{names, comments}` |
| `import_annotations` | `{data}` | `{names, comments}` |
| `snapshot_save` | `{description}` | `{filename}` |
| `snapshot_list` | `{}` | `{snapshots}` |
| `snapshot_restore` | `{filename}` | `{ok}` |

### Security / 보안

| Method | Params | Response |
| --- | --- | --- |
| `entry_points` | `{}` | `{components}` |
| `security_scan` | `{}` | `{findings}` |

---

## Parameter Aliases (JEB) / 파라미터 Alias

JEB server maps common parameter names to internal handler names via `_PARAM_ALIASES`.

JEB 서버는 `_PARAM_ALIASES`로 여러 이름을 동일 파라미터에 매핑합니다.

| Caller uses / 호출 시 | Handler expects / 핸들러 기대 | Applies to / 적용 대상 |
| --- | --- | --- |
| `class` | `class_sig` | decompile, get_smali, get_methods_of_class |
| `target` | `item_sig`, `class_sig` | get_xrefs, callgraph, cross_refs |
| `method` | `method_sig` | rename_method, get_method_info |
| `field` | `field_sig` | rename_field |
| `sig` | `class_sig`, `method_sig`, `field_sig`, `item_sig` | Universal / 범용 |
| `renames` | `entries` | rename_batch |
| `classes` | `class_sigs` | decompile_batch |

---

## Error Codes / 에러 코드

| Code | IDA | JEB | Description / 설명 |
| --- | --- | --- | --- |
| `UNKNOWN_METHOD` | ✓ | ✓ | Unregistered RPC method / 미등록 메서드 |
| `MISSING_PARAM` | - | ✓ | Required parameter missing / 필수 파라미터 누락 |
| `INVALID_PARAMS` | ✓ | - | Invalid parameter value / 파라미터 값 오류 |
| `NOT_FOUND` | ✓ | ✓ | Target not found / 대상 없음 |
| `EXEC_DISABLED` | ✓ | ✓ | `security.exec_enabled=false` |
| `AUTH_FAILED` | ✓ | ✓ | Invalid or missing token / 인증 실패 |
| `INTERNAL` | ✓ | ✓ | Server internal error / 내부 에러 |
| `JAVA_ERROR` | - | ✓ | Java/Jython exception (JEB only) |
| `NO_SWITCH` | ✓ | - | No switch table found |
| `PATCH_DISABLED` | ✓ | - | Patching requires exec_enabled |

---

## Pagination (IDA) / 페이지네이션

IDA listing methods support pagination. JEB currently returns all data.

IDA 목록 메서드는 페이지네이션을 지원합니다. JEB는 현재 전체 데이터를 반환합니다.

```
Request:  {"count": 50, "offset": 0}
Response: {"total": 500, "offset": 0, "count": 50, "data": [...50 items...]}
```

---

## Examples / 예시

### IDA: Decompile a function

```bash
PORT=34241
TOKEN=$(grep "instance_id" ~/.revkit/auth_tokens.json | cut -d: -f3)

curl -s -X POST http://127.0.0.1:$PORT/rpc \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"decompile","params":{"addr":"0x140010108"},"id":1}'
```

### JEB: Decompile a class

```bash
curl -s -X POST http://127.0.0.1:$PORT/jsonrpc \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"decompile","params":{"class_sig":"Lsg/vantagepoint/uncrackable3/MainActivity;"},"id":1}'
```

### JEB: Using parameter aliases

```bash
# Both work — "class" is aliased to "class_sig"
# 둘 다 동작 — "class"는 "class_sig"로 매핑됨
-d '{"jsonrpc":"2.0","method":"decompile","params":{"class":"Lcom/Foo;"},"id":1}'
-d '{"jsonrpc":"2.0","method":"decompile","params":{"class_sig":"Lcom/Foo;"},"id":1}'
```

---

## JEB Server Constraints (Jython 2.7) / JEB 서버 제약

- Empty `{}` params may fail on older server versions — use `{"_":"1"}` as workaround
- `exec` code must be Python 2 syntax (`print "hello"` not `print("hello")` — though parentheses work)
- Bare `except:` in server code is intentional (catches Java `Throwable`)
- f-strings, type hints, walrus operator, `match/case` — all forbidden in server code

- 빈 `{}` 파라미터는 구 서버에서 실패할 수 있음 — `{"_":"1"}`을 대안으로 사용
- `exec` 코드는 Python 2 문법 필수 (`print "hello"` — 괄호도 동작하지만 Python 2 기준)
- 서버 코드의 bare `except:`는 의도적 (Java `Throwable` 포착용)
- f-string, type hint, walrus 연산자, `match/case` — 서버 코드에서 전부 사용 금지
