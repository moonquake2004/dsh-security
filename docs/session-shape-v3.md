# DSH 会话事件形态规范（v3，2026-09-11 实测）

来源：直接解压 `~/.dsh/sessions/*/*/session.v3.jsonl.zstd`（多帧 zstd，用 `zstd -dc` 全帧解压）逐行解析得到。
用途：dsh-security 的 SR/SS 检查 与 dsh-doctor 的 S 检查**共用**此规范，避免各自猜字段导致漂移。

## 1. 文件命名与世代

| 世代 | 文件名 | 说明 |
|---|---|---|
| v0（旧） | `session.jsonl` / `session.jsonl.zstd` | 本机 52 个 |
| v3（当前） | `session.v3.jsonl.zstd` | 本机 22 个，**当前写入目标** |

- `SESSION_FORMAT_VERSION = 3`
- **定位器必须同时认两种世代，并取最新**：
  正则 `^session(?:\.v([1-9][0-9]*))?\.jsonl(\.zstd)?$`
  同目录 → 取**最高世代**；跨目录 → 按 `mtime` 取最新；忽略 `session.lock`；接受 `_no-cwd` 目录名。
- 目录布局：`~/.dsh/sessions/<project>/<session-id>/session*.jsonl*`（三层）

## 2. `tool/call`

```json
{"type":"tool/call","seq":19,"time":1786756102077,
 "data":{"turn":1,"step":1,"callId":"call_00_zXPGiohcszrmhgXzAd0I9896",
         "name":"bash",
         "arguments":"{\"command\": \"pwd && ls -la\", \"description\": \"…\"}"}}
```

| 需要的值 | 取值路径 | 注意 |
|---|---|---|
| 工具名 | `data.name` | — |
| 工具参数 | `data.arguments` | **JSON 字符串**，需 `JSON.parse`；旧世代为 `data.args` / `data.input`（对象） |
| callId | `data.callId` | — |
| turn / step | `data.turn` / `data.step` | **不在顶层**（旧代码读 `event.turn` → 恒 undefined） |

## 3. `tool/result`

```json
{"type":"tool/result","seq":20,"time":1786756102116,
 "data":{"turn":1,"step":1,
   "message":{"source":{"kind":"tool","callId":"call_00_…"},
              "content":[{"type":"tool-result","toolCallId":"call_00_…",
                          "content":[{"type":"text","text":"/Users/waterfly/收藏\n…"}]}]}}}
```

| 需要的值 | 取值路径（按优先级） | 注意 |
|---|---|---|
| callId | `data.message.source.callId` → `data.message.content[].toolCallId` → `data.callId`（旧） | `data.callId` 在 v3 **不存在**（0/45 命中） |
| 结果文本 | `data.message.content[].content[].text` → `data.message.content[].text` → `data.output`/`data.result`/`data.text`（旧） | **嵌套两层**，旧代码只找扁平的 `output`/`result`/`text` |
| turn / step | `data.turn` / `data.step` | — |

## 4. 共用提取器（两仓行为必须一致）

```
extractEvent(event) → {
  kind: 'call' | 'result' | 'other',
  name,            // 工具名（call 有）
  argsText,        // 参数字符串（JSON.parse 后 JSON.stringify，保证文本可扫）
  callId,
  resultText,      // 结果文本
  turn, step,
}
```

**判定孤儿时**：仅在 **turn 已闭合** 时才报"真孤儿"；活跃会话尾部天然有不配对的调用（in-flight），必须豁免。

## 5. 回归纪律（本次腐烂的根因）

- **禁止自造事件形态**：fixture 必须来自本规范（或真实日志提取）。安全套件此前用 `data:{name,args:{…}}` 自造，故 99/99 全绿却对真实数据失明。
- **元规则**：fixture 必须被断言"检查实际读取的字段存在"，字段名一漂移测试立刻红。
- 定位器必须同时有 **v0 与 v3** 用例。
