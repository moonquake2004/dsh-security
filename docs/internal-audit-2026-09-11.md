# dsh-security 内部审计 — 会话格式漂移导致的检查失效（2026-09-11）

审计人：主 agent（dsh-doctor 会话）
环境：`@deepseek-ai/dsh` **0.1.5-rc.1**，vendored 包 0.1.5-rc.2；`dsh-security` 0.1.7（22 项内置检查 + 4 集成）

## 结论（TL;DR）

**需要更新，且其中 5 项检查目前已失效**——4 项静默失明、1 项 100% 误报。根因是**会话事件形态漂移**：检查是按旧形态写的（`tool/result.data.callId` 扁平字段、工具参数叫 `args`/`input`、结果叫 `output`/`result`/`text`），
而当前 DSH 的真实形态是：

| 事件 | 真实 `data` 字段 | 说明 |
|---|---|---|
| `tool/call` | `turn, step, callId, name, **arguments**` | 参数叫 `arguments`（不是 `args`/`input`） |
| `tool/result` | `turn, step, **message**` | **没有 `callId`**；调用 id 在 `data.message.content[].toolCallId` |

## 逐项判定

| 检查 | 严重级 | 读取的字段 | 真实字段 | 后果 | 证据 |
|---|---|---|---|---|---|
| **SR1** sandbox-violation | CRITICAL | `data.args \|\| data.input` | `data.arguments` | **失明**：规则全是参数字符串（`chroot /`、`mount -o remount rw`、`/etc/passwd`），`args` 恒 `{}` → 永不匹配 | `sr1:58`；实测真实会话中 `args = {}`，`arguments = {"questions":[…]}` |
| **SR2** privilege-escalation | — | `data.args \|\| data.input` | `data.arguments` | **失明**（同上） | `sr2:35` |
| **SR3** data-exfiltration | — | `args/input/output/result/text` | `arguments` / `message` | **失明**：五个字段全不存在 → `text = "{}"` | `sr3:45` |
| **SS3** sensitive-output | LOW | `data.output \|\| data.result \|\| data.text` | `data.message` | **失明**：三个字段全不存在 | `ss3:30` |
| **SS4** session-integrity | HIGH | 配对键 `tool/result.data.callId` | `data.message.content[].toolCallId` | **100% 误报**：`data.callId` 为 `undefined` → 删除分支永不执行 → 所有 tool/call 都算孤儿 | 实测：45 个 tool/call，`data.callId` 命中 **0**，嵌套 `toolCallId` 命中 **45**，**真实孤儿 0**；套件却报「45 个孤儿 tool/call」并 exit 1 |

## 工作正常的检查（对照）

- **解压方式正确**：`src/session-reader.mjs:21` 用 `spawn('zstd', ['-dc', …])` CLI → **解全部帧**，避开了「Node `zlib.zstdDecompressSync` 只解第一帧」的陷阱（该陷阱会让扫描器只看到头部行）
- **SS1 credential-leak / SS2 pii-exposure**：按**原始行文本**扫描（`extractTextFromLine`），不依赖事件字段 → 正常（此前正是 SS1 检出 4 处 OpenAI key）
- SP1–SP10、SL1–SL4、SR4、SS4 之外的检查未发现字段失配；SP8 的报数为真（53 处 plugin×peer / 8 个插件）

## 建议修复（按优先级）

1. **`session-reader.mjs` 增加归一化视图**（一处修、多处受益）：给每个事件暴露
   - `toolName`（`tool/call.data.name`）
   - `toolArgs`（`tool/call.data.arguments`，对象或字符串）
   - `resultText`（`tool/result.data.message` 的文本内容块拼接；兼容旧的 `data.output`/`result`/`text`）
   并让 SR1/SR2/SR3/SS3 只从归一化视图取字段，避免各检查各自猜字段名。
2. **SS4 改配对键**为 `data.message.content[].toolCallId`，并**加入"尾部 in-flight"豁免**（照 dsh-doctor S1 的做法：`seq < maxSeq - 1` 才算真孤儿；当前活跃会话天然有不配对的尾部调用）。
3. **补 fixtures 认证**（照 dsh-doctor 的纪律）：每个检查至少一个好/坏样例，断言"该响的响、不该响的不响"——尤其 SS4 必须有一个"健康会话 → 0 孤儿"的 fixture，否则这类误报不会被拦住。
4. 修复后跑全量测试并复跑真实 profile，确认 SS4 转绿、SR/SS 在**构造的恶意样例**上确实报红（当前它们在任何输入上都报绿，说明没有有效测试覆盖）。

## 未验证

- SR2 / SS3 的规则集未逐条核对（只核了字段提取路径）；影响面按"字段全不存在 → 永不匹配"推断
- 未构造恶意的 `arguments` 样例来端到端验证修复后的检出（修复时应一并做）
- 其他检查（SP/SL 系列）只做了字段名扫描，未逐行审读其内部假设
