# dsh-security 更新方案（草案 v2 — 合并三份调研，待用户定稿）

日期：2026-09-11　当前 0.1.7（22 内置 + 4 集成）
依据：`internal-audit-2026-09-11.md`（我方）、`upstream-compat-audit-2026-09.md`、`threat-survey-2026-09.md`

---

## 零、一句话结论

**运行时安全层目前基本失效**：定位器指向 2 天前的旧世代日志（另一个工作区），且 6 项检查因字段/模型漂移而失明或误报。
**实测净结果：整个套件未检出任何真实安全问题**——唯一"真发现"（SP8）是上游 registry 事实，且其影响模型已过时。

---

## 一、证据总览

### A. 会话定位器失效（**最高优先，其它一切的前提**）
- 实际写入：`session.v3.jsonl.zstd`（`SESSION_FORMAT_VERSION=3`）；本机 **22 个 v3** vs 52 个 v0
- 最新文件按 mtime 全是 v3（今天 22:36）；我方定位器只匹配 `session.jsonl[.zstd]` → **选中 2026-09-09 的旧 v0 日志**
- 后果：**SR1–SR4 + SS1–SS3 全部在分析过期数据**（而且是另一个工作区的）

### B. 字段/模型漂移导致的失效（逐项已实证）

| 检查 | 问题 | 后果 | 证据 |
|---|---|---|---|
| SR1 (CRITICAL) | 读 `data.args\|input`，真实是 `data.arguments`（**JSON 字符串**） | **永久失明** | 45/45 行有 `arguments`；按旧字段扫得 0 命中，按真实文本扫出 3× `sudo chown -R …` |
| SR2 | 同上 | **静默假阴性**（在有 `sudo chown` 的日志上返回 PASS） | 同上 |
| SR3 | 5 个候选字段全不存在 | 失明 | `sr3:45` |
| SS3 | 3 个候选字段全不存在 | 失明 | `ss3:30` |
| SS4 (HIGH) | 配对键 `data.callId`；真实在 `data.message.source.callId` | **100% 误报**（45 孤儿 vs 真实 0） | 45/45 calls 有 callId，0/45 results 有 |
| SR4 | `event.turn` 顶层；真实在 `data.turn` | 潜在假 MEDIUM（整会话塌成 turn 0） | 0/45 行有顶层 turn；本次侥幸通过 |
| SP9 | 前提**反转**：`profiles/node_modules/@deepseek-ai/` 是 dsh 自己写的合法符号链接镜像 | 检查无效（且对 symlink 因 `isDirectory()` 为 false 而看不见） | 240 symlinks / 0 真实目录；healProfilesModuleFallback 写入 |
| SP3 | 真实沙箱配置在 `@deepseek-ai/dsh-base/cordis.patch.yml`（**profile 之外**） | **死代码**：14 个扫描文件里 0 个含 "sandbox-policy" | 且 `str_replace_editor`/`tool-glob` 等旧 id 已不存在 |
| SP1 | `npm audit` 在 pnpm profile 上 `ENOLOCK` 退出 1 | 被当成"无漏洞" → **永久假 PASS** | "扫描 ? 个依赖" |
| SP5 | 门控有效但模型错：真实能力面是 `dsh.client.inject` + `dsh.compatibility.*` + settings 的 `permission.*` | 建模错误 | 无 per-plugin permissions 字段 |
| SP8 | registry 事实为真，但 0.1.5 起 profile 不再从 registry 装 `@deepseek-ai/*`，已装闭包满足所有 peer 范围 | **结论被夸大** | 应降级为 advisory 并按 peer 范围门控 |
| SS2 | 未锚定正则：`127.0.0.1` 当 IPv4、Unix 毫秒时间戳子串当手机号 | **误报** | 抽样逐条核对 |
| SL1/SL4 | "本地 ≠ registry latest" 是不新鲜，不是完整性；且有一条方向反了 | 噪声（应降为信息级） | `dsh-at-file` 本地 0.6.8 > latest 0.6.3 |

### C. 仍然正确的（不要"修好"的东西）
- **`zstd -dc` CLI 解压**（解全部帧；真实 v3 日志 136 帧）——**切勿改用 Node `zlib`**（只解第一帧）
- 三层目录布局、`security.json`、`settings.yaml`、`dsh.bundle` 门控、`client/`+`lib/client.js` 布局、事件类型名本身（`tool/call`/`tool/result`/`permission/preset`/`sandbox/mode`/`approval/policy`）、沙箱模式与审批策略取值

### D. 生态侧（威胁调研）
- **零个确认的在野恶意 DSH 插件**（2026-09-11）；生态自带信任项目亦如此表述
- 真实存在：已复现的**宿主漏洞**、能力普查（非恶意度）、确认的扫描器误报
- 候选新检查（离线可判定）：**SP13** Code Mode×沙箱错配（近零误报）> **SP11** patch 覆盖安全行 > **SP12** `!!js` 标签 > SL5 篡改基线 > SP14 安装期执行面
- 明确不做：tarball-vs-repo diff、SLSA/Rekor、实时逃逸、签名库、远程提示注入

### E. 附带发现的真实环境问题
- `~/.dsh/profiles/node_modules/@deepseek-ai/` 镜像里 **603 个 symlink 中 118 个断裂、95 个指向 `~/.npm/_npx/` 残留**（与之前诊断侧同类腐烂）
- v0→v1 迁移冻结 `permission/preset: disposition(["preset"])`：**10/52 个 v0 日志**含 `origin` 成员 → 整日志不可读（SS4 职责内，当前完全未覆盖）

---

## 二、修复分三批

### P0 — 恢复运行时层（不做这些，后面都是空转）
1. **世代感知的会话定位器**：正则 `^session(?:\.v([1-9][0-9]*))?\.jsonl(\.zstd)?$`，同目录取最高世代、跨目录按 mtime，接受 `_no-cwd`，忽略 `session.lock`
2. **共享 payload 提取器**（一处修、多处受益）：`toolArgs`（`data.arguments`，兼容旧 `args|input`）、`resultText`（`data.message.content[].content[].text`）、`callId`（`data.message.source.callId` 等三处回退）、`turn/step`（`data.*`）
3. **SS4**：配对键三处回退；**仅当 turn 已闭合才报孤儿**；新增"不可迁移 v0 日志"信号
4. **止血误报**：SS2 加数字边界 + 排除回环/私网 + 手机号降级；SL1/SL4 降为信息级；SP8 降 advisory + 按 peer 门控

### P1 — 修复死检查
5. **SP3** 改指 `dsh-base` 的 cordis patch + `settings.yaml` 的 `permission.*`，刷新 id 列表
6. **SP1** 改用 `pnpm audit --json`（或 osv-scanner），无锁文件则**显式 skip**
7. **SP5** 换成 `dsh.bundle` / `dsh.client.inject` / `dsh.compatibility.*` 模型
8. **SP9** 改用 `lstatSync` 判真实重复（真实目录、或指向安装前缀之外的 symlink），并把**118 断裂/95 npx 残留**报为环境问题

### P2 — 新增检查
9. **SP13**（先做，近零误报）→ **SP11** → **SP12**（第三方层 error / 用户 patch warn）→ SL5 / SP14

---

## 三、测试纪律（本次腐烂的真正教训）
- **禁止自造事件形态**：fixture 必须来自真实日志（或用提取脚本从真实日志固化）
- 每个检查**至少一对好/坏样例**，坏样例断言"必须报红"（SR/SS 缺的正是这个）
- **新增元规则：fixture 断言检查实际读取的字段存在**（字段名一漂移，测试立刻红）
- 定位器要有"v0/v3 双世代"用例（本次最大失效点没有任何测试覆盖）

---

## 四、发布安排
- 版本号建议 **0.2.0**（P0+P1 修复 + P2 新增，属 minor）
- 三步流程；可能需同步 dsh-doctor（若共用定位器逻辑）
- 修复后必须**复跑真实 profile** 并给出前后对比（当前基线：exit 1，但 4 个是假、1 个夸大）

---

## 五、需要你定的事

1. **范围**：P0 单独发一版（先止血）再 P1/P2？还是 P0+P1+P2 一次做（0.2.0）？
2. **真实样本入库**：脱敏真实会话样本提交进仓库（可复现，但有隐私考量），还是只留提取脚本？
3. **SP9 的 118 断裂 symlink**：只报为环境警告，还是同时给修复建议（清理 npx 残留）？
4. **是否顺带对齐 dsh-doctor**：SS4 与 S1 同类逻辑，是否把"会话定位器 + 字段提取"抽成共享模块（两个仓库都要用）？
5. **生态工具清单报告尚未回来**——是否等它（影响 P2 的集成候选）再定稿？
