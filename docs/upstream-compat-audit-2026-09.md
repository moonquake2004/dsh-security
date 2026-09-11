# Upstream compatibility audit — dsh-security 0.1.7 vs installed `@deepseek-ai/dsh` 0.1.5-rc.1

- **Date:** 2026-09-11
- **Subject:** `@moonquake2004/dsh-security` v0.1.7 at `/Users/waterfly/dsh工作区/dsh-security`
- **Target:** installed harness `/opt/homebrew/lib/node_modules/@deepseek-ai/dsh` = **`0.1.5-rc.1`**, vendored packages = **`0.1.5-rc.2`** (e.g. `dsh-session`, `dsh-session-format*`, `dsh-session-persistence-jsonl`, `dsh-sandbox-policy`, `dsh-permission-presets`)
- **Method:** read-only source inspection of the installed tree and `~/.dsh`; no GitHub action; no writes under `/opt/homebrew`; no changes to `src/**`, `test/**`, `package.json`, or READMEs. The only file written is this report.
- **Baseline run loaded an installed copy of our own code:** `~/.dsh/profiles/web/node_modules/@moonquake2004/dsh-security` — `diff -rq` against the workspace `src/` is **clean**, so the baseline faithfully reflects the checks audited here.

---

## 1. Summary

0.1.5 changed three things that matter to our checks, and they are independent of each other:

1. **The session log became a versioned lineage of files.** Current writes go to `session.v3.jsonl.zstd` (`SESSION_FORMAT_VERSION = 3`), not `session.jsonl.zstd`. Our locator (in `dsh-doctor`) only matches `session.jsonl[.zstd]`, so **the entire SR/SS layer now analyses a stale, two-day-old log from a different workspace.** This is the same class of rot as the diagnostics-side locator.
2. **The `tool/call` / `tool/result` payload schema changed.** Arguments moved to `data.arguments` (a JSON string) and results to `data.message.content[]…`; `turn` moved under `data`. SR1/SR2/SR3/SR4/SS3/SS4 still read the old keys, so three checks are permanently blind and one produces a **false HIGH on every run**.
3. **`@deepseek-ai/*` packages now legitimately appear in profile-level `node_modules` as dsh-owned symlinks** written by the module-fallback mechanism. SP9's premise is inverted; SP3's target ids and patch-file set no longer cover where the sandbox is actually configured.

**Baseline: exit code 1 — 0 critical / 2 high / 3 medium / 0 low / 0 info / 0 skipped. Five FAILs: 1 true finding (SP8, upstream), 4 stale-check artifacts (SS4, SS2, SL1, SL4).**

The single highest-value fix is the **session-log locator + payload-key reader**, because it is the only one that currently produces a **false HIGH** (SS4) while simultaneously making a **CRITICAL-severity check silently blind** (SR1).

---

## 2. Dependency table

Status legend: **valid** = dependency still holds in 0.1.5-rc.1; **moved** = same concept, different path/key/name; **gone** = no longer exists; **broken** = the dependency no longer matches and the check misbehaves.

### 2.1 `src/session-reader.mjs` / `src/config.mjs`

| id | Dependency | Status | Evidence |
|---|---|---|---|
| D1 | Session log basenames `session.jsonl` / `session.jsonl.zstd` | **moved** | `dsh-session-format/lib/index.js:474` → `generation === 0 ? "session.jsonl" : \`session.v${generation}.jsonl\``. `SESSION_FORMAT_VERSION = 3` (`dsh-session/lib/index.js:56`), so the append target is `session.v3.jsonl` (+`.zstd`). |
| D2 | Session dir layout `~/.dsh/sessions/<user>/<session>/` | **valid** | `dsh-session-persistence-jsonl/lib/index.js:913-926` → `root/<projectKey(cwd)>/<encodeSegment(id)>/<generationLogFilename>`. Matches observed `~/.dsh/sessions/--Users-waterfly-~6536~85CF--/<id>/…`. |
| D3 | `zstd` CLI on `PATH`, invoked as `zstd -dc` | **valid (and the correct choice)** | `/opt/homebrew/bin/zstd` v1.5.7. Real v3 log = **136 concatenated zstd frames**; `zstd -dc` decodes all 136. `require('node:zlib').zstdDecompressSync` on the same bytes returns **only frame 1** (verified). `dsh-session-persistence-jsonl` writes one frame per batch (`compressZstdFrame`, `lib/index.js:3028`), so multi-frame is the norm. **Our subprocess reader is safe on this axis — do not "improve" it to `zstdDecompressSync`.** |
| D4 | One event per JSONL line, `event.data` envelope | **valid** | Every decoded line of both a v0 and a v3 log is independently `JSON.parse`-able. v3 line 1 is a header row `{"type":"session","version":3,…}` with no `data`. |
| D5 | `~/.dsh/security.json` | **valid (ours)** | Our own convention. `dsh-settings` namespaces are unrelated; no harness file reads `security.json`. File absent on this host → all checks enabled in the baseline. |

### 2.2 Static layer SP1–SP10

| id | Dependency | Status | Evidence |
|---|---|---|---|
| SP1 | `<profile>/package.json`; `npm audit --json --omit=dev`; npm v6 `advisories` / v7 `vulnerabilities` JSON | **broken (no-op)** | Profile is pnpm-managed, has **no `package-lock.json`**. `npm audit` exits 1 with `{"error":{"code":"ENOLOCK"…}}`; `runNpmAudit` parses that as "no vulns" → `PASS "依赖链无已知漏洞（扫描 ? 个依赖）"`. The `?` is `metadata.totalDependencies` being absent. |
| SP2 | Recursive scan of profile root for secrets; `cordis.patch.yml`, `package.json`; `node_modules` excluded; `!!js process.env` = safe | **valid** | `cordis.patch.yml` and `package.json` still exist with those names; `!!js` expressions are still the YAML escape hatch (`dsh-base/cordis.patch.yml:212`). |
| SP3 | `<profile>/cordis.patch.yml` + `<profile>/node_modules/**/cordis.patch.yml`; entry `- id:` YAML; ids `tool-fs`, `str_replace_editor`, `tool-fs-write`, `tool-fs-search`, `tool-glob`, `tool-grep`; keys `sandbox`/`sandbox-backend`/`fs`; `sandbox-policy` with `mode:` | **gone / broken (inert)** | `cordis.patch.yml` still valid, but: (a) the real sandbox wiring lives in **`@deepseek-ai/dsh-base/cordis.patch.yml`** (`id: sandbox-policy`, `id: sandbox`, `id: permission`) **outside the profile** — the profile is `~/.dsh/profiles/web`, and `web/node_modules/@deepseek-ai/` is empty; (b) none of the 14 profile-scanned patch files contain the string `sandbox-policy`, so `checkSandboxPolicy()` never fires; (c) `str_replace_editor` is now a *tool name*, not a loader entry id, and `tool-glob`/`tool-grep` no longer exist (folded into `tool-fs-search`). SP3 reports "14 patch files, consistent" while measuring nothing. |
| SP4 | Same patch-file discovery; regexes on patch content | **valid but low-yield** | 0.1.5 patch files now carry `!!js` expressions with `process.getBuiltinModule(...)`, `process.platform`, `ctx.loader.entries()` — none currently trip the `eval(`/`Function(`/`child_process`/`fetch(` patterns, so no false positive today. Discovery set is unchanged (14 files). |
| SP5 | `<pkg>/package.json` truthy `dsh.bundle`; `<pkg>/cordis.patch.yml` content heuristics | **gate valid, model wrong** | `dsh.bundle` is real: `{"bundle":{"patch":"./cordis.patch.yml"}}` (verified on `dsh-persist`, `dsh-better-sidebar`, `dshmarket`, `@xmanrui/dsh-im`, `@moonquake2004/dsh-doctor`). But the real 0.1.5 capability surface is elsewhere — see §4. |
| SP6 | `<profile>/package.json` `dependencies`; name filter `dsh\|deepseek`; OSV API | **valid** | 15 matching deps; baseline queried 10/15 successfully. |
| SP7 | `node_modules` scan gated on `pkg.dsh`; client artifacts `client/*.js`, `lib/client.js`, `client.js`; `node --check` | **valid** | Both layouts still in use in the live profile: `client/` (`@moonquake2004/dsh-doctor`, `dshmarket`) and `lib/client.js` (8 packages). Baseline: 16 plugin pkgs / 11 artifacts, all parse. |
| SP8 | `pkg.dsh` gate; `peerDependencies['@deepseek-ai/dsh-*']`; registry `dist-tags.latest`; broken shape `/^0\.0\.1-rc\./` | **valid fact, obsolete model** | Premise still literally true: `@deepseek-ai/dsh-session`, `-tools`, `-sandbox`, `-base`, `-web-app` all have `latest=0.0.1-rc.1`, `next=0.1.5-rc.2`. But in 0.1.5 profiles no longer install `@deepseek-ai/*` from the registry at all — see §3.3. |
| SP9 | `profileDir/node_modules/@deepseek-ai/dsh-*`; `CORE_RUNTIME_PKGS = {dsh-tools, dsh-agent-loop, dsh-sandbox-local, dsh-subprocess-local}`; `entry.isDirectory()` | **broken (both directions)** | Package names still exist and are still core. But `~/.dsh/profiles/node_modules/@deepseek-ai/` holds **240 dsh-owned symlinks** (including all four "core" names, pointing at the CLI's own vendored copies) written by `healProfilesModuleFallback` (`dsh-app-boot/lib/index.js:660-690`). `readdirSync(..., {withFileTypes:true}).isDirectory()` is **false for symlinks**, so SP9 cannot see them → vacuous PASS on both `~/.dsh/profiles/web` (empty real dir) and `~/.dsh/profiles` (240 symlinks). Verified by direct invocation. |
| SP10 | `pkg.dsh` gate; recursive source collection | **valid** | 16 plugins / 891 files scanned in baseline. |

### 2.3 Runtime / session layer SR1–SR4, SS1–SS3

| id | Dependency | Status | Evidence |
|---|---|---|---|
| SR1/SR2/SR3 | `event.type === 'tool/call'` | **valid** | `tool/call` is in `KNOWN_SESSION_EVENT_TYPES` (`dsh-session/lib/index.js:103-107`) and in the v0 frozen inventory. Present in both a v0 and a v3 log. |
| SR3 | `event.type === 'tool/result'` | **valid** | Same. |
| SR1/SR2/SR3/SR4 | Tool name at `data.name \|\| data.tool` | **valid** | v0 and v3 both carry `data.name`. |
| SR1/SR2/SR3 | **Argument text at `data.args \|\| data.input`** | **BROKEN** | The payload key is **`data.arguments`** (a JSON *string*), in both v0 and v3. All 45 `tool/call` rows of the scanned v0 log carry `data.arguments`; the checks read `JSON.stringify({}) === "{}"`. |
| SS3, SR3 | Tool output at `data.output \|\| data.result \|\| data.text` | **BROKEN** | v3/v0 `tool/result.data` = `{turn, step, message:{source:{kind,callId}, content:[{type:"tool-result", content:[{type:"text", text:…}]}]}}`. None of the three keys exist at `data` level. |
| SR1/SR2/SR3/SR4 | `event.turn` (top level) | **BROKEN** | `turn` lives at `data.turn`. Measured **0 / 45** rows have a top-level `turn`. SR4 therefore collapses every call of the whole session into `turn = 0`. |
| SR1/SR2/SR3 | `event.seq` (top level) | **valid** | `seq` is top-level in both generations. |
| SS4 | Pairing key `data.callId` on both `tool/call` and `tool/result` | **BROKEN** | `tool/call.data.callId` exists; `tool/result` carries it at **`data.message.source.callId`** (and again at `data.message.content[0].toolCallId`). Result: `data.callId` is present on **45 / 45** calls and **0 / 45** results → 45 phantom orphans. |
| SS1/SS2 | Whole-line recursive text extraction from `event.data \|\| event` | **valid** | Generation-agnostic; correctly found content in both a v0 and a v3 log. |
| SS4 | `statSync(file).size === 0` as "empty log" | **valid but weak** | A zstd container is never 0 bytes; the `< 10` line rule still works after decompression. |

### 2.4 Lifecycle layer SL1–SL4

| id | Dependency | Status | Evidence |
|---|---|---|---|
| SL1/SL4 | `<profile>/package.json` `dependencies`, name filter `dsh\|deepseek\|cordis` | **valid** | Matches 15 entries. |
| SL1 | `pnpm-lock.yaml` key shape `  'name@version':` + `integrity:` within 500 bytes | **valid (unexercised)** | Lock exists at `~/.dsh/profiles/web/pnpm-lock.yaml`. No integrity mismatch was found or expected (see §3.2 for why the check still FAILs). |
| SL1 | `registryInfo['dist-tags'].latest` compared to local version | **valid** | This is what produced all 5 baseline issues. |
| SL3/SL4 | Registry `maintainers`, `time[latest]`, `dist-tags.next` | **valid** | Used as-is. |
| SL2 | `parseVersion()` on dependency specs | **valid but degenerate** | 4 of 17 specs are non-semver (`file:`, `github:`, `https://…tar.gz`); they degrade to `{0,0,0}` and never fire. Harmless. |

### 2.5 Integrations

| id | Dependency | Status | Evidence |
|---|---|---|---|
| EXT-ECO-1 | GitHub API `zoahdev/dsh-ecosystem` `docs/`, `docs/release-compat/`, `weekly-*.md`, `release-compat-*.md` | **valid** | Ran successfully in the baseline (`PASS`). |
| EXT-PG-1 / EXT-SA-1 / EXT-RED-1 | `which dsh-poison-guard` / `dsh-sandbox-audit` / `dsh-plugin-reducer` | **valid (not installed)** | Absent from `PATH`, so not registered; they did not report in the baseline. |

---

## 3. Baseline run

### 3.1 Raw result

```
cd /Users/waterfly/dsh工作区/dsh-doctor
./dsh-doctor.sh --security --security-only --profile web --json
```

| | |
|---|---|
| **Exit code** | **1** (`[exit code: 1]` from the wrapper; `security.exitCode = 1`) |
| **`ok`** | `false` |
| **Severity counts** | `critical: 0`, `high: 2`, `medium: 3`, `low: 0`, `info: 0`, `skipped: 0` |
| **Checks recorded** | 23 security rows (22 built-in + `EXT-ECO-1`) |
| **resolveProfile('web')** | `/Users/waterfly/.dsh/profiles/web` |
| **Session file actually read** | `/Users/waterfly/.dsh/sessions/--Users-waterfly-~6536~85CF--/session-95cc28de-770e-4b5f-b1c9-006525e78de3/session.jsonl.zstd` (v0, **1146 lines, mtime 2026-09-09T07:41Z**) |

Full check status:

```
SP1 PASS   SP2 PASS   SP3 PASS   SP4 PASS   SP5 PASS   SP6 PASS
SR1 PASS   SR2 PASS   SR3 PASS   SR4 PASS
SL1 FAIL   SL2 PASS   SL3 PASS   SL4 FAIL
SS1 PASS   SS2 FAIL   SS3 PASS   SS4 FAIL
SP7 PASS   SP8 FAIL   SP9 PASS   SP10 PASS   EXT-ECO-1 PASS
```

**Session-locator fact (measured, not inferred):** running the doctor's `findLatestSession` logic verbatim over `~/.dsh/sessions` yields **52 candidates**, all `session.jsonl[.zstd]`, newest **2026-09-09T07:41:30Z**. The newest real session log on disk is `…/4ce3df03-d720-4015-b6ef-6da745752066/session.v3.jsonl.zstd` at **2026-09-11T22:29Z**. Census: **22 × `session.v3.jsonl.zstd`, 52 × `session.jsonl.zstd`** — the locator sees a strict subset of the 74 logs, and never the current one.

### 3.2 Failure triage

| FAIL | Sev | Verdict | Reasoning |
|---|---|---|---|
| **SS4** `45 个孤儿 tool/call` | high | **STALE-CHECK ARTIFACT — false positive, 100%** | Direct count on the scanned log: **45 `tool/call`, 45 `tool/result`**, `callId` on **45/45 calls** and **0/45 results**. The pairing key moved to `data.message.source.callId`; SS4's `data.callId` therefore never matches a result. Same result against the current v3 log (81 calls → "81 orphans"). No truncation exists. |
| **SS2** `27 个 PII 暴露` | medium | **STALE-CHECK ARTIFACT — false positive** | Every sampled match is benign: line 12's 10 "IPv4" hits are all `127.0.0.1` (loopback, in a skill description), and the "phone" regex matches **substrings of Unix-ms timestamps** (`"time":1788769155230` → `17887691552`). The regexes have no digit-boundary guard and no private-range exclusion. Additionally the whole check is reading a two-day-old log from a different workspace. |
| **SL1** `5 个供应链问题` | medium | **STALE-CHECK ARTIFACT (design)** | All five are `version-mismatch` = "local ≠ registry `latest`" — that is *outdated*, not a supply-chain integrity failure; **zero** integrity mismatches were found. One entry is outright backwards: `dsh-at-file` local `0.6.8` vs `latest 0.6.3` (the local build is a GitHub tarball, *newer* than npm). |
| **SL4** `4 个发布兼容性问题` | medium | **STALE-CHECK ARTIFACT (design)** | Two `next-available` (pure noise) and two `latest-is-prerelease` on `@zseven-w/dsh-noema*`. In an ecosystem whose whole release line is `-rc`, "latest is a prerelease" carries no signal. |
| **SP8** `53 处 plugin×peer 版本对` | high | **TRUE FINDING (upstream registry), impact overstated** | Verified independently: `@deepseek-ai/dsh-{session,tools,sandbox,base,web-app}` → `latest=0.0.1-rc.1`, `next=0.1.5-rc.2`. The registry condition is real. See §3.3 for why the *security consequence* the check asserts no longer holds. |

**Net: 1 true finding (SP8), 4 stale-check artifacts.** The non-zero exit code is produced entirely by artifacts plus one upstream-condition finding; no genuine security issue was detected by the suite, and none of the four artefacts should be treated as a finding.

### 3.3 Why SP8's impact model is now wrong (though its measurement is right)

In 0.1.0-era profiles, a plugin's `@deepseek-ai/dsh-*` peer really could be pulled from the registry, which is what #2763 described. In 0.1.5:

- the profile's `package.json` lists core packages only in `dsh.profile.bundles`, **not** in `dependencies`;
- `~/.dsh/profiles/web/pnpm-lock.yaml` records `@deepseek-ai/*` **only under `peerDependencies`** (125 occurrences), i.e. as host-provided, unresolved peers;
- `~/.dsh/profiles/web/node_modules/@deepseek-ai/` is an **empty real directory**;
- the actual instances come from `$DSH_HOME/profiles/node_modules` — a symlink mirror of the **CLI installation's own dependency closure** written by `healProfilesModuleFallback` (`dsh-app-boot/lib/index.js:660-690`, and the module doc at `:299-308`: *"`$DSH_HOME/profiles/node_modules` supplies the installation dependency closure through Node's ordinary parent-walk"*). Observed: `dsh-tools`, `dsh-session`, `dsh-client-connection` all resolve to **`0.1.5-rc.2`**, which satisfies every observed peer range (`^0.1.2-alpha.2`, `^0.1.2-rc.1`, `^0.1.0-rc.6`).

So the FAIL is a faithful reading of a genuinely broken `latest` tag, but the "plugin cannot resolve a usable version" consequence does not follow in 0.1.5. It should be re-scoped to an advisory, and only raised when a declared peer range **excludes** the version actually provided by the installation closure.

---

## 4. Rot found

Ordered by severity of consequence.

### R1 — Session locator only matches generation 0 (CRITICAL for the SR/SS layer) — **moved**
`dsh-doctor`'s `findLatestSession` builds candidates from `session.jsonl.zstd` / `session.jsonl` only. 0.1.5 appends to `session.v3.jsonl.zstd` (`SESSION_FORMAT_VERSION = 3`, `dsh-session-format/lib/index.js:474`). Consequence: SR1–SR4 and SS1–SS3 analyse an arbitrary *old* log (here: 2026-09-09, a different workspace) and report PASS/FAIL about the past. Same failure mode as the diagnostics-side locator. This is aggravated by the coexistence pattern — `session-351bcb12-…/` holds **both** `session.jsonl.zstd` (frozen at migration) and `session.v3.jsonl.zstd` (live), so filename matching silently selects the pre-migration snapshot.

### R2 — `tool/call` argument key moved to `data.arguments`; SR1/SR2/SR3 are permanently blind — **renamed**
**Proof:** of the 45 `tool/call` rows in the scanned log, 45 carry `data.arguments`. Scanning what our checks scan (`data.args || data.input` → `"{}"`) finds **0** matches; scanning the real argument text finds **3** matches, all of the form `sudo chown -R $(id -u):$(id -g) /Users/w…`. SR2 returned **PASS**, silently missing three HIGH-severity `sudo usage` hits that its own regex is designed to catch. This is the most serious rot because it is a CRITICAL/HIGH-severity check that can never fail.

### R3 — `tool/result` payload nesting; SS3 blind, SS4 emits a false HIGH — **moved**
v0 *and* v3 `tool/result.data` = `{turn, step, message:{source:{kind,callId}, content:[…]}}`. None of `data.output` / `data.result` / `data.text` / `data.callId` exist. SS3 can never match; SS4 fabricates one orphan per call (45 on the baseline log, 81 on the current v3 log).

### R4 — `turn` moved under `data`; SR4 collapses the whole session into one turn — **moved**
0/45 rows have a top-level `turn`. SR4's `call.turn || 0` therefore aggregates the entire session; it passed here only because this log used 3 distinct tools (`ask_user_question`, `bash`, `memory`). Any session using ≥7 distinct tools would produce a **false MEDIUM FAIL** ("multi-tool-turn") on the whole session. Latent, not yet triggered.

### R5 — SP9's duplicate-instance premise is inverted by the module-fallback design — **moved**
`~/.dsh/profiles/node_modules/@deepseek-ai/` is a **dsh-owned symlink mirror** of the installation closure: **240 symlinks, 0 real directories**, including all four `CORE_RUNTIME_PKGS` (`dsh-tools@0.1.5-rc.2`, `dsh-agent-loop`, `dsh-sandbox-local`, `dsh-subprocess-local`) pointing at `/opt/homebrew/lib/node_modules/@deepseek-ai/dsh/node_modules/…`. Two independent defects:
- `entry.isDirectory()` is `false` for symlinks, so SP9 is **blind to the fallback mechanism entirely** — verified: SP9 PASSes both on `~/.dsh/profiles/web` (empty dir) and on `~/.dsh/profiles` (240 symlinks). It can only ever see real pnpm-installed directories.
- The package names it treats as a CRITICAL leak are *expected* to be present in that mirror, so the rule would be a false CRITICAL if the symlink filter were ever relaxed.

Secondary observation on the same tree: of **603** symlinks in `~/.dsh/profiles/node_modules`, **95 point into `/Users/waterfly/.npm/_npx/…`** and **118 are broken**. This is a stale mirror generation — the same "npx layout" residue that rotted the diagnostics locator — and it means profile-level `@deepseek-ai/*` presence carries no signal at all.

### R6 — SP3's sandbox targets are outside the scanned set — **gone**
The live 0.1.5 sandbox wiring is in `@deepseek-ai/dsh-base/cordis.patch.yml` (lines ~199-242): `id: sandbox` → `dsh-sandbox-local`, `id: sandbox-policy` → `dsh-sandbox-policy` with `config.mode: !!js process.env.DSH_PERMISSION_MODE ?? 'workspace-write'`, `id: approval` → `dsh-user-approval` with `config.policy`, `id: permission` → `dsh-permission-presets` with a `config.presets.{read-only,workspace-write,danger-full-access}` table. None of that is inside the profile, and none of the 14 profile-scanned patch files contains the string `sandbox-policy`, so `checkSandboxPolicy()` is dead code. `str_replace_editor` is a tool *name* (`dsh-tool-str-replace-editor/lib/index.js:266`), not a loader id; `tool-glob` / `tool-grep` no longer exist (superseded by `tool-fs-search`); `tool-fs-write` never existed. SP3 reports "consistent" having tested nothing.

### R7 — SP5 does not model the real capability surface — **moved**
0.1.5 grants capabilities by cordis DI (`inject`) and, at the manifest level, via three real fields that SP5 ignores entirely:
- `dsh.bundle = { patch: "./cordis.patch.yml" }` — the loader-layer declaration (SP5's truthiness gate is correct here),
- `dsh.client = { inject: [<client package list>], platform: "web" }` — the client-side capability/dependency list,
- `dsh.compatibility = { dsh: "0.1.2-alpha.4 || …", dshReleases: {…}, profiles: ["web"] }` — the declared supported core releases and profiles.
There is no per-plugin `permissions` / `capabilities` field in the manifest, and session-level sandbox/permission is expressed through the `permission` settings namespace (`settings.yaml → permission.defaultPreset`, `dsh-permission-presets/lib/index.js:23,121-123`) plus the cordis `sandbox-policy.config.mode` — none of which SP5 reads. SP5's `tool-fs|str_replace_editor` + `sandbox` string heuristic matches no real declaration.

### R8 — `permission/preset` frozen disposition makes some real v0 logs unreadable by the harness — **new harness behaviour, relevant to SS4's remit**
`dsh-session-format-v0-to-v1/lib/index.js:119` freezes `"permission/preset": disposition(["preset"])` (required `["preset"]`, optional `[]`), and `assertReleasedV0Keys` (`:257-266`, invoked from `assertReleasedEventPayload` `:1579-1592`, reached via `normalizeReleasedV0Event` `:1917`) throws `SessionFormatError("… has unexpected member \"origin\"")` for any extra member. The chain converts that to a `malformed` status (`dsh-session-format/lib/index.js:299,331,453`) — the **whole v0 log is refused**, not partially read.

This is not theoretical on this host: **10 of the 52 v0 logs** contain `{"preset":"workspace-write","origin":"default"}`, e.g.

```
--Users-waterfly-dsh~5DE5~4F5C~533A--/session-8d782108-721a-4498-8de1-45657a1e53be/session.jsonl.zstd
--Users-waterfly-dsh~5DE5~4F5C~533A--/session-ff7acd38-5263-42ca-adf8-d1d93503b9a4/session.jsonl.zstd
--Users-waterfly-dsh~5DE5~4F5C~533A--/session-b17380c9-e40b-4454-bf12-35588dbcc6cd/session.jsonl.zstd
(+7 more)
```

Our checks parse raw lines, so they do not themselves break — but SS4's declared remit ("sessions that brick / fail to resume") includes exactly this class, and SS4 currently reports only JSON syntax + pairing + line count. It misses the dominant real bricking mode in 0.1.5. The log the baseline actually picked (`session-95cc28de`) happens to be migratable (its `permission/preset` has no `origin`), so this did not surface.

### R9 — SP1 is a permanent false PASS in a pnpm profile — **broken**
`npm audit` requires `package-lock.json`. Measured: exit 1, `{"error":{"code":"ENOLOCK", …}}`, no `package-lock.json` in the profile. `parseNpmAudit` finds no `vulnerabilities`/`advisories` → `PASS "依赖链无已知漏洞（扫描 ? 个依赖）"`. The check has never audited anything on this host.

### R10 — SS2 regexes are unanchored and produce only false positives — **stale patterns**
See §3.2. `IPv4` matches `127.0.0.1`; `phone` matches 11-digit windows inside millisecond timestamps. No private-range exclusion, no digit-boundary assertion, no context filter.

---

## 5. Recommended updates (ranked)

Ranked by (severity of the check affected) × (probability the defect is silently wrong today). All items are confined to `src/**` and to the locator in `dsh-doctor`; none requires modifying the harness.

1. **Fix the session locator (dsh-doctor `findLatestSession`) — generation-aware discovery.**
   Accept `/^session(?:\.v([1-9][0-9]*))?\.jsonl(\.zstd)?$/` (mirror `CANONICAL_LOG_FILENAME` in `dsh-session-format/lib/index.js:466`), enumerate **all** canonical generations per session directory, prefer the highest generation (today v3), and rank across directories by mtime. Also accept `_no-cwd` project dirs and ignore `session.lock`. Without this, every SR/SS result is a statement about the past. *Impact: restores the entire runtime layer.*

2. **Rewrite the SR/SS event readers for the current payload schema.** Add one shared extractor used by SR1/SR2/SR3/SR4/SS3/SS4:
   - arguments: `data.arguments` (parse the JSON string when it parses, else use raw text) — keep `data.args`/`data.input` as fallbacks for old logs;
   - results: walk `data.message.content[]` → `.content[]` → `.text` (and `data.message.source.callId`);
   - `turn`/`step`: read from `data.turn` / `data.step`, retaining top-level `event.turn` as a fallback.
   *Impact: removes the false HIGH (SS4), unblinds SR1 (CRITICAL), SR2, SR3, SS3, and fixes the latent SR4 false FAIL.*

3. **Make SS4's pairing generation- and direction-agnostic.** Pair on the first non-empty of `data.callId`, `data.message.source.callId`, `data.message.content[].toolCallId`; report orphan calls only when the session has a `turn/end` (or `session/end-seed`) closing the turn — an in-flight call is normal. Add a "log is unmigratable by the installed format chain" signal by checking the frozen `permission/preset` disposition invariant (`data.origin` present ⇒ the harness refuses the v0 log); this is the real bricking mode (R8).

4. **Re-scope SP8.** Keep the registry probe (the fact is real) but (a) drop severity to `low`/advisory, (b) only raise it when the declared peer range **excludes** the version actually provided by the installation closure (`~/.dsh/profiles/node_modules/@deepseek-ai/<pkg>/package.json → version`), and (c) treat a missing `@deepseek-ai/*` entry in the profile lock as **host-provided**, not affected. Otherwise it will keep failing forever for a condition that no longer breaks plugin resolution.

5. **Rewrite SP9 around real duplicates, not names.** The signal is no longer "a `@deepseek-ai/dsh-*` name appears under a profile", it is:
   - a **real directory** (not a symlink) at `<profileDir>/node_modules/@deepseek-ai/dsh-*`, **or**
   - a symlink under `$DSH_HOME/profiles/node_modules/@deepseek-ai/` whose target is **not** inside the installation prefix (this is a durable, cheap "shadowed core" test), **or**
   - two different resolved versions of the same core package reachable from one profile.
   Use `lstatSync`, not `readdirSync().isDirectory()`, so symlinked fallback entries are visible. Add a separate advisory for the broken/stale mirror generation (118 broken and 95 npx-cache-pointing symlinks observed today).

6. **Re-point SP3 at where the sandbox is actually configured.** Read `@deepseek-ai/dsh-base/cordis.patch.yml` (resolved through the module-fallback anchor) plus `$DSH_HOME/settings.yaml → permission.*`, instead of hunting `sandbox-policy` inside profile patch files. Refresh the id lists: drop `str_replace_editor` (a tool name), `tool-fs-write`, `tool-glob`, `tool-grep`; keep `tool-fs`, `tool-fs-search`; add the real service ids `sandbox`, `sandbox-policy`, `permission`, `approval`, `bash-sandbox`. The high-value assertion is `sandbox-policy.config.mode` (or `DSH_PERMISSION_MODE`) resolving to `danger-full-access` while `approval.config.policy` is `never`.

7. **Replace SP5's string heuristic with the declared manifest fields** — `dsh.bundle` (keep), `dsh.client.inject`, `dsh.compatibility.{dsh,dshReleases,profiles}`. The compatibility field is the real, machine-readable capability/compat surface and is currently unread. Keep SP5 scoped to "declared vs. supported core release", not to guessing sandbox usage from patch text.

8. **Fix SP1 or stop claiming it audits.** Either run `pnpm audit --json` (or `osv-scanner`) when the profile is pnpm-managed, or explicitly `skip` with `code: 'NO_LOCKFILE'` — a silent PASS with `扫描 ? 个依赖` is worse than a skip. Note SP6 already covers npm-side advisories via OSV for `dsh`-named deps.

9. **Tighten SS2.** Add digit boundaries (`(?<![\d.])` / `(?![\d.])`), exclude RFC1918/loopback for IPv4, and require the phone pattern to not be embedded in a longer digit run. Annotate matches with their line context so a reviewer can triage in one pass. Reconsider whether bare IPv4 is PII at all (it is currently the largest source of noise).

10. **Reclassify SL1/SL4's `version-mismatch` / `next-available` / `latest-is-prerelease` as informational.** They compare against `dist-tags.latest`, which is *not* the version source of truth in this ecosystem (`latest` is stuck at `0.0.1-rc.1` for core packages while `next` is `0.1.5-rc.2`). SL1's integrity/hash branch (its only critical-severity behaviour) found nothing and should stay the only path that can produce a non-zero severity.

11. **Add a "format generation" field to every SR/SS result detail** (e.g. `generation=v3`, `frames=136`, `path=…`). Given R1/R8, a reader must be able to tell *which* log a verdict came from; the current detail lines (`扫描 1146 行会话日志`) conceal the fact that it was the wrong file.

---

## 6. Unverified

Stated explicitly so nothing here is over-claimed:

1. **End-to-end behaviour of the v0→v3 migration on the 10 `origin`-bearing logs.** I verified the frozen disposition (`permission/preset → disposition(["preset"])`), the validator (`assertReleasedV0Keys` throws `unexpected member "origin"`), the call path (`normalizeReleasedV0Event` → `assertReleasedEventPayload`), that the chain converts such errors to a `malformed` status, and that 10 real local logs contain the offending member. I did **not** execute a migration (that would require writing to `~/.dsh`, which is out of scope), so the exact user-visible symptom — resume refusal vs. silent `malformed` vs. a fallback read of the v1/v2 generation — is **inferred from source, not observed**.
2. **Whether the harness reads a migrated v0 log at all when both `session.jsonl.zstd` and `session.v3.jsonl.zstd` coexist.** I confirmed both files exist and that the v3 file is the append target (`logPath()` uses `SESSION_FORMAT_VERSION`) and that `findOppositeGenerationInDirectory` only rejects the *opposite compression*, so coexistence is not an error. Which of the two a resume actually reads was not exercised.
3. **`zstd -dc` on a file whose later frames are truncated.** Our reader would surface the CLI's stderr as a thrown error (not a `skip`), so a torn tail currently becomes a check execution failure rather than a finding. I verified the frame count and that all 136 frames decode independently, but not the truncated-tail path.
4. **SP1's exact behaviour under `DSH_SECURITY_SRC` / other environments.** The `ENOLOCK` result is measured for `--profile web` on this host only; a profile carrying a `package-lock.json` would take the intended path.
5. **The stale `~/.dsh/profiles/node_modules` generation (118 broken + 95 npx-pointing symlinks).** Counted, not attributed: I did not determine whether it is self-healing on the next boot (`healProfilesModuleFallback` is invoked per launch) or permanently wedged. No dsh server was started, per the constraints.
6. **SP4's false-positive/false-negative rate under a richer plugin set.** The baseline's 14 patch files trip nothing; patch files elsewhere in the ecosystem may legitimately contain `child_process`/`fetch` in `!!js` expressions, which SP4 rates `high`/`medium`. Not sampled.
7. **The `dsh-session-query-sqlite` store and `~/.dsh/storages/session_projcache`** as alternative session indexes. They exist, but no `.sqlite` database file was found under `~/.dsh` on this host, so whether they could serve as a more robust locator than filesystem walking was not established.
8. **Anything requiring network beyond the npm registry and GitHub contents endpoints** used by SP6/SP8/SL1/SL3/SL4/EXT-ECO-1 was not exercised beyond what the baseline run itself performed.

---

## 7. Artifact/reproduction notes

- Two throwaway files were written under `/tmp` only: `/tmp/sec-baseline.json`, `/tmp/sec-baseline.err`, `/tmp/sec-baseline.exit`, `/tmp/npmaudit.json`, `/tmp/npmaudit.err`. Nothing else was created or modified outside this report.
- No `dsh` server was started; no GitHub call was made beyond the read-only `api.github.com`/`registry.npmjs.org` GETs performed by the suite itself; `/opt/homebrew` and `~/.dsh` were not written to.
- Re-running the baseline: `cd /Users/waterfly/dsh工作区/dsh-doctor && ./dsh-doctor.sh --security --security-only --profile web --json`. Expect `exit 1`, `high 2 / medium 3`, and the same five FAILs until items 1–3 and 4 are addressed. Note that SS4's orphan count tracks the live session size and will grow.
