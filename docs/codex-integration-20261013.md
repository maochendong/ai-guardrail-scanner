# Codex 接入与真实项目流程验收

日期：2026-10-13。

**接入和扫描流程验证通过；两个应用的安全结论均未完成。** 两个项目使用自定义模型网关，没有使用现版规则支持的 Spring AI API。本次 0 条违反、11 条未知不能解释为安全通过。

## 已安装配置

- Codex server 名称：`ai-guardrail-scanner`，`codex mcp get ai-guardrail-scanner --json` 确认 `enabled=true`。
- 配置文件：`/Users/Darkknight/.codex/config.toml`。
- 原配置备份：`/Users/Darkknight/.codex/backups/config.before-ai-guardrail-20261013-223825.toml`。完成后通过 TOML 结构比对，确认除新增 server 外原配置保持一致。
- Java：`/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home/bin/java`。
- 已安装 JAR：`/Users/Darkknight/.local/share/ai-guardrail-scanner/0.1.0/ai-guardrail-scanner.jar`。使用独立安装副本，项目执行 Maven clean 不会删除已配置的 server。
- JAR SHA-256：`bd870dc554db4308ae9ad6a997fb5afcd604ff951609be3d9d1761788dcf02bf`，与本次构建产物一致；扫描器源码提交 `343fd36`。
- allowed roots 仅为 `/Users/Darkknight/CodeBuddy` 和 `/Users/Darkknight/wm-sales-atlas-analysis`。
- 报告根目录：`/Users/Darkknight/Documents/AI安全围栏/scan-results`，位于两个目标项目之外。

接入使用官方 `codex mcp add ... -- <stdio command>`，配置由桌面应用和 CLI 共用。[OpenAI 官方 MCP 文档](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)

## 实际验证方式

使用本机 Codex app-server 的 stdio 客户端，创建仅存于内存的测试上下文；不启动模型推理回合。通过 `mcpServerStatus/list` 发现工具，并通过 `mcpServer/tool/call` 发起请求。测试实例临时停用其他 MCP/插件，不修改其持久配置。扫描器从刚注册的全局配置启动，未改用 CLI `scan` 来替代 MCP 验证。

验证结果：server 状态为 `connected`，发现全部 5 个工具，规则目录返回 11 条。26 次工具调用覆盖：

1. `guardrail_rules` 读取规则目录。
2. 拒绝 allowed roots 之外的 `/Users/Darkknight` 扫描请求；拒绝无效 scanId。
3. 两个项目依次 `guardrail_scan_start`，通过 `guardrail_scan_status` 观察 `RUNNING → COMPLETED`。
4. 对每个 scanId 分别读取 JSON、Markdown、SARIF。工具返回正文与对应落盘文件逐字一致，JSON/SARIF 可解析，七域记录和违反规则集合一致。
5. 对已完成任务调用取消，确认终态及计数不变。此次没有用真实项目重测运行中的取消竞态；该行为已有打包 JAR 协议回归测试，见 [MVP 验证记录](verification.md)。

当前聊天最初加载的工具列表尚未显示新增 server；本次验证的是新启动的真实 Codex 客户端。不得把独立客户端的 connected 描述为当前聊天已经热加载。使用时若当前客户端列表尚未更新，可重新加载 MCP 或重新启动客户端。

## 项目结果

| 项目 | Java 文件 | 配置文件 | 违反 | 未知 | 完整性 | 流程 |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| codebuddy | 249 | 7 | 0 | 11 | false | COMPLETED |
| wm-sales-atlas-analysis | 217 | 25 | 0 | 11 | false | COMPLETED |

配置文件数是扫描器清点的受支持配置文件总量，不等于全部是应用配置。两份报告均声明 `securityVerified=false`，SARIF `executionSuccessful=false`。摘要的 `passed=true` 只表示流程验收通过。

- codebuddy：scanId `d6f22a7b-7f7b-49c7-a9ec-aad3b9d0605f`；[中文报告](../scan-results/d6f22a7b-7f7b-49c7-a9ec-aad3b9d0605f/report.md)、[JSON](../scan-results/d6f22a7b-7f7b-49c7-a9ec-aad3b9d0605f/report.json)、[SARIF](../scan-results/d6f22a7b-7f7b-49c7-a9ec-aad3b9d0605f/results.sarif)。
- wm-sales：scanId `da6af336-365a-4279-b64e-d3236be34da1`；[中文报告](../scan-results/da6af336-365a-4279-b64e-d3236be34da1/report.md)、[JSON](../scan-results/da6af336-365a-4279-b64e-d3236be34da1/report.json)、[SARIF](../scan-results/da6af336-365a-4279-b64e-d3236be34da1/results.sarif)。

原始工具调用记录、发现结果、配置快照及验证驱动脚本保存在 `scan-results/codex-integration-20261013/`，不纳入 Git。报告不导出目标源码或配置原始值。

## 覆盖缺口

- codebuddy 是 Spring Boot 2.7.18 / Java 8，自定义 `LLMClient`、`DeepSeekClient`、`AgnesClient` 及多种 Guard。wm-sales 是 Spring Boot 3.3.4 / Java 21，自定义 `LlmGateway`、`OpenAiCompatGateway`、`AiGuard`。二者生产 Java 与 POM 未发现 Spring AI 引用或依赖。
- 因此 `aiDetected=false` 表示未识别到当前支持的 AI 模式，**不能解释为应用没有 AI 功能或安全围栏**。自定义控制的行为需要专门的调用适配和证据规则，目前未完成。
- codebuddy 的 `application-sprint7.yml` 无法在当前安全解析约束内确认，记录为配置 UNKNOWN；未修改该文件，也未从通用错误信息推断具体根因。
- 两项目均有 macOS `FILESYSTEM_RACE_LIMITATION`，要求扫描期间保持源码树稳定；wm-sales 另有 37 个符号链接被跳过。默认测试和构建目录排除均留有诊断。
- 此次不执行目标应用或构建，不检测真实围栏抗攻击率，不得据此作生产准入结论。

## 目标项目保持只读

扫描前后两项目 HEAD 与 `git status --porcelain=v1 -z` 的 SHA-256 一致，保留原有未提交内容。

| 项目 | HEAD | Git 工作区状态 SHA-256 |
| --- | --- | --- |
| codebuddy | `e368f255c3777f3dc3a5fb6fc6c359817f0da0cc` | `6b7d039dfde1d180200a0a4d988857297239742b403ff45be7796117d45e2cf1` |
| wm-sales | `27239cc9ae35f4b651c2a027ee4576af8de0b7b4` | `93e5a33d79d32540b409d1179c3a7f3521d1ffd1791fded383145d2499e71e1c` |
