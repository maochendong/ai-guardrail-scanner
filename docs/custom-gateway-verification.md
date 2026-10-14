# 自定义网关、Guard 与 Function Calling 验收 · 0.2.0

2026-10-13：开发、打包、Codex 注册及两个真实项目的 MCP 流程复验完成。规则不依赖两个项目的名称、包名或业务类名。报告提供有界静态证据，两个项目均不是安全通过，`securityVerified=false`、`complete=false`。

## 本次能力

- 原有 11 条 Spring AI 规则保留；新增自定义网关/Guard 5 条、function calling 3 条，共 19 条。
- 以已知 HTTP 客户端类型、关联协议地址/请求响应形状发现模型边界；支持源内委托、候选接口分派与部分 Consumer 流式回调。
- Guard 观察输入前提前退出、模型输出进入判定、record/普通布尔结果对象的消费关系及 SSE 释放顺序。未知检查语义不会因为方法名或顺序而升级为安全/违规。
- FC 关联模型名称/参数字段、JSON 解码、record 和有限分派参数，记录固定 switch/Map 结构、独立上下文实参，并检查命令/反射目标路径。参数验证、身份可信度和实际工具授权独立保留 UNKNOWN。
- schema 为 `1.1`，规则集为 `java-guardrail-v2`；JSON/Markdown/SARIF 均保留 AI 协议及边界方法数量，不伪造 Spring AI 版本。

## 验证结果

`./scripts/mvn.sh -q clean verify`：**230 tests，0 failures/errors/skipped**。包括调用图 24、网关模型 19、Guard 19、FC 21、端到端报告集成 1 项，以及既有规则/文件/权限/生命周期/报告测试。

`./scripts/mvn.sh -q -Dtest=McpProtocolTest -Dscanner.jar=target/ai-guardrail-scanner.jar test`：**4 tests passed**，使用真实 `java -jar` 子进程。它们是单独的打包产物验收，不加到 230 项唯一测试数中。

独立复核及回归覆盖：应用类型/方法重命名、普通 HTTP/非模型 JSON、无关返回与字段覆盖、接口混合分派、忽略或改写 Guard 结果、跨分支顺序、Java 8 可变结果对象、未执行的嵌套请求 builder、HTTP/usage 元数据、`grep -c` 普通参数与真正 shell 命令、匿名对象覆写、取消与预算。运行规则目录中没有目标项目标识。

## 真实 Codex MCP 流程

通过 `codex app-server --stdio` 的临时客户端运行时读取正式 Codex 配置，发现 server **0.2.0**、5 个工具、19 条规则。测试实例临时禁用其他 MCP/plugin，不修改其持久配置；未发起模型 turn。

共 30 次实际 `mcpServer/tool/call`，验证允许范围外路径拒绝、无效扫描 ID 拒绝、两项目 RUNNING → COMPLETED、JSON/Markdown/SARIF 三格式读取与文件逐字一致、规则/域覆盖一致，以及完成后的取消不改变终态。验收脚本要求两个项目均有网关与 FC 三条规则的 OBSERVED，避免只验证进程结束却遗漏新能力。

| 项目 | Java / 配置文件 | 网关边界方法 | VIOLATED | OBSERVED | UNKNOWN | 流程耗时 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| codebuddy | 249 / 7 | 4 | 1 | 5 | 19 | 2.286 s |
| wm-sales-atlas-analysis | 217 / 25 | 1 | 0 | 5 | 19 | 1.252 s |

统计的是评估记录，不是独立漏洞数量；耗时包括本机 MCP 状态轮询和报告读取，不是性能基准。相比 0.1.0，两项目均从 `aiDetected=false`、11 个 UNKNOWN，变为 `aiDetected=true`，协议为 `openai-chat-compatible`。前后源文件摘要完全相同，因此新增证据来自扫描能力变化。

### CodeBuddy

- 网关边界：AgnesClient 的同步/流式各一处，DeepSeekClient 的同步/流式各一处，共 4 个方法。
- Guard：AIAssistantService:196/209/221/229 观察到模型调用前的自定义判定/提前退出；输入关联与拒绝语义尚未证明。
- FC：AIAssistantService:558、671 → FunctionCallExecutor:86 固定 switch，默认分支 :187 未包含直接工具调用。FC 三条规则均 OBSERVED + UNKNOWN。
- `AI-GW-002` 一条违反评估包含 **2 处日志位置**：DeepSeekClient:216 记录模型 reasoning 内容；:258 的 SSE 解析失败路径把完整事件数据传入日志。已核实源至日志参数关系；不宣称这些内容必含敏感数据、实际落盘或已发生泄露。
- SSE 模型回调至发送可见，但不完整证明对应内容的发送前审核与完整流覆盖。

### wm-sales-atlas-analysis

- 网关边界：OpenAiCompatGateway:68 的 RestClient 请求/响应协议形状；通过候选接口及 FailoverGateway 返回链关联模型来源。
- Guard：AiChatService:195/252、AiInsightService:103 的模型来源值进入判定，返回结果参与提前退出；只确认消费结构，不证明规则正确或全路径覆盖。
- FC：AiChatService:179 → AiToolRegistry:27 的 Map 成员检查及 FunctionCallExecutor:109 的 Map 查找；跨 try 赋值、JSON 解析及自定义 record 关联已被识别。FC 三条规则均 OBSERVED + UNKNOWN。
- AiChatService:256、AiInsightService:107 的模型响应日志仅为 UNKNOWN：运行时分派/来源候选未能确证，不强行升级为违反。零条违反不表示安全。

## 诊断与范围

两项目均保留 macOS `FILESYSTEM_RACE_LIMITATION` 和 `RESULT_LIMIT`（每评估最多 16 个证据位置）；wm 另有 37 个 `SYMLINK_SKIPPED` 和 1 个 `CALL_GRAPH_LOCAL_TYPE`。源码图、协议传播和规则均有预算；不跟随符号链接、不执行目标构建/脚本、不下载目标依赖、不访问模型或上传源码。

动态 Bean、AOP、反射、复杂异步、所有工具 schema、工具循环预算/回灌注入和完整业务授权尚不在已验证范围。静态观察不能替代真实应用行为验证。两项目 Git HEAD 与已有工作区修改的状态摘要在复验前后完全一致，目标项目未被修改。

## 安装与当前会话

- 安装 JAR：`/Users/Darkknight/.local/share/ai-guardrail-scanner/0.2.0/ai-guardrail-scanner.jar`
- SHA-256：`387d92dd8f56484fe1662cc9be7b6e9eef771b79a3762ac4abc51be6e1b7b136`
- 配置备份：`/Users/Darkknight/.codex/backups/config.before-ai-guardrail-v020-20261013-230951.toml`
- TOML 结构对比确认仅本 server 的 JAR 参数改变；允许根目录、报告目录及其他所有设置保持原值。0.1.0 JAR 保留可回退。
- 当前对话已经建立的 MCP 进程仍返回 11 条规则；本次新 Codex 运行时实际返回 19 条规则。当前对话继续直接用工具前需重连该 MCP 或重新启动 Codex 会话；不能把配置已更新等同于旧进程已热更新。

## 持久证据

- [完整 MCP 汇总](../scan-results/codex-custom-20261013/summary.json)
- [30 次工具调用记录](../scan-results/codex-custom-20261013/mcp-tool-transcript.json)
- [验收驱动](../scan-results/codex-custom-20261013/verify_codex_integration.py)
- [构建测试及 JAR 摘要](../scan-results/codex-custom-20261013/build-verification.json)
- [目标项目未变更核验](../scan-results/codex-custom-20261013/target-verification.json)
- [安装记录](../scan-results/codex-custom-20261013/registration.json)
- codebuddy： [Markdown](../scan-results/1cf94274-57ad-45a7-840a-9d9a8e38c1de/report.md) · [JSON](../scan-results/1cf94274-57ad-45a7-840a-9d9a8e38c1de/report.json) · [SARIF](../scan-results/1cf94274-57ad-45a7-840a-9d9a8e38c1de/results.sarif)
- wm-sales-atlas-analysis： [Markdown](../scan-results/4f5cadfe-6d5f-4134-8e67-e1c40c02460f/report.md) · [JSON](../scan-results/4f5cadfe-6d5f-4134-8e67-e1c40c02460f/report.json) · [SARIF](../scan-results/4f5cadfe-6d5f-4134-8e67-e1c40c02460f/results.sarif)
