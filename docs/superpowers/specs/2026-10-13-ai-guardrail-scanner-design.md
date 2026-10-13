# Java AI 安全围栏扫描 MCP — 已确认设计

用户于 2026-10-13 确认：源码与配置扫描；Java / Spring Boot / Spring AI；独立 Java MCP server、离线静态证据、可验证 MVP。本文件具体化已确认的架构。

## 范围与边界

Java 21 运行时，官方 MCP Java SDK 2.0.1，JavaParser / Symbol Solver 3.28.2。首期只读解析源码和配置，不执行目标 Maven/Gradle、应用、注解处理器或任意项目代码，不下载目标依赖，不向模型传输源码。LLM 语义复核作为后续可选扩展，0.1.0 不提供或宣称这项能力。

L1 提示注入，L2 授权与隔离，L3 数据泄露，L4 资源限制，L5 内容审核，L6 审计，L7 输出与执行安全。RAG/记忆相关规则归入 L2。模型权重后门、真实围栏抗攻击率和生产有效性不在静态扫描的证明范围。

## 分析架构

单进程：文件清点/摘要 → Java AST 与符号解析 → 有界调用与数据关系 → 版本化规则评估 → JSON / Markdown / SARIF。Maven XML 使用禁用外部实体的解析器；Gradle 仅识别字面量和常见版本变量，不求值脚本。支持 Spring AI 1.0.x、1.1.x、2.0.x 的显式版本识别；版本冲突、外部 BOM 或无法求值的版本保留未知，版本相关结论不升级为已确认违规。

符号解析不保证完整控制流、动态 Bean/AOP、反射或外部授权解析。规则只能在其明确支持的模式内作出结论；自定义防护/网关/存储 ACL 未解析时保留限制。

## 结果契约

每条规则输出 `ruleId / domain / disposition / severity / title / explanation / recommendation / evidence / limitations`。Evidence 是相对源码位置与固定描述，不包含原始代码、提示词或密钥。状态：VIOLATED（在规则支持范围内有违反证据）、OBSERVED（只确认某控制或构造存在）、UNKNOWN（证据不足）、NOT_APPLICABLE（有不适用依据）。OBSERVED 不是安全通过，也不计算安全分数。

所有七个域进入控制覆盖报告。报告包含规则版本、源文件摘要、依赖版本、分析诊断。无法解析、达到文件/字节限制或规则分析失败均记录诊断并将完整性标为 false。UNKNOWN 使控制覆盖不完整。CLI：发现违规返回 1；无违规但信息不足返回 2；无违规且评估完成返回 0；取消返回 130。

## 首批控制

有界检测覆盖：不可信输入进入 system prompt；围栏绑定与异常放行；工具输入到敏感操作；固定会话 ID；原始 AI 数据日志；无界重试；流式输出审查顺序；审计关联；模型输出到危险 sink；RAG 过滤覆盖。规则说明必须注明实际支持的语法和降级条件，不能以规则数量冒充检测能力。

## MCP 与扫描器安全

提供 `guardrail_rules`、`guardrail_scan_start`、`guardrail_scan_status`、`guardrail_scan_cancel`、`guardrail_scan_result`。启动时由操作员配置 allowed roots；工具调用不能扩大范围。真实路径校验，默认不跟随符号链接。禁止扫描输出目录；结果保存在操作员指定且位于目标之外的目录。一次最多一个活动扫描，有限历史与输出大小；取消结果不可变且不得再写完成结果。会话终止清理扫描任务；stdout 只用于 JSON-RPC，日志写 stderr。

MCP 不提供任意文件读取、shell、任意网络请求或漏洞利用执行能力。源文件视为不可信数据，不作为扫描指令；输出无源码摘录。

## 验收

1. 规则针对明确违规、已正确处理/不应误报、证据不足建立独立样例；不能只测规则函数存在。
2. 覆盖声明未绑定、流式/同步差异、同名非 AI API、外部鉴权和未知版本等边界。
3. 路径逃逸、符号链接、解析错误、预算耗尽、未知 scanId、非法参数、取消与失败状态均不会产生通过结论。
4. 打包 jar 的真实 stdio MCP 握手、工具发现、扫描开始/查询/结果、取消通过；JSON、Markdown、SARIF 文件可重新读取。
5. 演示 fixture 不是生产审计有效性认证，所有限制写入 README 和报告。

## 一手依据

- https://docs.spring.io/spring-ai/reference/api/advisors.html
- https://docs.spring.io/spring-ai/reference/api/tools.html
- https://docs.spring.io/spring-ai/reference/api/retrieval-augmented-generation.html
- https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html
- https://github.com/javaparser/javaparser
- https://java.sdk.modelcontextprotocol.io/latest/server/
- https://genai.owasp.org/llmrisk/llm01-prompt-injection/

