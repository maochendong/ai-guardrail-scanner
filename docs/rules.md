# 规则支持说明 · 0.1.0

本版本包含 11 条规则，覆盖七个控制域。它们检查明确列出的 Java 局部语法及配置模式，不提供全程序数据流或生产安全保证。规则目录也可通过 CLI `rules` 或 MCP `guardrail_rules` 获取。

## 共同前提

当前规则通过 AST 的明确类型声明、导入及限定名识别 API，没有调用符号求解 API。项目加载器虽附加了 JavaParser 符号解析器并索引本地类型，不能据此宣称规则具备完整类型解析或跨方法分析能力。扫描不会执行目标构建或下载依赖。

数据来源跟踪限于同一方法中的直接表达式、字符串拼接及未被重新赋值的局部别名。方法间传参、字段变化、分支控制流、自定义转换及动态代理通常保留为 `UNKNOWN`。未知 `map`、`flatMap` 转换会中断已确认的来源关系。同名的非 Spring AI API 不应仅凭方法名称命中；遇到未支持的封装也可能无法识别 AI 路径。

版本相关评估以输入中的显式 Spring AI `1.0.x`、`1.1.x` 或 `2.0.x` 声明为前提。支持版本号不代表支持该版本的所有 API。含明确 AI 引用的源码或明确 AI 配置按最近的 `pom.xml`、`build.gradle` 或 `build.gradle.kts` 确定所属模块；模块版本无法确定时记录 `MODULE_VERSION_UNKNOWN` 并将全项目版本状态降为 `UNKNOWN`，不借用兄弟模块的已知版本。首期没有逐源码版本结果。

- Maven 支持字面量版本、本地属性及真正导入的 Spring AI BOM；已纳入清点且 GAV 匹配的本地父 POM 链可提供属性或依赖管理。外部父 POM/BOM、未解析属性、版本冲突及所属模块未声明 AI 依赖时保守降级。
- Gradle 支持本模块常见依赖声明、字面量变量、`gradle.properties` 以及 `platform`、`enforcedPlatform`、`mavenBom`。不求值复杂脚本、多模块脚本继承或版本目录。
- 仅静态读取这些文件；Maven XML 禁用 DTD、外部实体与外部 schema，不执行构建声明。

同一条规则按不同 disposition 输出多条 assessment：有违反证据也不会吞掉同规则的未知路径。例如，一处直接入参到 system 指令可为 `VIOLATED`，另一处自定义构造可同时为 `UNKNOWN`。覆盖表、`violations` 与 `unknowns` 统计评估记录，不是独立漏洞或代码位置总数。规则内部每种证据最多保留 40 个位置，最终扫描报告每条 assessment 最多导出 16 个位置；达到结果截断条件时记录 `RESULT_LIMIT` 并使完整性不足。必须一起阅读 `evidence`、`limitations` 和诊断。

## 支持矩阵

| 规则 | 控制域 | 可以确认的局部证据 | 不能由本规则证明的事项 |
| --- | --- | --- | --- |
| `AI-L1-001` | L1 提示注入 | Web 方法入参进入明确 `ChatClient.system(...)`：`VIOLATED`；字面量系统指令：`OBSERVED` | 输入置于 `user(...)` 并不防止注入；RAG、工具返回、多轮上下文和语义攻击效果未评测 |
| `AI-L1-002` | L1 围栏绑定 | 请求级直接绑定 `SafeGuardAdvisor`：`OBSERVED`；try 使用该围栏，catch 请求同一客户端但省略围栏，且客户端在方法内通过明确 `ChatClient.builder(model).build()` 构造、未重赋值且可排除默认 Advisor 时：`VIOLATED` | 注入字段或客户端默认 Advisor 无法确定时，catch 遗漏降为 `UNKNOWN`；自定义围栏、跨方法绑定及完整同步/流式覆盖仍需核实 |
| `AI-L2-001` | L2 工具边界 | `@Tool` 入参直接进入明确命令执行文本或 `JdbcTemplate` SQL 文本：`VIOLATED`；`@PreAuthorize` 声明仅为 `OBSERVED` | 不完整分析 `SecurityFilterChain`、外部授权、方法安全启用或表达式正确性；未发现注解不能判定无鉴权。固定 `ProcessBuilder` 程序的独立数据参数不作为命令文本 |
| `AI-L2-002` | L2 会话隔离 | Web 方法中 `ChatMemory.CONVERSATION_ID` 参数使用常量，且同请求表达式明确绑定对应记忆 Advisor：`VIOLATED` | 动态 ID 的用户归属、跨 Bean 或默认 Advisor 绑定、单用户部署用途和存储 ACL；仅配置参数却无法确认绑定，或动态 ID，均为 `UNKNOWN` |
| `AI-L2-003` | L2 RAG 过滤 | Web 入参直接设置请求级 `QuestionAnswerAdvisor.FILTER_EXPRESSION`，且同请求表达式明确绑定该 Advisor：`VIOLATED`；常量表达式为 `OBSERVED` | 仅配置参数却未确认绑定不升级为违规；向量库 ACL、过滤构造器、组合后的权限范围及实际数据是否泄露仍需确认 |
| `AI-L3-001` | L3 原始数据日志 | 同一方法内进入 AI 的 Web 输入或模型输出，直接进入明确 SLF4J `Logger` 参数：`VIOLATED` | 是否确实含敏感信息、日志插件是否脱敏、是否落盘及谁能访问；本规则发现原始数据日志路径，不宣称已发生泄露 |
| `AI-L3-002` | L3 内容记录配置 | 支持的 Spring AI 观测配置显式为 `true`：原始内容记录声明风险 `VIOLATED`；同时保留实际生效与脱敏未确认的 `UNKNOWN`。显式 `false` 为 `OBSERVED`，同时保留运行时覆盖未确认的 `UNKNOWN` | 配置覆盖、profile 激活、占位符、重复键、未知 YAML 构造和无法解析的内容不能确认；未证明有真实敏感内容写出，也不证明日志访问控制 |
| `AI-L4-001` | L4 资源限制 | 明确 AI 流式调用链的无参数 `.retry()`：`VIOLATED`；字面量次数 `.retry(n)`：`OBSERVED` | 有限重试不代表存在超时、Token 预算、并发限制、用户/租户配额；网关控制需另行确认 |
| `AI-L5-001` | L5 流式审核顺序 | 同一直线语句块中，`SseEmitter.send` 发送模型内容后才调用明确 `ModerationModel.call` 审核同一原始输出变量或流片段：`VIOLATED`；先审核仅为 `OBSERVED` | 审核结果是否阻断发送、完整内容覆盖以及复杂 lambda/异步/条件分支；未知 `map`/`flatMap` 转换后不能沿用原始来源结论 |
| `AI-L6-001` | L6 审计关联 | AI Web 方法把 MDC `requestId`、`traceId`、`correlationId` 设为常量：`VIOLATED`；动态值：`OBSERVED` | 关联 ID 唯一性、其他已有追踪机制、异步传播、清理、日志持久化、策略版本与保留制度 |
| `AI-L7-001` | L7 输出执行 | 模型原始输出或未修改局部别名进入明确 `Runtime.exec` 或 SQL 文本：`VIOLATED`；`ProcessBuilder` 检查可执行程序首参及 `-c`、`/c`、`-Command` 后的命令文本 | 固定程序的独立数据参数不据此报命令执行缺陷。自定义允许列表、跨方法校验、HTML 输出、所有 SQL API 及回滚行为不在已验证范围 |

`AI-L3-002` 只检查 `application*.properties`、`application*.yml`、`application*.yaml` 中以下五个键：

- `spring.ai.chat.client.observations.log-prompt`
- `spring.ai.chat.client.observations.log-completion`
- `spring.ai.chat.observations.log-prompt`
- `spring.ai.chat.observations.log-completion`
- `spring.ai.tools.observations.include-content`

YAML 支持嵌套键、点分隔键及多文档的安全树读取；不会执行 tag，也不会把别名或未解析结构当作已确认布尔值。`chat.client.observations.log-completion` 需要已支持的 `1.1.x` 或 `2.0.x` 正式版本，`1.0.x` 对该键保留未知；其余四键识别已支持的 `1.0.x`、`1.1.x`、`2.0.x` 正式版本。此条规则不把预发布版本升级为已确认语义，也不回显配置原始值。

## 结论和覆盖

`OBSERVED` 表示语法构造存在，不表示防护有效。没有识别到某条规则所需语法时，AI 应用通常得到 `UNKNOWN`；在项目清点和解析完整且没有相关 AI 证据时可判为 `NOT_APPLICABLE`。L5 未识别支持的流式调用时也可能不适用。诊断、版本未知和未支持语法必须随结果保留。

例如，`system("固定说明").user(prompt)` 修正了“请求参数直接成为 system 指令”的局部模式，却不能证明应用具备抗注入能力。类似地，`.retry(2)` 只确认局部重试次数，不能覆盖本域的租户配额。

JSON 和 Markdown 保留全部评估状态。SARIF `results` 只列 `VIOLATED`，运行属性保存七域状态计数、UNKNOWN 数、未产生评估的域及评估状态；不要用 SARIF 的零条结果推断审计通过。当前 SARIF `executionSuccessful` 跟随报告的 `complete`，有 `UNKNOWN` 或影响完整性的诊断时为 `false`；它不是应用安全结论，也不等同于“进程没有异常退出”。

输入使用 UTF-8 与 Java 21 语法级别；默认排除构建/工具目录和 `src/test`、`src/testFixtures`、`src/integrationTest`。当前 macOS 等缺少锚定目录读取 API 的环境会产生 `FILESYSTEM_RACE_LIMITATION`，要求扫描期间源码保持稳定，完整性保守标为不足。文件摘要只涵盖成功读取的相对路径和字节，不能代表所有目录内容都被审计。

## 参考资料

- [Spring AI Advisors](https://docs.spring.io/spring-ai/reference/api/advisors.html)
- [Spring AI Tools](https://docs.spring.io/spring-ai/reference/api/tools.html)
- [Spring AI RAG](https://docs.spring.io/spring-ai/reference/api/retrieval-augmented-generation.html)
- [Spring Security 方法安全](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [Spring AI 1.0.0 观测配置说明](https://raw.githubusercontent.com/spring-projects/spring-ai/v1.0.0/spring-ai-docs/src/main/antora/modules/ROOT/pages/observability/index.adoc)
- [Spring AI 1.1.0 观测配置说明](https://raw.githubusercontent.com/spring-projects/spring-ai/v1.1.0/spring-ai-docs/src/main/antora/modules/ROOT/pages/observability/index.adoc)
- [OWASP 提示注入风险](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)

这些资料用于解释控制语义；实际支持范围以当前规则实现、测试及本表的限制为准。
