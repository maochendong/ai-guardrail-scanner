# 规则支持说明 · 0.3.1

本版本包含 26 条规则，覆盖七个控制域：19 条 Java 规则（11 条 Spring AI、5 条自定义网关/Guard、3 条 function calling）和 7 条 Python/RAG 规则。清点到 Java 源码或支持的配置时执行 Java 规则，清点到 Python 源码时执行 Python 规则；混合仓库可同时得到两组结果。它们检查明确列出的 Java/Python 语法、有限源码调用关系及配置模式，不提供全程序数据流或生产安全保证。规则目录也可通过 CLI `rules` 或 MCP `guardrail_rules` 获取。

## 共同前提

当前规则通过 AST 的明确类型声明、导入及限定名识别 API，没有调用符号求解 API。新增源码调用图索引字段/参数类型、源内返回类型、有限接口候选和 record 访问器；不推断实际 Spring Bean、反射或依赖内部实现。0.3 兼容产物使用 ANTLR 语法与有界源码索引，不依赖 JavaParser 或外部编译器的符号求解。根模块保留的 0.2 参考实现与兼容实现不是同一解析器。扫描不会执行目标构建或下载依赖。

原有 Spring AI 数据来源规则限于同一方法中的直接表达式、字符串拼接及未被重新赋值的局部别名；未知 `map`、`flatMap` 转换会中断来源关系。新增网关模型提供有限返回/参数/Consumer 与 BiConsumer 回调传播，function calling 额外关联有限 record 和分派参数；跨参数汇总、混合返回及候选分派不能成为确定来源。SSE 字段聚合只提供候选来源。字段变化、复杂分支、自定义转换及动态代理通常保留为 `UNKNOWN`。遇到未支持的封装也可能无法识别 AI 路径。

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
| `AI-L7-001` | L7 输出执行 | 模型原始输出或未修改局部别名进入明确 `Runtime.exec` 或 SQL 文本：`VIOLATED`；`ProcessBuilder` 检查可执行程序首参，以及已识别 shell 与匹配 `-c`、`/c`、`-Command` 标志组合中的命令文本 | 固定程序的独立数据参数不据此报命令执行缺陷。自定义允许列表、跨方法校验、HTML 输出、所有 SQL API 及回滚行为不在已验证范围 |

`AI-L3-002` 只检查 `application*.properties`、`application*.yml`、`application*.yaml` 中以下五个键：

- `spring.ai.chat.client.observations.log-prompt`
- `spring.ai.chat.client.observations.log-completion`
- `spring.ai.chat.observations.log-prompt`
- `spring.ai.chat.observations.log-completion`
- `spring.ai.tools.observations.include-content`

YAML 支持嵌套键、点分隔键及多文档的安全树读取；不会执行 tag，也不会把别名或未解析结构当作已确认布尔值。`chat.client.observations.log-completion` 需要已支持的 `1.1.x` 或 `2.0.x` 正式版本，`1.0.x` 对该键保留未知；其余四键识别已支持的 `1.0.x`、`1.1.x`、`2.0.x` 正式版本。此条规则不把预发布版本升级为已确认语义，也不回显配置原始值。

## 自定义模型网关、Guard 与 Function Calling

新增规则不匹配项目名、包名、应用类名或业务方法名。HTTP 客户端类型、公开协议字段和源码关系必须共同提供证据；注释、字符串中的 AI/Guard 字样及普通 HTTP 请求不足以确认模型来源。

| 规则 | 控制域 | 支持的证据 | 未证明的事项 |
| --- | --- | --- | --- |
| `AI-GW-001` | L1 | 明确 OkHttp POST `/chat/completions` 协议；RestClient POST 的协议地址或关联请求/响应 DTO 形状；`java.net.http.HttpClient.send` 与 `BodyHandlers.ofString`；源码返回委托、接口候选；OkHttp SSE 监听器到 Consumer/BiConsumer 回调：`OBSERVED` | 实际服务行为、运行时 Bean、全部协议和转换。未识别网关且 Java 分析没有相关不确定性时可为 `NOT_APPLICABLE`，其余保留 `UNKNOWN` |
| `AI-GW-002` | L3 | 已识别模型响应进入明确 SLF4J 参数，确定来源为 `VIOLATED`，候选来源为 `UNKNOWN` | 是否包含敏感内容、外部日志脱敏及日志访问权限 |
| `AI-GUARD-001` | L1 | 可达网关的方法内，与模型实参共享未改局部声明的自定义判定，用于调用前局部提前退出：`OBSERVED` | 输入与判定的业务关系、拒绝极性、安全语义和全部路径 |
| `AI-GUARD-002` | L7 | 模型来源值传入源内布尔判定或布尔结果 record/普通结果对象，其结果被局部 if/return/throw 消费：`OBSERVED`；忽略或改写结果保留 `UNKNOWN` | 判定是否有效、回滚是否完成、跨框架代理与完整控制流 |
| `AI-GUARD-003` | L5 | 同一局部语句块中发送模型值与消费判定的先后顺序：`OBSERVED`；其他顺序关系为 `UNKNOWN` | 未知安全语义的自定义判定不能单凭后置顺序升级 `VIOLATED`；同步判定不能证明流式全覆盖 |
| `AI-FC-001` | L2 | 模型来源 JSON 的成对 `name/arguments` 或 `tool/args` → 有限 record/参数关系 → 本地分派；固定字符串 switch、Map 查找/成员检查为 `OBSERVED`；确定模型字段进入命令文本、进程目标或反射目标为 `VIOLATED` | 固定注册表与未知名称拒绝是否覆盖所有入口、动态插件、分支支配和每个工具的权限 |
| `AI-FC-002` | L7 | 参数提取、Jackson 解码、已知 Validator/JsonSchema 调用分别记录 `OBSERVED` | JSON 解析、工具 schema 声明或调用 validate 均不证明拒绝结果被消费；类型、范围和业务约束保留 `UNKNOWN` |
| `AI-FC-003` | L2 | 分派实参中模型字段与其他实参分离：`OBSERVED` | 不以 user/tenant 等变量名推断认证主体；身份可信度、授权和资源归属仍是 `UNKNOWN` |

普通结果对象仅支持源码可见、无参且直接返回 boolean 字段的访问器，不按 is/get 等方法名推断；观察到结果重赋值、字段写入或中间调用时不确认原结果已消费。

每条新增规则独立保留 `UNKNOWN`，不会因为局部观察而清除未知路径。调用图上限为 30,000 个方法、100,000 个调用、16 个分派候选及 2,000,000 次索引操作；继承与成员查找最多 8 层，表达式解析最多 24 层。网关传播最多 10 轮、600,000 次来源分析操作。Java 规则引擎（含 function calling）共享 300,000 次分析预算。预算与不支持的关系会造成覆盖不足，不能解释为无风险。

目前不完整覆盖 agent 循环预算、所有 SDK 的工具 schema、动态工具插件、工具结果回灌提示注入、跨服务工具执行、每个工具的业务副作用及所有业务授权。原有 `@Tool` 规则仍独立运行。报告 schema 为 `1.2`、规则集为 `java-python-guardrail-v3.1`，包含 `project.aiProtocols`、`project.customGatewayMethods`、`project.languages`、`project.pythonFiles` 和实际 `runtime.javaVersion`；识别自定义协议不会伪造 Spring AI 版本。

## Python / RAG

Python 源码由扫描器进程内的 Python 3 语法解析器处理，不安装目标依赖，不调用 Python 解释器，不执行 import、装饰器或项目代码。公开 SDK 身份、参数结构及有界来源关系提供证据；类名、项目名或注释中的关键词不能证明模型或围栏存在。

| 规则 | 控制域 | 检查范围 |
| --- | --- | --- |
| `AI-PY-001` | L1 | 模型调用、构造器注入的有限客户端来源与 RAG 输入边界；提示注入防护效果保留未知 |
| `AI-PY-002` | L2 | 检索与租户隔离构造；存储 ACL、身份归属和服务端授权保留未知 |
| `AI-PY-003` | L3 | 模型来源值进入日志，区分确定来源与候选关系 |
| `AI-PY-004` | L4 | 可识别的调用限制与预算构造；配额执行效果保留未知 |
| `AI-PY-005` | L5 | 模型流式输出与审核相关结构，未知自定义判定不升级为确定违规 |
| `AI-PY-006` | L6 | 可见审计构造与剩余审计要求；日志存在不证明全链路追踪 |
| `AI-PY-007` | L7 | 输出、工具调用或动态执行的有限来源关系；源码可见消费者的返回结果进入条件或返回/输出值可为 `OBSERVED`，校验语义仍未知 |

0.3.1 支持 `case` 在普通名称位置作为软关键字，同时保留 match/case 语句的语法限制。客户端来源按有限构造器/方法调用上下文绑定位置、关键字与可见默认参数，实例和调用各自保留上下文。拆包、不匹配参数、字段覆盖、装饰器及混合返回不能升级为确定来源。

消费者结果关系与原始模型文本分开追踪。源码可见调用接收模型内容，返回值或字段与模型来源存在已解析关系，并被局部条件或返回/输出值使用时，记录独立的 `consumer-result` 观察；不会凭方法名、结果字段名、JSON 解码或布尔返回认定安全校验有效。常量结果、无关字段、结果被忽略、被覆盖或无法关联时不能据此证明围栏。流式释放与后续调用的源码顺序仍只提供局部观察。

Python 来源分析最多保留 2,048 个调用上下文、执行 500,000 次分析操作，递归深度上限为 64。超限记录 `PYTHON_FLOW_LIMIT`，不会按已完成覆盖处理。每项评估最多导出 16 个证据位置，截断时记录 `PYTHON_RESULT_LIMIT`；调用来源解析成功也不代表所有相关证据已完整导出。

Python 是动态语言。猴子补丁、复杂别名、跨服务关系和不支持的表达式不会按名称猜测。f-string 的内部表达式不做完整污点传播，保留诊断与未知范围。AST 解析成功也不表示已证明全部调用或控制流。

## 结论和覆盖

`OBSERVED` 表示语法构造存在，不表示防护有效。没有识别到某条规则所需语法时，AI 应用通常得到 `UNKNOWN`；在项目清点和解析完整且没有相关 AI 证据时可判为 `NOT_APPLICABLE`。L5 未识别支持的流式调用时也可能不适用。诊断、版本未知和未支持语法必须随结果保留。

例如，`system("固定说明").user(prompt)` 修正了“请求参数直接成为 system 指令”的局部模式，却不能证明应用具备抗注入能力。类似地，`.retry(2)` 只确认局部重试次数，不能覆盖本域的租户配额。

JSON 和 Markdown 保留全部评估状态。SARIF `results` 只列 `VIOLATED`，运行属性保存七域状态计数、UNKNOWN 数、未产生评估的域及评估状态；不要用 SARIF 的零条结果推断审计通过。0.3 兼容产物始终将 `complete`、`securityVerified` 与 SARIF `executionSuccessful` 设为 `false`，明确保留有限静态分析的覆盖缺口。扫描任务是否正常结束以 MCP 的 `COMPLETED` 状态为准，不能把该状态解释为安全通过。

兼容产物以 Java 7 API 和字节码运行，Java 语法包含已测试的 Java 7/8 与现代 record、switch 等构造；这不代表支持所有新版语言特性。输入按 UTF-8 解码，超预算或解析错误会丢弃该文件的部分语法结果。默认排除构建、依赖、工具、虚拟环境及测试目录。兼容产物使用路径和文件身份检查，不提供原子快照或锚定目录读取，始终产生 `FILESYSTEM_RACE_LIMITATION`，要求扫描期间源码保持稳定。文件摘要只涵盖成功读取的相对路径和字节，不能代表所有目录内容都被审计。

## 参考资料

- [Spring AI Advisors](https://docs.spring.io/spring-ai/reference/api/advisors.html)
- [Spring AI Tools](https://docs.spring.io/spring-ai/reference/api/tools.html)
- [Spring AI RAG](https://docs.spring.io/spring-ai/reference/api/retrieval-augmented-generation.html)
- [Spring Security 方法安全](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [Spring AI 1.0.0 观测配置说明](https://raw.githubusercontent.com/spring-projects/spring-ai/v1.0.0/spring-ai-docs/src/main/antora/modules/ROOT/pages/observability/index.adoc)
- [Spring AI 1.1.0 观测配置说明](https://raw.githubusercontent.com/spring-projects/spring-ai/v1.1.0/spring-ai-docs/src/main/antora/modules/ROOT/pages/observability/index.adoc)
- [OWASP 提示注入风险](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)

这些资料用于解释控制语义；实际支持范围以当前规则实现、测试及本表的限制为准。
