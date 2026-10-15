# AI 安全围栏扫描 MCP Server

对 Java / Spring Boot / Spring AI 与 Python/RAG 应用的源码和配置进行本地静态审计，输出七个控制域的证据、违反项和未评估范围。0.7.0 原生运行于 Java 7/8，提供 19 条 Java 规则、7 条 Python/RAG 规则及 7 条可选银行规则，支持自定义模型网关、Guard 调用关系及 function calling，不提供“安全总分”。

银行模式通过启动参数 `--profile bank-common|bank-customer|bank-internal|bank-all` 选择，分别覆盖共性、客户服务/理财销售辅助、行内知识库/办公研发助手。使用外部操作员合同映射 API 后，追踪数据出站、可信身份、Guard 阻断、事实/适当性及文档/工具权限；缺少映射保留 `UNKNOWN`。配置、样例与限制见 [银行规则包](docs/banking-rules.md)，验收见 [0.4.0 银行验证](docs/banking-verification.md)。默认 `generic` 保留原有 26 条规则选择。0.5.0 支持 [真实 API 映射与 UNKNOWN 三类原因](docs/bank-semantic-mappings.md)，对应验收见 [0.5.0 记录](docs/semantic-mappings-verification.md)。

本项目是 MVP。报告中的 `OBSERVED` 只表示观察到控制或构造，不能解释为安全通过。未发现问题也不能证明防注入效果、鉴权正确性或生产防护有效性。

0.5.1 修复 Python 局部诊断污染与 Java 初始化路径遗漏，补齐 MCP 错误恢复和取消发布一致性，并在单次扫描内复用语法解析。规则集版本为 `java-python-guardrail-v6`，报告结构保持 `1.4`，新增 `mappingCoverage.incompleteSourceFiles` 表示银行适配中被丢弃或未遍历完的源文件数量。发布验收见 [0.5.1 记录](docs/analysis-hardening-verification.md)。

0.6.0 增加 Java 条件分支、Python 流式元素来源和带参数条件的输出边界，按位置保留 UNKNOWN 原因及复核任务。身份信任、文档范围和 Guard 失败语义分别说明所需证据，技术能力缺口与必须人工确认的事项分开处理。规则集为 `java-python-guardrail-v7`，报告结构为 `1.5`；详见 [合同与报告说明](docs/bank-semantic-mappings.md)、[本轮验收记录](docs/unknown-followup-verification.md) 和 [整体技术实现方案](docs/technical-architecture.md)。

0.7.0 将业务分析类及对应测试统一命名为 `Business*`，保留既有 `bank-*` 参数和规则 ID 兼容。新增有界的跨函数参数/返回分析、具体调用点的身份来源与首包相对时序证据；同一函数的其他入口、动态分派和必须人工确认的业务事实继续保留。规则集为 `java-python-guardrail-v8`，报告结构为 `1.6`。首包时序描述本地释放边界与映射检查的关系，不代表客户端网络送达或整体安全通过。详见 [0.7.0 验收记录](docs/business-context-stream-verification.md) 和 [整体技术实现方案](docs/technical-architecture.md)。

## 构建与演示

扫描器运行要求 **Java 7 或以上**；不启动其他 JVM、Python 或目标应用。扫描源码的语法版本与扫描器运行版本彼此独立：在 Java 7 上也能解析受支持的 Java 8 lambda、现代 record/switch 和 Python 3 源码。

构建使用 Maven 3.9+ / Java 21 驱动构建工具，并通过真实 JDK 7 的 `javac` 编译兼容模块，防止误用新 Java API。设置 `JAVA7_HOME`，或在 macOS 使用已注册的 JDK 7。首次构建下载扫描器自身依赖；扫描阶段不下载目标依赖。

```bash
./scripts/build-compatible.sh clean verify
"$JAVA7_HOME/bin/java" -jar compat/target/ai-guardrail-scanner-java7.jar rules
"$JAVA7_HOME/bin/java" -jar compat/target/ai-guardrail-scanner-java7.jar scan /absolute/application --output /absolute/report-root
```

Java 8 运行时可直接用该 JAR，不需重新编译。仓库根模块保留 Java 21 参考实现及其回归测试，`./scripts/mvn.sh verify` 构建的是参考实现；Codex 应加载 `compat/` 的兼容产物。

正式发布使用统一验收入口（操作员工具需要 Python 3.11+，扫描器不需要 Python）：

```bash
python3 scripts/verify-release.py \
  --java7-home /absolute/jdk7 --java8-home /absolute/jdk8 \
  --project /absolute/application --output /absolute/new-verification-directory \
  --profile bank-all --bank-policy /absolute/operator-policy.json
```

可重复 `--project`。该入口执行真实 javac 7 的 `clean verify`、最终 JAR 的双 JVM 全量 JUnit 和 MCP 扫描；校验两种实际运行版本、三格式一致性、取消与错误恢复，并将制品 SHA256 和结果写入 `release-verification.json`。输出目录必须新建或为空。日常 `build-compatible.sh verify` 中 Maven/Surefire 使用构建 JVM，本身不代表双运行时发布验收；只传一个 JVM 的矩阵会被拒绝。

将 `/absolute/application` 替换为待审计项目的绝对路径，报告根目录放在项目之外。两者不能相互包含。每次扫描产生独立扫描 ID 和目录，内含：

- `report.json`：完整的规范结果，包括全部评估状态与诊断。
- `report.md`：中文覆盖表、未评估项、限制和代码位置。
- `results.sarif`：SARIF 2.1.0；仅 `VIOLATED` 进入结果列表，完整性与覆盖状态保留在运行属性中。

`examples/unsafe` 展示可识别的缺陷模式；`examples/safe` 展示部分模式修正；`examples/unknown` 展示依赖版本和外部控制无法确定的情况。这些源码只作为静态扫描输入，不是可直接启动的 Spring 应用。`safe` 目录不表示整套应用通过安全认证，其他控制仍可能是 `UNKNOWN`。

`rules` 将规则目录作为 JSON 写入 stdout；`scan` 输出扫描 ID、报告路径及违反数、未知数与完整性摘要。CLI 退出码：`1` 为发现违反，`2` 为存在未知、分析未完成或执行错误，`130` 为取消；`rules`/帮助正常返回 `0`。静态扫描始终保留未验证范围，不用退出码 `0` 表示安全通过。参数或执行错误会返回非零状态；调用方应同时检查报告和错误输出。

## MCP 接入

使用支持本地 stdio MCP 的客户端，配置完整的 Java 可执行文件、jar、允许扫描的项目根路径和外部报告目录。例如：

```json
{
  "mcpServers": {
    "ai-guardrail-scanner": {
      "command": "/absolute/jdk-7/bin/java",
      "args": [
        "-jar", "/absolute/ai-guardrail-scanner/compat/target/ai-guardrail-scanner-java7.jar",
        "mcp",
        "--allow-root", "/absolute/projects",
        "--output", "/absolute/guardrail-reports"
      ]
    }
  }
}
```

可以重复传入 `--allow-root`。允许目录和报告目录由启动 server 的操作员决定，MCP 请求不能扩大权限。stdout 仅用于 JSON-RPC，日志写入 stderr。

本机 Codex 首次接入记录见 [0.1 验收](docs/codex-integration-20261013.md)；自定义网关、Guard 和 function calling 的升级与两个真实项目复验见 [0.2 验收](docs/custom-gateway-verification.md)。原生 Java 7/8、Python/RAG 见 [0.3 验收](docs/java7-python-verification.md)，Python 软关键字、客户端注入与校验返回值使用见 [0.3.1 验收](docs/python-source-chains-verification.md)。流程完成不代表应用安全通过。

| 工具 | 参数 | 用途 |
| --- | --- | --- |
| `guardrail_rules` | 无 | 查询规则目录与说明 |
| `guardrail_scan_start` | `repository`：绝对项目路径 | 启动扫描并返回扫描 ID |
| `guardrail_scan_status` | `scanId` | 查询状态 |
| `guardrail_scan_cancel` | `scanId` | 请求取消；已经结束的结果不会变更 |
| `guardrail_scan_result` | `scanId`，可选 `format` | 读取结果；格式为 `json`、`markdown`、`sarif`，默认 `json` |

每个 server 同时只执行一个扫描，保留最多 32 个任务，达到上限后拒绝新任务；每次扫描设置 120 秒协作式超时；内存中的报告正文总量最多 64 MiB，达到上限后返回 `SESSION_RESULT_LIMIT`，重新启动 server 可建立新会话。扫描 ID 与任务历史仅在当前进程会话内有效，不支持重启后恢复任务或继续查询旧 ID；成功导出的文件会持久保存。取消或失败不会冒充完成结果。

完整单行的 JSON/UTF-8 解析错误与非法 RPC 包络返回错误响应后继续服务；超长帧仍终止会话。报告先写入私有暂存目录，再与任务状态一起确认发布：取消先被接受则不发布正式报告，发布完成后的取消返回 `COMPLETED`。磁盘发布失败仍可能留下部分正式文件，消费者必须检查任务状态。

结果工具返回状态、格式、内容可信度提示和文件位置；内容超过 512 KiB 时设置 `contentOmitted`，省略内联正文，完整文件仍可在操作员指定的目录读取。调用方应检查该字段，不能把空正文解释为空报告。

## 如何解读报告

| 状态 | 含义 |
| --- | --- |
| `VIOLATED` | 在当前规则明确支持的模式内发现违反证据 |
| `OBSERVED` | 发现某个控制或构造，实际有效性仍需验证 |
| `UNKNOWN` | 当前源码与配置不足以判断，或相关语义不支持 |
| `NOT_APPLICABLE` | 有依据表明当前规则不适用 |

七个控制域为 L1 提示注入、L2 授权与隔离、L3 数据泄露、L4 资源限制、L5 内容审核、L6 审计追踪、L7 输出与执行安全。编号不代表安全等级。完整规则及语法边界见 [规则支持说明](docs/rules.md)。

同一条规则可以输出不同状态的多条评估记录，例如一个调用路径为 `VIOLATED`，另一个为 `UNKNOWN`；发现违反不会隐藏其他路径的未知状态。覆盖表及 CLI 摘要统计的是评估记录，不是独立漏洞总数或代码位置数。评估的主证据列表最多导出 16 个位置，通用规则超限会产生 `RESULT_LIMIT` 或 `PYTHON_RESULT_LIMIT`，并将完整性标为不足。银行规则另有最多 128 项的逐位置评估与独立 Guard 控制复核列表，截断会显式标记，详见合同与报告说明。

配置声明或函数名本身不能证明围栏有效。同步调用的控制也不能自动证明流式调用受保护。扫描器无法确定外部网关限额、存储 ACL、自定义安全服务或动态 Bean/AOP 的作用时，应当保留 `UNKNOWN`，由人工补充证据。

## 执行边界与数据处理

- 扫描只读解析源码与配置，不运行目标的 Maven、Gradle、应用、注解处理器或项目脚本，不下载目标依赖。Maven XML 禁用 DTD 和外部实体，不执行 XML 中的构建或插件声明。
- 不调用模型、不发送源码到远程服务。可选 LLM 语义复核属于后续扩展，0.7.0 未实现。
- Java/Python 均使用固定版本的 ANTLR 语法解析，输入按 UTF-8 解码；解析失败或超预算的文件不使用部分语法结果。默认排除 `.git`、构建/依赖/工具目录、Python 虚拟环境与缓存，以及 Java/Python 测试目录；任意目录名只要具有 `pyvenv.cfg` 标记也按虚拟环境排除，`site-packages` 按依赖排除。排除项记录在 `EXCLUDED_SCOPE` 中。配置只选择 `pom.xml`、`build.gradle[.kts]`、`gradle.properties` 与 `application*.properties/yml/yaml`，其他 XML/YAML 不纳入当前配置规则。
- 默认不跟随符号链接，并拒绝扫描范围逃逸和输入/输出目录重叠。单次最多清点 200,000 个目录条目、选择 10,000 个源码/配置文件，单文件 2 MiB、读取总量 32 MiB；预算耗尽或解析失败会留下诊断，不会计为通过。
- 兼容实现使用不跟随链接的文件打开、路径、文件身份和修改信息校验，但不提供锚定目录读取或原子快照。每次记录 `FILESYSTEM_RACE_LIMITATION`，扫描期间源码树须保持稳定。
- 版本按包含 AI 引用的源码或明确 AI 配置所属模块核实，不能借用兄弟模块版本。无法确定模块的 Spring AI 依赖时，全项目版本状态保守降为 `UNKNOWN`；首期不输出逐源码版本。详细 Maven/Gradle 支持范围见规则说明。
- 报告只包含受控说明、相对文件位置和摘要，不导出源码摘录、原始提示词或模型响应。文件名和路径本身仍可能透露业务信息，报告应保存在操作员控制的目录。
- 源文件摘要覆盖成功读取文件的相对路径及字节；未读取、被跳过或超预算文件不在摘要内。已经读入但解析失败的文件仍进入摘要。摘要不是整个仓库完整性的证明。
- 报告目录必须新建或为空，不覆盖既有文件，不接受目录链中的符号链接。文件通过同文件系统硬链接原子发布，因此报告文件系统需要支持硬链接；不支持时导出失败。已发布文件不会被覆盖，失败可能留下部分文件，不能据此认定扫描完成。

自定义网关规则使用类型、HTTP 协议和有限跨方法来源关系，应用类名及方法名不作为模型或安全控制的判据。调用图最多索引 30,000 个方法、100,000 个调用，每次分派最多 16 个候选，继承与成员查找最多 8 层。方法、调用、候选及总操作预算耗尽会留下诊断，无法解析的深度关系保留未知。接口和可覆写方法的候选关系不等于部署中的实际 Bean。模型返回、SSE 回调和工具分派分别追踪；普通 HTTP、JSON 解析、方法名带 Guard 或多传一个 user 参数均不能证明安全。

Java 静态块、实例块与字段初始化按各自声明顺序分析，字段控制证明仅在所属初始化执行体内使用，不跨构造器、其他对象或静态/实例边界传播。接口常量等尚未建模位置的调用和初始化中的延迟 lambda 保留 UNKNOWN 候选。Python 局部不支持沿实际路径传播，不使无关函数的已确定违规消失；整文件被丢弃时另记覆盖缺口。Java/Python 的语法缓存只在单次扫描内使用，通用与银行分析各自保留独立状态和预算。

这仍不是完整跨方法数据流，也没有完整分析 Spring Security `SecurityFilterChain`、方法安全及业务授权。源码与配置仅覆盖表中列出的模式。静态审计不能测量围栏抗攻击率，也不涵盖模型权重后门、在线鲁棒性或真实业务恢复效果；这些结论需要真实应用样例和运行时验证。

## Java 21 参考实现的开发与验证

```bash
./scripts/mvn.sh -Dtest=ReportWriterTest test
./scripts/mvn.sh verify
./scripts/mvn.sh -Dtest=McpProtocolTest -Dscanner.jar=target/ai-guardrail-scanner.jar test
```

`verify` 执行规则、文件与权限边界、生命周期、报告重新读取和基于测试 classpath 的 MCP 协议测试，并打包 jar。紧随其后的命令显式指定打包产物，才会通过真实 `java -jar` 子进程验证 stdio MCP。首次 144 项测试与示例结果见 [0.1 验证记录](docs/verification.md)，0.2 结果见 [历史验证记录](docs/custom-gateway-verification.md)。0.3 的构建、实际 JDK 7/8 执行及 Codex 复验命令见 [兼容验收记录](docs/java7-python-verification.md)。项目设计与实施计划见 `docs/superpowers/`。
