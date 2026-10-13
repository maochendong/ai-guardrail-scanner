# AI 安全围栏扫描 MCP Server

对 Java / Spring Boot / Spring AI 应用的源码与配置进行本地静态审计，输出七个控制域的证据、违反项和未评估范围。首期通过 11 条有限范围规则检查 Java AST 与部分配置，不提供“安全总分”。

本项目是 MVP。报告中的 `OBSERVED` 只表示观察到控制或构造，不能解释为安全通过。未发现问题也不能证明防注入效果、鉴权正确性或生产防护有效性。

## 构建与演示

要求 Java 21、Maven 3.9+。脚本优先使用本机 Homebrew Java 21，没有该路径时使用当前 Java 环境，并通过项目内 Maven 配置访问依赖仓库；不修改系统 Java 设置。使用其他 JDK 时，可显式设置 `JAVA_HOME` 后执行 `mvn -s .mvn/settings.xml verify`。首次构建需要下载扫描器依赖；扫描阶段不下载目标依赖。

```bash
./scripts/mvn.sh verify
java -jar target/ai-guardrail-scanner.jar rules
java -jar target/ai-guardrail-scanner.jar scan /absolute/application --output /absolute/report-root
```

将 `/absolute/application` 替换为待审计项目的绝对路径，报告根目录放在项目之外。两者不能相互包含。每次扫描产生独立扫描 ID 和目录，内含：

- `report.json`：完整的规范结果，包括全部评估状态与诊断。
- `report.md`：中文覆盖表、未评估项、限制和代码位置。
- `results.sarif`：SARIF 2.1.0；仅 `VIOLATED` 进入结果列表，完整性与覆盖状态保留在运行属性中。

`examples/unsafe` 展示可识别的缺陷模式；`examples/safe` 展示部分模式修正；`examples/unknown` 展示依赖版本和外部控制无法确定的情况。这些源码只作为静态扫描输入，不是可直接启动的 Spring 应用。`safe` 目录不表示整套应用通过安全认证，其他控制仍可能是 `UNKNOWN`。

`rules` 将规则目录作为 JSON 写入 stdout；`scan` 输出扫描 ID、报告路径及违反数、未知数与完整性摘要。CLI 退出码：`0` 为没有违反且评估完成，`1` 为发现违反，`2` 为没有违反但存在未知或分析未完成，`130` 为取消。参数或执行错误会返回非零状态；调用方应同时检查报告和错误输出。

## MCP 接入

使用支持本地 stdio MCP 的客户端，配置完整的 Java 可执行文件、jar、允许扫描的项目根路径和外部报告目录。例如：

```json
{
  "mcpServers": {
    "ai-guardrail-scanner": {
      "command": "/absolute/jdk-21/bin/java",
      "args": [
        "-jar", "/absolute/ai-guardrail-scanner/target/ai-guardrail-scanner.jar",
        "mcp",
        "--allow-root", "/absolute/projects",
        "--output", "/absolute/guardrail-reports"
      ]
    }
  }
}
```

可以重复传入 `--allow-root`。允许目录和报告目录由启动 server 的操作员决定，MCP 请求不能扩大权限。stdout 仅用于 JSON-RPC，日志写入 stderr。

| 工具 | 参数 | 用途 |
| --- | --- | --- |
| `guardrail_rules` | 无 | 查询规则目录与说明 |
| `guardrail_scan_start` | `repository`：绝对项目路径 | 启动扫描并返回扫描 ID |
| `guardrail_scan_status` | `scanId` | 查询状态 |
| `guardrail_scan_cancel` | `scanId` | 请求取消；已经结束的结果不会变更 |
| `guardrail_scan_result` | `scanId`，可选 `format` | 读取结果；格式为 `json`、`markdown`、`sarif`，默认 `json` |

每个 server 同时只执行一个扫描，保留最多 32 个任务，达到上限后拒绝新任务；每次扫描设置 120 秒协作式超时。扫描 ID 与任务历史仅在当前进程会话内有效，不支持重启后恢复任务或继续查询旧 ID；成功导出的文件会持久保存。取消或失败不会冒充完成结果。

结果工具返回状态、格式、内容可信度提示和文件位置；内容超过 512 KiB 时设置 `contentOmitted`，省略内联正文，完整文件仍可在操作员指定的目录读取。调用方应检查该字段，不能把空正文解释为空报告。

## 如何解读报告

| 状态 | 含义 |
| --- | --- |
| `VIOLATED` | 在当前规则明确支持的模式内发现违反证据 |
| `OBSERVED` | 发现某个控制或构造，实际有效性仍需验证 |
| `UNKNOWN` | 当前源码与配置不足以判断，或相关语义不支持 |
| `NOT_APPLICABLE` | 有依据表明当前规则不适用 |

七个控制域为 L1 提示注入、L2 授权与隔离、L3 数据泄露、L4 资源限制、L5 内容审核、L6 审计追踪、L7 输出与执行安全。编号不代表安全等级。完整规则及语法边界见 [规则支持说明](docs/rules.md)。

同一条规则可以输出不同状态的多条评估记录，例如一个调用路径为 `VIOLATED`，另一个为 `UNKNOWN`；发现违反不会隐藏其他路径的未知状态。覆盖表及 CLI 摘要统计的是评估记录，不是独立漏洞总数或代码位置数。每条评估最多导出 16 个位置，超过上限会产生 `RESULT_LIMIT`，并将完整性标为不足。

配置声明或函数名本身不能证明围栏有效。同步调用的控制也不能自动证明流式调用受保护。扫描器无法确定外部网关限额、存储 ACL、自定义安全服务或动态 Bean/AOP 的作用时，应当保留 `UNKNOWN`，由人工补充证据。

## 执行边界与数据处理

- 扫描只读解析源码与配置，不运行目标的 Maven、Gradle、应用、注解处理器或项目脚本，不下载目标依赖。Maven XML 禁用 DTD 和外部实体，不执行 XML 中的构建或插件声明。
- 不调用模型、不发送源码到远程服务。可选 LLM 语义复核属于后续扩展，0.1.0 未实现。
- Java 解析使用 Java 21 语法级别，输入按 UTF-8 解码；不支持的语法或编码会留下诊断。默认排除 `.git`、`target`、`build`、`node_modules`、`.idea`、`.gradle`，以及 `src/test`、`src/testFixtures`、`src/integrationTest`，范围排除记录在 `EXCLUDED_SCOPE` 中。
- 默认不跟随符号链接，并拒绝扫描范围逃逸和输入/输出目录重叠。单次最多清点 200,000 个目录条目、选择 10,000 个源码/配置文件，单文件 2 MiB、读取总量 32 MiB；预算耗尽或解析失败会留下诊断，不会计为通过。
- 优先使用锚定目录的安全读取。部分平台或文件系统，包括当前 macOS 环境，不能提供该 API，会记录 `FILESYSTEM_RACE_LIMITATION` 并使完整性不足；此时退回路径、文件身份和修改信息校验，要求扫描期间源码树保持稳定。即使目录 API 可用，也不代表获得了跨文件原子快照。
- 版本按包含 AI 引用的源码或明确 AI 配置所属模块核实，不能借用兄弟模块版本。无法确定模块的 Spring AI 依赖时，全项目版本状态保守降为 `UNKNOWN`；首期不输出逐源码版本。详细 Maven/Gradle 支持范围见规则说明。
- 报告只包含受控说明、相对文件位置和摘要，不导出源码摘录、原始提示词或模型响应。文件名和路径本身仍可能透露业务信息，报告应保存在操作员控制的目录。
- 源文件摘要覆盖成功读取文件的相对路径及字节；未读取、被跳过或超预算文件不在摘要内。已经读入但解析失败的文件仍进入摘要。摘要不是整个仓库完整性的证明。
- 报告目录必须新建或为空，不覆盖既有文件，不接受目录链中的符号链接。文件通过同文件系统硬链接原子发布，因此报告文件系统需要支持硬链接；不支持时导出失败。已发布文件不会被覆盖，失败可能留下部分文件，不能据此认定扫描完成。

规则使用局部 AST 声明、导入和有限来源关系，没有完整跨方法数据流，也没有完整分析 Spring Security `SecurityFilterChain`、方法安全及业务授权。源码与配置仅覆盖表中列出的模式。静态审计不能测量围栏抗攻击率，也不涵盖模型权重后门、在线鲁棒性或真实业务恢复效果；这些结论需要真实应用样例和运行时验证。

## 开发与验证

```bash
./scripts/mvn.sh -Dtest=ReportWriterTest test
./scripts/mvn.sh verify
./scripts/mvn.sh -Dtest=McpProtocolTest -Dscanner.jar=target/ai-guardrail-scanner.jar test
```

`verify` 执行规则、文件与权限边界、生命周期、报告重新读取和基于测试 classpath 的 MCP 协议测试，并打包 jar。紧随其后的命令显式指定打包产物，才会通过真实 `java -jar` 子进程验证 stdio MCP。本次构建、144 项测试与示例结果见 [验证记录](docs/verification.md)。项目设计与实施计划见 `docs/superpowers/`。
