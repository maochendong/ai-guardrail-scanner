# MVP 验证记录

验证日期：2026-10-13。环境：macOS、Java 21、Maven 3.9.6。以下结果来自本地源码与实际打包产物；未对生产应用开展运行时安全验证。

## 构建与自动化测试

```bash
./scripts/mvn.sh -q clean verify
./scripts/mvn.sh -q -Dtest=McpProtocolTest -Dscanner.jar=target/ai-guardrail-scanner.jar test
```

完整构建成功，144 项测试通过，无失败、错误或跳过。之后将同一套 4 项 MCP 协议测试重新指向打包 JAR，全部通过；这 4 项是重复执行，不计作额外独立测试。

| 测试集 | 用例数 | 主要验证内容 |
| --- | ---: | --- |
| ProjectLoaderTest | 44 | 清点预算、符号链接、UTF-8/Java 解析、XML 外部实体、版本展开预算、多模块版本归属、纯配置识别 |
| RuleEngineTest | 58 | 局部来源与危险边界、同名 API 排除、Advisor 绑定、默认控制未知、流式顺序及多状态证据 |
| ConfigurationRulesTest | 27 | 五个开关、版本边界、properties/YAML、多文档与 profile、重复键、占位符、tag/alias、解析预算 |
| ScanServiceTest | 5 | 允许路径、输入输出重叠、取消竞态、任务上限、超时失败、终态不变和结果缓存 |
| McpProtocolTest | 4 | 真实子进程握手和五工具、参数校验、扫描取结果、取消、EOF 清理、非法/超大帧退出 |
| ReportWriterTest | 6 | 三种格式重读与状态一致、相对位置、转义、无原文摘录、符号链接与禁止覆盖 |

协议验证通过 `java -jar` 子进程执行，检查 stdout 为协议 JSON；未在用户的 MCP 客户端中完成安装或会话配置。

## 实际 JAR 扫描示例

在项目根目录执行以下命令，将 `unsafe` 分别替换为 `safe` 和 `unknown` 可复现三组输入。Java 命令需指向 Java 21。

```bash
java -jar target/ai-guardrail-scanner.jar scan "$PWD/examples/unsafe" --output "$PWD/target/verification/unsafe"
```

| 输入 | 退出码 | VIOLATED | OBSERVED | UNKNOWN | complete |
| --- | ---: | ---: | ---: | ---: | --- |
| examples/unsafe | 1 | 5 | 0 | 7 | false |
| examples/safe | 2 | 0 | 2 | 9 | false |
| examples/unknown | 2 | 0 | 0 | 11 | false |

数字是评估记录数，不能解释为独立漏洞数量。同一规则可能同时产生违反和未知记录。unsafe 中识别到不可信 system 输入、固定会话键、原始日志、无限重试和原始内容记录配置。safe 仅修正部分支持模式，仍有未核实控制。

独立重新读取三组 `report.json`、`report.md`、`results.sarif`：JSON 可解析；Markdown 在实体解码后包含对应规则；SARIF 2.1.0 的违反规则与 JSON 一致；全部包含七域评估和 `securityVerified=false`。这项检查不等同于外部 SARIF 消费端兼容性认证。

本次输出摘要保存在 `target/verification/summary.json`，各报告存于相应扫描 ID 目录；它们是构建目录产物，执行 Maven clean 会删除。

## 当前结论与限制

可用于本地源码与配置模式检查，以及 stdio MCP 集成试用。不得据此宣布生产安全准入通过。

- 实现了 11 条有界规则，没有完整跨方法控制流、业务授权、全链路审计、租户配额、语义敏感内容或回滚有效性验证。
- 当前 macOS 不提供所需的锚定目录安全读取 API，三组输入均记录 `FILESYSTEM_RACE_LIMITATION`，要求扫描期间保持源码树稳定。没有将回退读取宣称为并发敌对文件系统隔离。
- 未知输入还记录模块版本及 Spring AI 版本未知；这些情况不会自动计作通过。
- 不执行目标代码，不调用 LLM，不上传源码。演示源码不是可启动的 Spring 应用，也未被当作真实业务应用验收。
- 只完成本地构建及验证；未发布到 Registry、未部署远程服务。
