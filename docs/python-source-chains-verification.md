# 0.3.1 Python 语法与客户端、校验调用链验收

本轮范围是修复普通 `case` 标识符的解析、补齐 Python 构造器注入的客户端来源，以及观察模型内容消费者返回值的后续使用。规则仍依据公开 SDK、源码绑定和调用关系，不使用目标项目名或业务方法名作为判据。

## 最终验收 · 2026-10-14

0.3.1 已通过真实 JDK 7u79、JDK 8u40 **各 166 项测试**，构建测试亦为 166 项，失败、错误、跳过均为 0。较 0.3.0 增加 52 项通用回归，包括 6 项语法、14 项来源与结果链、32 项独立上下文隔离测试。打包的 1,005 个 class（包括运行依赖）主版本均不超过 51。Java 21 参考模块未修改，本轮不把历史参考测试计入验收。

同一最终 JAR 在两套 JVM 上分别扫描三个项目，共 6 次；规则状态、位置证据、诊断及源码摘要一致。安装后，真实 Codex app-server 从持久配置加载 **0.3.1 / 5 个工具 / 26 条规则**，在 Java `1.7.0_79` 上再次完成三个项目扫描。三种格式的文件与工具返回正文相符，Codex 报告与原生矩阵证据逐项一致。

| 项目 | Java / Python / 配置文件 | 模型调用边界 | VIOLATED | OBSERVED | UNKNOWN |
| --- | ---: | ---: | ---: | ---: | ---: |
| CodeBuddy | 249 / 1 / 5 | 4 | 1 | 4 | 25 |
| wm-sales-atlas-analysis | 217 / 40 / 2 | 1 | 0 | 5 | 25 |
| 蒸馏小可乐 | 0 / 60 / 0 | 8 | 0 | 4 | 7 |

统计对象是评估记录，不是漏洞数或通过率；两个 Java 项目另各有 1 条 `NOT_APPLICABLE`。所有项目的纳入文件数和源码摘要与 0.3.0 相同，目标仓库 HEAD 与既有工作区状态摘要也未变。本轮只读解析目标源码，没有启动目标应用、执行构建、Python import 或数据库操作。

## 覆盖变化与剩余限制

- wm：两个 Python 文件现在均完整解析，`PYTHON_PARSE_FAILED` 消失，40 个 Python 文件没有解析失败诊断。Java 网关、Guard、function calling 的原有观察结果保留。
- 蒸馏小可乐：原有 7 个 SDK 调用位置全部保留，新增 `src/rag/validator.py:80`，合计 8 个；`PYTHON_UNRESOLVED_MODEL_CALL` 消失。客户端来源证据包括 `src/llm.py:26、38` 的 SDK 构造、`src/rag/generator.py:67` 与 `src/rag/validator.py:67` 的字段来源；运行时替代注入仍为候选关系。
- 校验结果链：新增独立 `AI-PY-007 / OBSERVED`，包括 `pipeline.py:212、225` 的内容消费、`:215` 的条件使用、`:251` 的返回，以及 `:346` 消费到 `:370` 的 yield。`validator.py:93` 的结果构造和返回也有来源证据。该观察保留全部 7 条 Python `UNKNOWN`。
- CodeBuddy：原有 4 个网关边界和 function calling 证据保留；`DeepSeekClient.java:216、258` 的模型响应日志路径仍构成 1 条 `AI-GW-002 / VIOLATED` 评估，并不证明敏感信息实际泄露。
- 三个项目均没有 Python 解析或来源分析预算耗尽诊断。f-string 内部表达式、动态分派、外部包、安全语义及文件系统快照限制继续保留；wm 另有未跟随的符号链接。
- RAG 增加的来源证据使部分 `UNKNOWN` 汇总超过每项 16 个位置，报告明确记录 `PYTHON_RESULT_LIMIT`。独立 L1 来源观察的 14 个位置与 L7 结果链的 13 个位置均未截断。CodeBuddy 既有的 `RESULT_LIMIT` 也仍保留。

## 可泛化机制与误报边界

按源码作用域绑定构造器和方法的有限位置、关键字及默认参数，实例、调用位置与调用方上下文各自保存 memo，避免把另一个实例的客户端或另一次调用的模型内容混入当前路径。字段写入、别名改写、拆包、缺失必需参数、混合返回和装饰器保留候选或未知，不会据此推断确定的原始输出执行缺陷。

消费者返回值与原始模型文本分开追踪；只有返回值或字段和模型来源有已解析关系，且后续进入条件、返回或输出，才记录 `consumer-result`。常量返回、无关字段、结果忽略或被覆盖均有负例。包装函数在相关调用上下文内只分析一次结果使用，保留既有 2,048 上下文、500,000 操作、64 层深度上限；超限继续产生诊断。

最终独立审查发现的缺失必需参数误报先对旧 JAR 复现失败，再补一行候选处理并通过回归；随后重新构建、运行全部测试及六次扫描。通用实现和验收脚本经检查无目标项目名、类名或业务方法选择器。验收脚本按语言和显式选项检查解析、来源及结果链，不按项目名分支。

## 语法根因与通用修复

wm 的 `scripts/harnesslib/documents.py` 和 `scripts/harnesslib/reports.py` 使用了合法的 `case` 循环或解包变量。上游语法的 `name` 已接纳 `_`、`match`，但遗漏 `case`。修复只为该产生式增加一个软关键字名称，没有放开所有关键字，也没有修改目标源码。[Python 软关键字规范](https://docs.python.org/3/reference/lexical_analysis.html#soft-keywords)

新增六项语法回归覆盖普通名称、参数、属性、导入别名、循环解包、真正的 match/case、非法 case 语句和 SDK 变量重命名。旧 JAR 出现四个预期失败；修复后的新六项加原有二十八项 Python 测试，在真实 JDK 7u79/8u40 各通过三十四项。两个真实文件的独立 Java 7 解析均为 0 错误；这项阶段验证与后续最终全套测试分别记录。

阶段证据位于 `scan-results/python-syntax-20261014/`：`red-junit.log`、两份 `*-green-junit.log` 和 `green-target-parser.log`。目标源文件仅作解析输入，没有执行 Python import 或应用代码。

## 安装与 Codex 验证

安装文件为 `/Users/Darkknight/.local/share/ai-guardrail-scanner/0.3.1/ai-guardrail-scanner.jar`，SHA-256：

```text
60a126be654ab46e5f95009a11751ba9fe621f3fa5f51e1c96af8c537813f583
```

Codex 配置仅替换本 server 的 JAR 路径；Java 7 启动命令、堆上限、允许根目录及所有其他配置保持原样，已进行字节和解析后 TOML 对比。备份为 `/Users/Darkknight/.codex/backups/config.before-ai-guardrail-v031-20261014-102639.toml`。0.3.0 JAR 保留，回退时只恢复该 server 的旧 JAR 路径，避免覆盖其他设置的后续变化。

新进程接入已实际验证；配置变更不会替换既有 Java 进程中的代码。已有 MCP 连接需重连或重启 Codex，才能确保使用 0.3.1。本轮没有强制终止已有会话。

原生协议矩阵还验证了范围拒绝、无效 ID、运行中取消、终态不变、EOF 退出及异常/超大帧拒绝。Codex 验证使用临时 app-server 测试会话，没有启动模型推理回合。

## 最终证据

- [最终一致性汇总](../scan-results/python-chain-20261014/final-verification.json)
- [166 项原生测试与两套 JVM](../scan-results/python-chain-20261014/native-test-verification.json)
- [六次扫描、JAR 字节码与跨 JVM 一致性](../scan-results/python-chain-20261014/final-matrix/runtime-matrix.json)
- [真实 Codex 工具发现与扫描汇总](../scan-results/python-chain-20261014/final-codex/summary.json)
- [Codex 工具调用记录](../scan-results/python-chain-20261014/final-codex/mcp-tool-transcript.json)
- [相对 0.3.0 的来源与诊断变化](../scan-results/python-chain-20261014/source-evidence-delta.json)
- [目标 HEAD 与工作区状态核验](../scan-results/python-chain-20261014/target-verification.json)
- [安装与配置备份记录](../scan-results/python-chain-20261014/installation.json)
- CodeBuddy，`7cdb031d-9608-44a4-9354-42b6f602bfe7`：[Markdown](../scan-results/7cdb031d-9608-44a4-9354-42b6f602bfe7/report.md) · [JSON](../scan-results/7cdb031d-9608-44a4-9354-42b6f602bfe7/report.json) · [SARIF](../scan-results/7cdb031d-9608-44a4-9354-42b6f602bfe7/results.sarif)
- wm-sales-atlas-analysis，`a7f2d1e1-1f66-4031-abc5-e02441acdf31`：[Markdown](../scan-results/a7f2d1e1-1f66-4031-abc5-e02441acdf31/report.md) · [JSON](../scan-results/a7f2d1e1-1f66-4031-abc5-e02441acdf31/report.json) · [SARIF](../scan-results/a7f2d1e1-1f66-4031-abc5-e02441acdf31/results.sarif)
- 蒸馏小可乐，`ec91c70f-fa0d-4398-9503-b09dd07f3d71`：[Markdown](../scan-results/ec91c70f-fa0d-4398-9503-b09dd07f3d71/report.md) · [JSON](../scan-results/ec91c70f-fa0d-4398-9503-b09dd07f3d71/report.json) · [SARIF](../scan-results/ec91c70f-fa0d-4398-9503-b09dd07f3d71/results.sarif)

`scan-results/` 按仓库规则保留在本机、不纳入 Git；实现、测试、通用复验脚本及本文纳入版本控制。0.3.0 的原验收文档保留为历史记录，其 Python 缺口以本轮结果更新。

## 复验命令

```bash
./scripts/build-compatible.sh clean verify
python3 scripts/verify-runtime-matrix.py \
  --java /absolute/jdk-7/bin/java --java /absolute/jdk-8/bin/java \
  --jar compat/target/ai-guardrail-scanner-java7.jar \
  --project /absolute/java-project --project /absolute/python-rag-project \
  --expect-java-functions --expect-python-rag \
  --require-python-parse-success --require-resolved-python-clients \
  --expect-python-guard-results --output /absolute/runtime-verification

python3 scripts/verify-codex-integration.py \
  --project /absolute/java-project --project /absolute/python-rag-project \
  --expect-java-functions --expect-python-rag \
  --require-python-parse-success --require-resolved-python-clients \
  --expect-python-guard-results --output /absolute/codex-verification
```

按验收对象选择 `--expect-*` 要求；不含对应构造的项目不应开启该预期。验证脚本需要 Python 3.11，扫描器本身不依赖 Python。

## 证据边界

SDK 客户端的静态来源不保证运行时注入选择。自定义函数接收了模型内容、返回值进入条件或输出，也不证明该函数具有正确的安全校验语义。流式内容与后续调用的源码先后顺序不能单独证明拒绝行为、全路径覆盖或真实回滚。

`UNKNOWN` 和 `OBSERVED` 始终与安全通过区分。所有扫描继续保留 `complete=false`、`securityVerified=false`，SARIF 的零条违反也不是安全认证。
