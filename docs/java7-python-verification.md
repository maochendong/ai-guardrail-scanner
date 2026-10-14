# 0.3 Java 7/8 与 Python/RAG 验收

本次要求包括扫描器自身原生运行于 JDK 7/8、保留 Java 网关/Guard/function calling 能力，并新增 Python/RAG 静态扫描。不启动目标项目，不执行目标构建，不调用模型，不读取数据库。

## 最终验收结果 · 2026-10-14

最终产物通过真实 **JDK 7u79 与 JDK 8u40 各 114 项测试**，失败、错误、跳过均为 0。构建亦通过 114 项测试。JAR 内 1,004 个 class（包括运行依赖）的主版本均不超过 51。Java 21 参考模块 231 项测试通过，单独计数，不与兼容测试相加。

同一最终 JAR 在两套 JVM 上各扫描三个项目，共 6 次扫描；规则状态、证据、诊断及源码摘要一致。安装后再经真实 Codex app-server 发现 **0.3.0 / 5 个工具 / 26 条规则**，在 Java `1.7.0_79` 上完成三个项目的扫描和 JSON、Markdown、SARIF 导出；Codex 报告与原生矩阵证据再次逐项一致。范围拒绝、无效 ID、运行中取消、终态不变、EOF 和异常帧边界均已验证。

| 项目 | Java / Python / 配置文件 | 模型边界 | VIOLATED | OBSERVED | UNKNOWN |
| --- | ---: | ---: | ---: | ---: | ---: |
| CodeBuddy | 249 / 1 / 5 | 4 | 1 | 4 | 25 |
| wm-sales-atlas-analysis | 217 / 40 / 2 | 1 | 0 | 5 | 25 |
| 蒸馏小可乐 | 0 / 60 / 0 | 7 | 0 | 3 | 7 |

上表统计评估记录，不能作为独立漏洞数或通过率。两个 Java 项目另各有 1 条 `NOT_APPLICABLE`。源码摘要来自实际纳入的文件；三个目标仓库的 HEAD 和既有工作区状态摘要与扫描前一致，扫描过程没有执行目标应用、构建、脚本或数据库操作。

安装文件：`/Users/Darkknight/.local/share/ai-guardrail-scanner/0.3.0/ai-guardrail-scanner.jar`；SHA-256：

```text
05f969dbbd01a59af55a5460b7130470c02c4e91441cbf239c9812c4cfd9ba48
```

Codex 配置仅修改本 server 的 command/args：使用真实 JDK 7，指定 768 MiB 最大堆、0.3 JAR 与三个已授权项目根目录。解析后的 TOML 对比确认其余配置未变。配置备份为 `/Users/Darkknight/.codex/backups/config.before-ai-guardrail-v030-20261014-093235.toml`，0.1/0.2 JAR 保留可回退。回退时恢复本 server 对应的旧配置项，避免覆盖后续对其他设置的修改。

当前既有对话的 MCP 连接仍返回 19 条规则；新 Codex 进程已实测返回 26 条。旧连接需要重连 MCP 或重启 Codex 才能使用新版，配置变更不会让已运行的 Java 进程自动换包。

## 最终证据文件

- [最终汇总与安装一致性](../scan-results/java7-python-20261013/final-verification.json)
- [双 JVM 矩阵、版本及六次扫描 ID](../scan-results/java7-python-20261013/final-matrix/runtime-matrix.json)
- [114 项原生测试结果](../scan-results/java7-python-20261013/native-test-verification.json)
- [231 项 Java 21 参考测试结果](../scan-results/java7-python-20261013/modern-reference-verification.json)
- [真实 Codex 工具发现及扫描汇总](../scan-results/java7-python-20261013/final-codex/summary.json)
- [Codex 工具调用记录](../scan-results/java7-python-20261013/final-codex/mcp-tool-transcript.json)
- [目标 HEAD 与工作区状态核验](../scan-results/java7-python-20261013/target-verification.json)
- [安装与配置备份记录](../scan-results/java7-python-20261013/installation.json)
- CodeBuddy，扫描 ID `62b40f7c-a238-4d98-932b-7da1060c3154`：[Markdown](../scan-results/62b40f7c-a238-4d98-932b-7da1060c3154/report.md) · [JSON](../scan-results/62b40f7c-a238-4d98-932b-7da1060c3154/report.json) · [SARIF](../scan-results/62b40f7c-a238-4d98-932b-7da1060c3154/results.sarif)
- wm-sales-atlas-analysis，扫描 ID `a841e582-bba9-4787-a70f-f8ba9ad6cc15`：[Markdown](../scan-results/a841e582-bba9-4787-a70f-f8ba9ad6cc15/report.md) · [JSON](../scan-results/a841e582-bba9-4787-a70f-f8ba9ad6cc15/report.json) · [SARIF](../scan-results/a841e582-bba9-4787-a70f-f8ba9ad6cc15/results.sarif)
- 蒸馏小可乐，扫描 ID `d03fd8d0-33ac-420e-b135-a07bd5f46c1c`：[Markdown](../scan-results/d03fd8d0-33ac-420e-b135-a07bd5f46c1c/report.md) · [JSON](../scan-results/d03fd8d0-33ac-420e-b135-a07bd5f46c1c/report.json) · [SARIF](../scan-results/d03fd8d0-33ac-420e-b135-a07bd5f46c1c/results.sarif)

以上 `scan-results/` 文件保存在本机，按仓库规则不纳入 Git；复验脚本、实现、测试与本文纳入版本控制。目录名沿用任务开始日 `20261013`，最终验收日期为 2026-10-14。

## 产物与兼容边界

发布入口为 `compat/target/ai-guardrail-scanner-java7.jar`。构建工具使用 Java 21，兼容源码及测试通过真实 JDK 7 `javac` 编译；运行该 JAR 不需要构建工具、Python 或另一版本 JVM。Java/Python 语法解析器在同一 Java 进程中运行。

- JDK 7：`/Library/Java/JavaVirtualMachines/jdk1.7.0_79.jdk/Contents/Home/bin/java`
- JDK 8：`/Library/Java/JavaVirtualMachines/jdk1.8.0_40.jdk/Contents/Home/bin/java`
- 原实现：Java 21 参考模块，本轮 231 项测试通过。它不能作为 Java 7/8 运行兼容的证据。
- 兼容依赖：ANTLR 4.9.3、Gson 2.11.0、SnakeYAML 1.33；YAML 仅组合并检查节点，不实例化源文件指定的对象。
- 语法来源固定在 grammars-v4 提交 `89fd36482e8cb68a4e55df021a8adbc7541b52f2`，许可及修改见 `compat/THIRD-PARTY-NOTICES.txt`，并随 JAR 分发。

## 复验命令

```bash
./scripts/build-compatible.sh clean verify
python3 scripts/verify-runtime-matrix.py \
  --java /absolute/jdk-7/bin/java \
  --java /absolute/jdk-8/bin/java \
  --jar compat/target/ai-guardrail-scanner-java7.jar \
  --project /absolute/java-project \
  --project /absolute/python-rag-project \
  --output /absolute/verification-output

python3 scripts/verify-codex-integration.py \
  --project /absolute/java-project \
  --project /absolute/python-rag-project \
  --output /absolute/codex-verification-output
```

验证脚本需要 Python 3.11，属于验收工具，不是扫描器运行依赖。原生 JVM 验证检查每个打包 class 的主版本不超过 51、真实启动版本、握手与工具发现、扫描完成、三种报告文件与工具正文一致、跨 JVM 证据等价、范围拒绝、运行中取消、结束状态不变、EOF 退出和异常帧拒绝。Codex 脚本通过真实 `app-server` 与临时测试会话调用已配置 MCP，不启动模型推理回合。

## 验收中修正的问题

首轮原生矩阵中，Python 虚拟环境使用了非标准目录名，清点器只按 `.venv`/`venv` 名称排除，误纳入第三方依赖并触发 120 秒超时。已增加基于 `pyvenv.cfg` 的环境识别与 `site-packages` 排除，并用任意目录名的通用测试验证。超时任务保持 FAILED，没有导出成功结论；初次失败记录保留在 `scan-results/java7-python-20261013/preliminary-matrix/`。

最终审阅还补齐了初始同名重载的 16 候选上限：17 个不明确重载不会被截成一个看似完整的集合，而是返回未知并记录 `CALL_GRAPH_TARGET_LIMIT`。回归同时覆盖 final 与非 final 类。另对工作线程异常、解析中途超预算的部分结果、SDK 名称遮蔽与候选来源误升级增加了回归。

兼容版的配置清点只读取与已实现配置规则有关的 Maven/Gradle/application 文件，而 0.2 清点所有 XML、YAML、properties，因此配置数量及整个清点摘要不能与 0.2 直接等同。Java 生产源码数量、模型边界及关键证据应单独核对。

## 证据解释

`COMPLETED` 表示扫描任务及报告导出完成。`OBSERVED` 是局部源码构造证据，`UNKNOWN` 是未验证范围；两者均不是安全通过。Java 兼容实现与原实现使用不同解析器，原有全部测试通过不能代替迁移回归；必须比较网关、调用关系、规则状态及证据位置。

新报告 schema 为 `1.2`，规则集 `java-python-guardrail-v3`。目录共 26 条规则；Java 19 条在清点到 Java 源码或支持配置时执行，Python 7 条在清点到 Python 源码时执行，因此混合仓库的评估条数可能增加。每个规则也可产生多种 disposition，评估数不等于漏洞数。

Java/Python 都有有界语法、来源与调用关系分析。动态分派、外部控制与无法证明的来源保留未知。兼容实现不提供锚定目录读取或原子源码快照，始终记录 `FILESYSTEM_RACE_LIMITATION`，要求源码树在扫描期间保持稳定。完整性与安全验证字段均不会用来宣称安全认证。

## 真实项目的证据与剩余覆盖

- codebuddy：识别 4 个自定义模型边界。`DeepSeekClient.java:216、258` 的模型响应进入 SLF4J 日志产生 1 条 `AI-GW-002 / VIOLATED` 评估，包含两个位置；这不证明真实敏感数据已经泄露。`AIAssistantService.java:558、671` 的模型工具名称/参数与本地分派关联，三个 function calling 规则均有观察证据，授权及校验有效性仍未知。
- wm-sales-atlas-analysis：识别 `OpenAiCompatGateway.java:58` 的模型边界；`AiChatService.java:179` 的工具分派与注册表查找关联。`AiChatService.java:195、252` 和 `AiInsightService.java:103、105` 的自定义输出判定结果被消费，仅确认局部结构。
- 蒸馏小可乐：清点 60 个 Python 文件，识别 7 个有导入身份与来源关系的 OpenAI SDK 调用位置。`src/rag/generator.py:95、121` 有模型调用及 Token 预算参数；`generator.py:131` 与 `pipeline.py:337` 有模型来源内容的 yield。`pipeline.py:346` 的调用消费模型内容，但自定义校验的有效性、拒绝行为与完整输出覆盖均未证明。Chroma 检索位置保留在 L2 的未知证据中。构造器注入的客户端不能全部绑定，`src/rag/validator.py:80` 保留未知来源，并产生 `PYTHON_UNRESOLVED_MODEL_CALL`。

兼容版对调用前 Guard 的观察要求判定与网关实参共享可追踪输入。codebuddy 的 `AI-GUARD-001` 从 0.2 的局部提前退出观察降为 `UNKNOWN`，因此 Java 侧 OBSERVED 数由 5 变成 4；不能为维持旧计数而把无法关联的判定当作围栏证据。两个 Java 项目还有 Python 脚本，因此新增 7 条 Python 未知评估，并不表示新增了 7 个漏洞。

本次仍有以下明确缺口：

- codebuddy 网关证据超过每项 16 个位置，产生 `RESULT_LIMIT`；未导出的位置不能视为已完整审阅。
- wm 的 `scripts/harnesslib/documents.py` 与 `scripts/harnesslib/reports.py` 未被 Python 语法解析器完整解析，产生 `PYTHON_PARSE_FAILED`，相应文件不贡献确定结论。217 个 Java 文件未出现解析失败。
- 蒸馏小可乐本次没有语法失败或来源分析预算耗尽，但 f-string 插值、动态派发、外部包、服务端授权、注入客户端和完整审计链仍有未验证范围。0 违反不能解释为 RAG 安全通过。
- 三个项目均保留排除目录及文件系统快照限制诊断，wm 还记录未跟随的符号链接。所有报告的 `complete`、`securityVerified` 和 SARIF `executionSuccessful` 均为 `false`，任务完成与安全结论分开记录。

## 协议与接入依据

stdio 使用 UTF-8、逐行 JSON-RPC，stdout 不混入普通日志；能力与协议版本通过初始化握手协商。实现范围仅包含本地 stdio、五个工具及必要生命周期。畸形 JSON 或超长帧会拒绝并关闭当前进程，需要客户端重连；不承诺逐帧恢复。[MCP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)、[MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)

Codex 通过配置中的 `mcp_servers`、`command` 与 `args` 启动本地服务器；实际是否加载新版本以新进程的发现结果与报告 runtime 为准。[Codex MCP 官方说明](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
