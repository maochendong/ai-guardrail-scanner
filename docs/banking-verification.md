# 0.4.0 银行规则包验收记录

日期：2026-10-14。原生兼容模块版本 `0.4.0`，报告 schema `1.3`，规则集 `java-python-guardrail-v4`。五个 MCP 工具保留，目录共 33 条规则；默认 generic 使用原有语言规则，bank-all 增加七条银行规则。

## 已实现与验收边界

共性三条：敏感数据出站是否使用脱敏结果、可信身份与资源授权绑定、Guard 拒绝/失败路径阻断。客销两条：事实与时效校验、客户适当性绑定。行内两条：文档 ACL、工具能力与输入授权。具体合同与范围见 [规则说明](banking-rules.md)。

Java/Python 适配器使用现有语法树，通过相同局部值流引擎分析。绑定精确导入/类型来源、全限定符号、实际参数数量及参数位置；没有项目专名或业务字段关键词分支。未知绑定、未支持结构、预算及解析缺口保留为 UNKNOWN。数据转换的真实有效性、接口语义、动态分派及运行时超时/并发仍须单独验证。

本次真实项目未配置经业务确认的银行 API 合同，七条银行规则均为 UNKNOWN，并产生 BANK_POLICY_UNMAPPED。这是缺少应用映射的明确结果，不是银行控制已通过。银行规则实际检出能力由双语言合成正反例与对抗测试验收。

## 构建与真实 JVM

- `./scripts/build-compatible.sh -q clean verify`：273 tests，0 failures、0 errors；使用真实 JDK 7 javac 编译。
- JDK `1.7.0_79`：最终 JAR 对应的全部 273 项 JUnit 测试通过。
- JDK `1.8.0_40`：相同 273 项测试通过。
- 最终 fat JAR 中 1,031 个 class 的最大 major 为 51；实际 JDK 7/8 均启动并完成 MCP 扫描，不只检查编译目标。
- JAR SHA-256：`be6d056097942ae0611cad36892d053d5a5ff00a7f3c3b1b5424f2b92d25f1e1`。

新增 107 项测试包含语法适配、七规则正反例/未知分支、合同严格解析、MCP 请求不能降级、外部合同快照、来源不泄露、源码/构建/hooks 不执行，以及独立控制流反例。重点回归包括静态接收者、接受结果极性、短路、不可达异常路径、异常/最终处理释放、原值与脱敏值、身份覆盖、错误参数顺序、旧布尔结果复用及参数求值期间的对象变化。

实际老 JDK 测试发现 `Files.newInputStream(..., NOFOLLOW_LINKS)` 的运行时不兼容，已沿仓库既有方式改用 `Files.newByteChannel` 保留不跟随链接的打开语义；两个真实 JVM 的外部合同加载测试均通过。

## 合成合同的完整 MCP 流程

使用 [40 条虚构合同样例](../examples/bank-contracts.example.json)，合同放在两个合成源码目录之外。每个目录同时包含 Java 和 Python，覆盖全部七条银行规则。

| 合成输入 | 银行规则结果 | gateDecision |
|---|---|---|
| 同值转换、接受分支与权限绑定 | 7 OBSERVED | REVIEW |
| 原值出站、无控制放行与未授权调用 | 7 VIOLATED | BLOCK |

两个 JVM 分别走 initialize → tools/list → rules → start → status → 三格式 result，并核验报告文件与正文一致。运行中取消、取消后结果拒绝、畸形/超大消息拒绝、EOF 退出也通过。OBSERVED 仅表示合同前提下观察到局部控制；不输出 ALLOW/PASS。

## 三个真实项目复扫

两个 JVM 和全新 Codex app-server 会话均使用 `bank-all`，空银行合同。三个渠道的规范证据、策略摘要与 gateDecision 完全一致；JSON/Markdown/SARIF 均已重新读取核对。

| 项目 | Java / Python / 配置文件 | VIOLATED | OBSERVED | UNKNOWN | N/A | 门禁 |
|---|---:|---:|---:|---:|---:|---|
| CodeBuddy | 249 / 1 / 5 | 1 | 4 | 32 | 1 | BLOCK |
| wm-sales-atlas-analysis | 217 / 40 / 2 | 0 | 5 | 32 | 1 | REVIEW |
| 蒸馏小可乐 | 0 / 60 / 0 | 0 | 4 | 14 | 0 | REVIEW |

CodeBuddy 的确定违反仍为原有 `AI-GW-002`（自定义网关响应日志）。三个项目的原有规则证据与 0.3.1 验收逐项相同，UNKNOWN 分别增加七条银行规则。数字是评估记录数，不是独立漏洞数。

三次扫描均未出现 Python 解析失败、客户端来源未解析或分析预算失败。既有 f-string/静态范围限制仍保留；CodeBuddy 的 RESULT_LIMIT、wm-sales-atlas-analysis 的 SYMLINK_SKIPPED、蒸馏小可乐的 PYTHON_RESULT_LIMIT 仍存在。所有报告始终 `complete=false`、`securityVerified=false`。

源文件摘要分别为：

- CodeBuddy：`5090b941bcdf723b804cc8fb95f29c5a78cf854aa0e06892473c952290954e24`
- wm-sales-atlas-analysis：`bc4b6bcf43d5f0556932c64c29ef7d8274ab740c503c03443747105fd10e5e5b`
- 蒸馏小可乐：`9548cbb4a3babb0963efc71942e092401fea397ad2b43b7ea98710b38dc686e1`

扫描前后目标仓库 HEAD、Git 工作区状态摘要均保持一致；上述已读取源码摘要也与前次验收一致。未启动或修改目标应用。

## Codex 安装

新 JAR 安装到操作员本地 `ai-guardrail-scanner/0.4.0/ai-guardrail-scanner.jar`，保留 0.3.1 回退文件。备份 config.toml 后，只替换该 MCP 的 JAR 参数并追加 `--profile bank-all`；解析后比较确认其他配置未变，仍由真实 JDK 7 启动。

新 Codex 会话发现 33 条规则和五工具，完成三个项目的扫描、状态查询、JSON/Markdown/SARIF 导出、根目录越界拒绝、非法 scanId 拒绝及终态一致性验证。当前工作聊天里的旧进程在查询时仍返回 26 条目录，因此没有声称旧连接已热更新；重连 MCP 或新建会话后加载新配置。

## 复现与证据位置

本机完整证据保留在忽略提交的 `scan-results/bank-20261014/`，包括 `native-test-verification.json`、`runtime-matrix/`、`synthetic-matrix/`、`codex/`、安装回执、目标状态基线与 `final-verification.json`。公开仓库发布通用实现、合成测试/合同和本汇总；不提交目标源码或本机配置备份。

运行 `scripts/verify-runtime-matrix.py` 时分别传入两个真实 `--java`，指定兼容 `--jar`、三个 `--project`、外部 `--output` 和 `--profile bank-all`。为保留此前来源链验收，追加 `--expect-java-functions --expect-python-rag --require-python-parse-success --require-resolved-python-clients --expect-python-guard-results`。合成场景额外传入外部 `--bank-policy`；真实应用须先审查并登记其接口语义，不能直接拿虚构合同声称覆盖。

`scripts/verify-codex-integration.py` 使用已安装的 Codex 配置，接受相同 profile/合同和验收开关；它会核对启动配置，再创建临时 app-server 会话执行工具，不启动模型回合。
