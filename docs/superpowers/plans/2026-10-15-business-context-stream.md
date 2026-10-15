# Business Context and Stream Timing Implementation Plan

**Goal:** 将兼容模块类名统一为 Business，补齐调用上下文身份与流式首包时序证据，并完成真实双 JVM 和三项目交付验证。

**Architecture:** 保留现有语法适配与 BusinessFlow。BusinessAnalysis 在确定的本地调用点执行有界 callee frame；BusinessStreamTiming 独立输出相对时序事实，不替代安全处置。

**Tech Stack:** Java 7、ANTLR 4.9.3、JUnit、Python 3 验收工具、stdio MCP。

**Spec:** `docs/superpowers/specs/2026-10-15-business-context-stream-design.md`

## Global Constraints

- 扫描器本身原生兼容 JDK 7/8；保留 `bank-*` 参数和规则 ID 兼容。
- 不修改三个目标应用，不将项目名称或私有符号写入引擎与合成回归。
- 保留独立入口与候选绑定 UNKNOWN；流式顺序事实不等于生产网络时序或控制有效性。
- 源码和私有合同仅留本地，公开提交前核对范围。

## Task 1: 命名与基线

- [x] 保存目标仓库 HEAD、工作区与 tracked diff 摘要。
- [x] 将五个 Bank 生产类、对应测试及当前技术文档引用改为 Business。
- [x] 核对 Java 类型引用不遗留旧类名，历史验收记录保留原版本事实。

## Task 2: 调用上下文身份

Files: `BusinessFlow.java`、`BusinessJavaAnalysis.java`、`BusinessPythonAnalysis.java`、`BusinessAnalysis.java`、`BusinessInterproceduralTest.java`。

- [x] 先补参数传递、返回、分支、重载和递归的失败回归。
- [x] IR 声明与调用携带唯一函数身份、绑定确定性，避免仅按方法名和参数数量选择实现。
- [x] 建立隔离 callee frame，用实际参数初始化，只向调用者合并所有正常出口共有的值与证据；保守处理异常、副作用与预算。
- [x] 导出 `callContextSites` 及截断标志，包含调用/被调位置、绑定和参数身份状态，不包含接口符号。
- [x] 定向执行新回归并检查已有规则的错误升级或证据污染。

## Task 3: 首包相对时序

Files: `BusinessStreamTiming.java`、`BusinessStreamTimingTest.java`，BusinessAnalysis 的只读结果装配。

- [x] 实现 `BusinessStreamTiming.analyze(BusinessFlow.Program, BusinessPolicy, Cancel)`，返回 `sites` 和 `truncated`。
- [x] 只按合同、值与控制流跟踪释放/检查；区分前置同值成功、释放早于后置检查、关系未决。
- [x] 覆盖分支、零次循环、拒绝、异常、错误对象、候选校验、返回与取消后检查未执行的边界。
- [x] 将 `streamTimingSites` 与截断标志放入 Guard 评估，不修改原处置。

## Task 4: 报告与集成

Files: `Reports.java`、`scripts/report_schema.py`、报告回归及版本常量。

- [x] 版本升级 0.7.0、schema 1.6、ruleset v8。
- [x] 三种格式通过白名单输出新证据，增加缺字段、错字段与截断回归。
- [x] 单次构建后执行聚焦回归，复核证据和隐私边界。

## Task 5: 验收与推送

- [x] 通过 `scripts/verify-release.py` 在真实 JDK 7/8 上完整验收；`--project` 分别使用本地操作员授权的三个目录。
- [x] 安装已验收的 JAR，更新本机 Codex scanner 路径，用 `scripts/verify-codex-integration.py` 验证新进程。
- [x] 比较三项目稳定报告、源码摘要和工作区基线，记录 UNKNOWN 变化及必须人工确认的证据。
- [x] 更新技术方案和公开验收汇总；精确暂存、提交、推送并核对远端 HEAD。
