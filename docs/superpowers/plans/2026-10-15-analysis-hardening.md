# Analysis Hardening Implementation Plan

**Goal:** 修复判定、服务和验收缺陷，降低重复解析与候选搜索开销，三个项目复验后推送。
**Architecture:** 保留语言 IR 与有界分析，通过局部诊断、初始化执行体、暂存发布、严格 JVM 矩阵和解析复用完成增量修复。
**Tech Stack:** Java 7、ANTLR 4.9.3、Gson、JUnit 4；Python 3.11 用于操作员验收。
**Spec:** `docs/superpowers/specs/2026-10-15-analysis-hardening-design.md`

## Global Constraints

- 保持真实 JDK 7/8 运行兼容和规则泛化。
- 不修改三个目标项目，不提交私有合同、扫描报告或 presentations。
- UNKNOWN、OBSERVED 均不是安全通过；已确定违规优先保留。

## Task 1: 两个 P1

Files: BankAnalysis.java、BankFlow.java、BankPythonAnalysis.java、JavaSyntax.java、BankJavaAnalysis.java；银行/集成测试。

- [x] 失败回归：`edge.release(edge.make())` 无 Guard 应 BLOCK；添加独立 `unrelated(): print('hello')` 后仍 BLOCK。
- [x] 将不支持局限到真实受影响路径；解析失败单独记覆盖缺口，已确定违规不被覆盖。
- [x] 失败回归：`static { Port.release(Port.make()); }` 与受保护方法并存仍应发现违规。
- [x] 纳入静态、实例和字段初始化顺序；覆盖控制前后顺序、不同类与初始化上下文隔离。
- [x] 执行 `scripts/build-compatible.sh -q test`，审查新增测试和最小复现。

## Task 2: MCP 与报告生命周期

Files: McpHost.java、ScanService.java、Reports.java、InfrastructureTest.java、verify-runtime-matrix.py。

- [x] 初始化→无效包络→ping 验证可恢复；解析错误与无效请求返回对应错误。
- [x] latch 控制报告生成时序，取消后无正式报告发布，已完成任务不可取消。
- [x] 暂存生成、临界区检查状态并发布；保留硬链接不覆盖、符号链接拒绝与限额，失败清理已知暂存文件。
- [x] 更新协议验收，分开可恢复错误与不可恢复超长帧。

## Task 3: 验收入口

Files: verify-runtime-matrix.py、新增发布验收入口和脚本回归、README.md。

- [x] 单 JVM、重复版本、非 7/8 版本不能输出双版本通过。
- [x] 矩阵执行前核验实际版本集合覆盖 1.7、1.8。
- [x] 统一入口执行原生 clean verify、双 JVM JUnit 和 MCP 矩阵，记录测试数与 JAR SHA256。

## Task 4: 性能

Files: JavaGraph.java、语言分析器、Scanner.java；语法/调用图测试。

- [x] 按类型、方法名、参数数量索引；覆盖重载、继承、歧义与预算。
- [x] 合成大量方法断言候选工作量受索引约束，不依赖耗时阈值。
- [x] 共享只读语法结果，保留通用/银行分析独立预算与可变状态。
- [x] 比较规范报告与真实项目耗时，区分语义修复造成的变化。

## Task 5: 最终验收与推送

Files: 版本字符串、README.md、docs/analysis-hardening-verification.md；本地 scan-results。

- [x] 保存三个项目 HEAD/status 和映射摘要绑定情况。
- [x] 最终制品执行双 JVM 全量 JUnit、三个项目 MCP 流程及三格式一致性检查。
- [x] 更新本地安装制品；新 Codex 进程复验并比较规范报告；目标状态未变化。
- [x] 复核公开 diff 与制品摘要，明确提交范围。

发布交付以 Git 提交、origin/master 远端 SHA 和本地 `final-verification.json` 中的记录核对，不以计划中的勾选代替远端确认。
