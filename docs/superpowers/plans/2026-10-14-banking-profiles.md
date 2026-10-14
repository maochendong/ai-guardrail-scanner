# 银行规则包实施计划

设计依据：[banking-profiles-design](../specs/2026-10-14-banking-profiles-design.md)。用户已明确要求实现、验证并推送 GitHub。

- [ ] 增加 `BankFlow` 局部值流 IR 与 `BankPolicy` 严格解析器；拒绝未知字段/重复键/无效槽位，启动方固定 profile，合同只接受外部文件。
- [ ] `BankJavaAnalysis.adapt(List<SourceFile>, Cancel)` 通过 JavaSyntax/JavaGraph 生成 IR；验证全限定符号、局部变量、分支与异常结构，未知结构保守处理。
- [ ] `BankPythonAnalysis.adapt(List<SourceFile>, Cancel)` 通过现有 ANTLR 生成 IR；验证 import 来源、遮蔽、局部实例及异常结构，禁止执行源码。
- [ ] `BankAnalysis.analyze(Inventory, BankPolicy, Cancel)` 有界解释 IR，实施三条共性、两条客销、两条行内规则。值来源和检查参数必须一致；正反例涵盖原值外发、错误身份、忽略 Guard、异常回退、错绑适当性和未授权工具。
- [ ] 扩展 CLI 启动参数与 ScanService 闭包，保持 MCP 请求无法变更策略；报告/目录显示 profile、policyDigest、gateDecision，升级版本与文档。
- [ ] 独立集成/对抗测试验证未知配置拒绝、缺映射 UNKNOWN、门禁状态、同源码 digest、三格式和不执行目标代码。
- [ ] 运行 native build 和全部 JUnit 用例，分别用实际 JDK 1.7/1.8 启动执行；扩展两份验证脚本覆盖银行模式。
- [ ] 记录三个目标仓库状态基线，执行两个场景合并的只读 MCP 回归，核对源码 digest 与扫描后状态；记录发现和覆盖缺口。
- [ ] 安装新版本 JAR，备份并仅修改 Codex MCP 相关配置，启动新 Codex 实例验证五工具完整流程；保留旧 JAR。
- [ ] 检查公开提交无凭据/真实源代码报告，提交精确文件并推送 master，核对远端提交。
