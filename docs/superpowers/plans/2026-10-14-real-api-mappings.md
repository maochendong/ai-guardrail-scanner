# Real API Mappings Implementation Plan

**Goal:** 用源码审查过的真实合同验证三个项目，并明确区分三类 UNKNOWN。
**Architecture:** 外部合同 v2 + 既有 Java/Python IR + 有界局部路径引擎；旧规则由统一报告层补原因，不改变旧结论。
**Tech Stack:** Java 7 源码与运行 API、ANTLR 4.9.3、Gson、JUnit 4；Python 3.11 只用于操作员验证脚本。
**Spec:** `docs/superpowers/specs/2026-10-14-real-api-mappings-design.md`

## Global Constraints

- 不执行或修改三个目标项目；规则不得出现三个项目的名称或专属分支。
- 保持真实 JDK 7/8 运行；未知/候选映射不能成为安全通过。
- 真实合同在仓库外并绑定源码摘要；公开提交不含源码摘录和真实凭据。

## Task 1: 合同与通用流扩展

Files: BankPolicy.java、BankFlow.java、BankAnalysis.java、BankSemanticTest.java。
Interfaces: `BankPolicy.parse/load` 保留；新增 `matchesSourceDigest(String)`、合同参数归一化元数据和接收者查询；`BankAnalysis.analyze` 保留。

- [ ] 先添加测试：v1 兼容；v2 未知字段拒绝；摘要变化禁用银行合同；check 结果经 accessor 才生效，candidate 保持 UNKNOWN。
- [ ] 扩展严格解析、不可变合同和快照验证，不加载仓库内策略。
- [ ] 在调用/返回/抛出路径上实现声明的源、判定投影和输出边界，保留 unknown 原因。
- [ ] 执行 `./scripts/build-compatible.sh -q -Dtest=BankSemanticTest test`，检查正反例。

## Task 2: 两语言适配器

Files: BankJavaAnalysis.java、BankPythonAnalysis.java、各自 Test。
Interfaces: 新增 `adapt(List<SourceFile>,Cancel,BankPolicy)`，保留原入口；新 IR MEMBER/MAP/NEW/YIELD，CALL 参数名与接收者候选信息。

- [ ] 使用改名合成源码测试对象判定、关键字/default、self 来源、字段与返回输出。
- [ ] 仅在类型/导入/外部接收者合同一致时绑定；歧义和未知调用保持未知。
- [ ] 对容器/回调/循环未覆盖的路径输出 UNSUPPORTED，禁止伪造正面结论。
- [ ] 执行适配器测试并核对旧回归。

## Task 3: UNKNOWN 分类

Files: Unknowns.java、Findings.java、Reports.java、UnknownsTest.java；Scanner/ScanService 接入由主线程负责。
Interfaces: `Unknowns.set(Map,String,String,String)`、`Unknowns.summarize(List<Map<String,Object>>)`、`Unknowns.complete(List<Map<String,Object>>,List<Map<String,Object>>)`。

- [ ] 测试三主分类、无证据占位、非 UNKNOWN 不附分类、原因不泄露源码、三格式一致。
- [ ] 统一补旧规则缺省原因；精确银行原因由引擎写入，不用项目名或错误正文猜测。
- [ ] 报告展示分类统计，MCP 状态保留同一统计。

## Task 4: 真实映射与发布验收

Files: 操作员私有目录中的项目合同与审查清单；scripts/verify-*.py；docs/real-api-mappings-verification.md；README.md。

- [ ] 保存三个项目 HEAD/status/sourceDigest；将审查中有依据的源/候选控制/输出边界登记为 v2 合同，无对应接口的项保留缺映射或证据不足。
- [ ] 使用实际 API 名解析扫描，检查 mapped 调用计数、重点三规则及原因；对异常放行、输出先于校验等结构保留证据与限制。
- [ ] 构建并分别用真实 JDK 7/8 跑所有测试及完整 MCP 流程，重新安装 Codex 并比较三个渠道规范证据。
- [ ] 核对目标状态未变、公开提交内容无敏感源码/凭据，记录通过与未知，提交并推送 GitHub。

## 执行结果

已实现并完成真实 JDK 7/8 各 344 项测试、双 JVM MCP 和新 Codex 进程三个项目验收。51 个真实合同和 8 个 receiver 存放操作员私有目录并绑定源码摘要。完整结果与剩余 UNKNOWN 见 [0.5.0 验收记录](../../semantic-mappings-verification.md)。
