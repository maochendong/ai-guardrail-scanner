# 真实 API 语义映射与 UNKNOWN 分类

0.5.0 在同一通用银行规则引擎中支持合同 v2。项目 API 名称只写在操作员维护的外部 JSON 中；引擎不按项目名、目录名或 `guard/auth/userId` 等关键词授信。v1 合同仍可加载。

## 建立可复核的映射

1. 只读审查实际声明、调用点、参数来源、拒绝/异常分支及返回值使用。把“质量校验”与“安全控制”分开，把“检查定义存在”与“真实路径调用”分开。
2. 先运行源码扫描取得 `sourceDigest`，把已审查的摘要写入外部合同的 `sourceDigests`。映射和摘要必须由操作员维护，不能接受目标仓库自行提供的放行策略。
3. 映射真实 API；无法确认的类型/语义使用 `assurance: "candidate"`。没有可信身份槽、没有文档密级证据时如实声明，不能补造身份或 ACL 检查。
4. 重新扫描，核对 `mappingCoverage`、每条规则的证据及 UNKNOWN 原因。代码摘要改变后应重新审查并更新合同，不能仅复制新摘要绕过复核。

`sourceDigests` 可省略；省略表示没有绑定快照。配置后只接受列出的库存摘要，失配时停用银行映射、输出 `STALE_SOURCE_MAPPING`，原有语言规则继续扫描。摘要只覆盖扫描器纳入的源码/配置，不证明部署产物、数据库权限或外部系统状态未变化。

## v2 字段

顶层必需 `version: 2`，可选 `contracts`、`receivers`、`sourceDigests`。`contracts` 缺省为空。最多 256 条合同、128 条接收者映射、16 个摘要，文件不超过 64 KiB；未知字段、重复 selector/JSON key、越界参数及无效类型均拒绝。

每条合同仍以全限定 `symbol/arity` 唯一标识。Java 构造器使用 `qualified.Type#<init>`；Python 方法 arity 不包含绑定的 `self/cls`。不支持同一 symbol/arity 重复登记不同角色。

| 字段 | 适用范围 | 含义 |
|---|---|---|
| `parameterNames` / `defaults` | 所有合同 | 声明参数名和 JSON 标量/null 缺省值，归一 Python 关键字及省略参数；名字数量须等于声明 arity。多个候选都匹配时保留 UNKNOWN。`*args/**kwargs` 不猜测；本版小数或超出 Long 范围的数字缺省值保留未知。 |
| `assurance` | 合同及 receiver | `reviewed` 为操作员声明已审查（默认），`candidate` 不建立已覆盖证明。它不是扫描器认证。 |
| `outboundArgs` | source | 同一模型 API 的请求参数同时作为数据出站点，其返回值仍作为来源追踪。 |
| `decision` | boolean check | `{"symbol":"example.Decision#accepted","arg":-1}` 表示零参数实例判定；`arg:0` 表示仅一个参数的判定函数。只绑定该次检查返回的对象，不能凭同名谓词授信。 |
| `mode` | check | `boolean`（默认）消费布尔接受结果；`normal-return` 表示正常返回建立断言，异常路径不继承该证明。 |
| `failureMode` | check | v2 默认 `unknown`；`closed` 为已审查失败阻断；`open` 表示失败放行。接受分支不能把 open/unknown 当作完整 Guard 覆盖。 |
| `control: "preserve"` | transform | 明确审查过的值载体/派生关系，`arg:-1` 引用 receiver，否则引用参数。不得把任意序列化、净化、修改操作声明透明。 |
| `boundary` | sink | `call`（默认）、`return` 或 `yield`。后两者的虚拟槽位为：0 是返回/产出值，1..arity 是函数参数。返回边界表示应用输出构造，不能等同已验证 socket 发送。 |
| `valuePath` | sink | 常量键路径，提取受支持结构里的值。未知属性、别名变更、动态键不构成确证。 |
| `requiresLabel` | sink | 只对指定来源标签要求该控制；已知固定错误文案可跳过，来源不明仍 UNKNOWN。 |
| `identity: -1` | access/retrieve/recommend | 明确没有身份参数，禁止把 query、top_k、persona 当主体。 |
| `scope` | sink | `unknown` 为 v2 默认，资源范围未确定；`restricted` 要求权限绑定；`public` 声明公开范围，不产生权限通过结论。 |
| `when` | call sink，0.6.0 起 | `{"arg":0,"equals":"content"}` 仅对该常量参数值应用边界，用于区分同一事件封装 API 中的内容与状态消息。支持字符串、布尔、数字及 null；仅已知不匹配才能跳过，未知条件输出 `SINK_CONDITION_UNRESOLVED`。不能用于 return/yield 边界。 |

`receivers` 的每项包含 `owner`（完整模块类名）、`field`、`type`，以及可选 `assurance`。它用于绑定 `self.field.method` 的声明类型。构造器允许任意客户端注入时通常只能设 candidate；局部重绑定、反射修改或别名逃逸仍会阻止精确绑定。

[v2 虚构合同示例](../examples/bank-contracts-v2.example.json) 展示对象判定和函数返回边界。它不含任何目标项目 API，也不能直接作为生产系统已接入控制的证据。

## 分类与统计

每条 UNKNOWN 带 `unknownCategory` 和非空 `unknownReasons`（category/code/explanation）。第一项原因作为主分类计数；同一发现可同时保留其他原因，不重复计入总数。

| 主分类 | 中文 | 示例 |
|---|---|---|
| `MISSING_MAPPING` | 缺少映射 | 没有有效操作员合同、源码摘要失配、未解析到可用的输出/执行边界。 |
| `INSUFFICIENT_EVIDENCE` | 证据不足 | 身份可信度、文档受限范围、校验失败语义或质量校验的安全资格未建立；旧规则没有足够定位证据。 |
| `UNSUPPORTED` | 暂不支持 | 跨函数状态、回调/循环、动态绑定、未知修改或预算限制妨碍当前路径证明。 |

没有解析到某类 sink 也可能是该功能未实现或在扫描范围之外；`NO_RESOLVED_MAPPED_SINK` 不断言目标必然缺少控制。诊断单独分类，不把全局 f-string/解析诊断随意归到每条 UNKNOWN。

JSON、Markdown、SARIF、MCP 状态均带 `unknownSummary`。SARIF 保留原数字 `unknownAssessments`，并增加 `unknownAssessmentsDetails`，不会因只导出违反项而丢失待复核内容。

0.6.0 报告 schema 为 `1.5`。银行评估增加 `siteAssessments`，按相对路径、行号、内部绑定与处置区分有界路径结果，同一位置可以同时存在不同处置；同一 UNKNOWN 位置的多条原因合并保留。每条银行规则最多导出 128 项，超过后 `siteAssessmentsTruncated=true`，后续路径仍参加规则汇总。位置不是独立漏洞数或安全覆盖率。合同符号和源码值不随位置明细导出。

UNKNOWN 的 `reviewActions` 给出 `kind`、`code`、`status: OPEN`、`ownerRole`、`reasonCodes`、`requiredEvidence` 与 `locations`。动作不表示已完成人工审查，也不会改变处置。`manualReviewRequired` 只在具有明确业务/部署语义确认或运行验收动作时为 true。

| 动作 | 下一步 |
|---|---|
| `MAP_API` | 补齐或复核实际 API 参数、返回值与来源合同；确认是否确实缺少主体槽位。 |
| `EXTEND_ANALYSIS` | 用最小复现补接收者、跨函数、流式元素、迭代或预算能力。 |
| `CONFIRM_SCOPE` | 由身份、业务或数据权限负责人提供可信身份、公开/私有资源范围及控制资格依据。 |
| `VERIFY_RUNTIME` | 在真实部署中执行拒绝、异常、超时、跨用户/租户、文档撤权与首包释放等负测。 |
| `TRIAGE_EVIDENCE` | 旧规则只有“未定位/语义未核实”时先定位证据，不直接把所有 UNKNOWN 指派给人工。 |

逐位置原因优先绑定本位置，未访问路径/预算原因单独保留；父规则为 VIOLATED 时也保留其他 UNKNOWN 位置的动作。SARIF 的 `reviewAssessmentsDetails` 保存这类非 UNKNOWN 父规则的复核信息。Markdown 列出具体原因和证据要求。最终运行验收仍须由具备部署环境与业务数据权限的人员完成。

Guard 的 `controlReviewSites` 单独记录实际命中的候选、失败放行或失败语义未知的检查调用（最多 128 项，`controlReviewSitesTruncated` 标示截断）。它与输出位置分开：不计入 `mappedPathOutcomes`，不改变规则处置，不能据此断言某次失败已经释放到客户端。这样即使下游值流尚未打通，也不会隐藏已定位的检查实现复核任务。

0.7.0 报告 schema 升为 `1.6`，兼容既有合同与 `bank-*` 参数，Java 实现类统一命名为 `Business*`。新增两类最多 128 项的独立证据：

- `callContextSites`：调用与被调函数位置、确定/候选绑定、各参数的 trusted/untrusted/unknown 身份状态。它说明具体调用点，不覆盖同一方法的其他入口。`callContextSitesTruncated` 显式说明截断。
- `streamTimingSites`：首个已映射的本地释放位置、映射检查位置、先后顺序、同值关系、控制资格、失败语义与限制。`streamTimingSitesTruncated` 显式说明截断。没有定位到检查时 `checkPath` 为空、`checkLine` 为 0。

`RELEASE_PRECEDES_MAPPED_CHECK` 表示释放发生在该检查之前，不能推断此前不存在其他控制；`ACCEPTED_CHECK_PRECEDES_RELEASE` 仅用于同值、reviewed、失败阻断且接受分支先于释放的受限事实；其余关系为 `ORDER_UNRESOLVED`。三者均不替代银行规则处置、生产网络验证或循环全部迭代证明。

JSON 保留上述字段，Markdown 展示对应位置与限制；SARIF 的 `contextAssessmentsDetails` 保留有上下文/时序证据或截断的评估，即使其处置并非 UNKNOWN。私有接口符号和源码值不进入这些明细。

`mappingCoverage` 分别给出合同定义数、源码匹配声明数、实际命中调用位置、return/yield 边界、候选绑定、参数绑定失败与分析函数数。位置计数按相对路径、行号和符号去重，同一行同一 API 多次调用可能合并；这些是映射使用统计，不是安全覆盖率。仅有声明不会计作实际调用。

## 0.8.0 通用规则复用

`generic` 也可显式加载 `--bank-policy`，但不输出 BANK 专项规则；其他 profile 仍按既有范围选择专项输出。语义分析在单次扫描内执行一次，通用检查继续独立运行，通过 `GenericSemanticAnalysis` 消费以下同义证据：

| 通用规则 | 共享语义依据 |
| --- | --- |
| Java `AI-GUARD-002`、Python `AI-PY-005` | 带模型输出来源标签的真实释放边界及同值 Guard 判定 |
| Java `AI-L2-003`、Python `AI-PY-002` | 同一检索位置的文档 ACL 与主体/资源范围约束；不能只检查 ACL 而忽略身份 |

这不是把七条业务评估逐条复制到通用规则。数据出站不等同日志处理，资源访问不等同会话隔离，工具能力不等同参数 schema；其余通用规则暂不消费外部合同。原有 VIOLATED 与未覆盖 UNKNOWN 保留；同一行的多个同 API 调用按位置保守合并，不拼接不同调用的成功证明。

报告 schema `1.7` 新增 `semanticOrigin`（来源规则、语言、共享引擎及策略摘要）、`semanticScope: MAPPED_LOCAL_SITES_ONLY`、`semanticCoverageIncomplete`，明确证据的来源与局部边界。位置关联用不暴露 API 符号的摘要标识；SARIF 的 `semanticAssessmentsDetails` 保留全部语义评估，包括 OBSERVED 和 VIOLATED，Markdown 显示相同来源与范围。局部 OBSERVED 不是整个规则通过，新增评估可能增加 UNKNOWN 记录数。

## 0.9.0 复合结果判定

v2 的 `decision` 兼容旧单一访问器，并新增有限合取形式。下面描述同一个检查结果必须同时允许且不要求二次审核；外层 check 的 `accept` 必须为 `true`：

```json
{
  "all": [
    {"symbol": "example.Decision#allowed", "arg": -1, "accept": true},
    {"symbol": "example.Decision#needsReview", "arg": -1, "accept": false}
  ]
}
```

`all` 包含 1–8 个唯一 `(symbol,arg)`，每项显式声明布尔 `accept`；不能与旧 `symbol/arg` 格式混合，不能添加任意表达式或嵌套组合。实例访问器用 `arg:-1`，单参数外部谓词用 `arg:0`。同一路径必须满足同一次检查返回对象的全部叶子；检查两个不同返回对象、少检查一项、以 OR 放行、读取后修改对象，均不构成完整接受证明。接受的布尔事实与合同资格、失败策略、身份来源仍分开。

字段值流只处理有源码或明确基础类型依据的结构。动态 JSON 解码不能凭字段名称恢复模型结果、身份或安全属性；源码生成方法、未建模集合元素与所有输出的关系仍可能 UNKNOWN。Python 常量 JSON 摘要仅在已扫描源码不存在同名 `json.py` / `json/__init__.py` 时启用；有同名模块时保留普通调用，不猜测 `PYTHONPATH`，显式运营合同仍优先。

报告 schema `1.8` 的时序值关系增加 `checked-value-derived-from-release`，表示检查输入在源码中由先前释放值构造。它必须携带非空检查文件、正行号及 `DERIVATION_IS_NOT_CONTENT_OR_GUARD_EQUIVALENCE` 限制，即使顺序尚未确定也不能省略检查位置；不能与 `same` 混用，也不能产生 `ACCEPTED_CHECK_PRECEDES_RELEASE` 的保护结论。

## 保留的分析边界

本轮支持常量 Map/字典字段、显式构造器和值载体、对象判定、受限 Python receiver 和默认参数，未实现完整跨过程分析。0.6.0 对 Java 根赋值/返回条件表达式保留择一分支；调用参数内部的条件表达式仍可能未知。隐式虚调用保留可定位的候选符号，不推断部署实现。

Python 简单 `for NAME in ...` 保存来源与代表性元素，分析零次与一次路径。元素不能继承整个集合的校验证明，单次迭代也不能证明后续迭代或汇总值安全。流式释放缺少先行同值 Guard 时记录 `STREAM_RELEASE_WITHOUT_BOUND_GUARD`；它表示当前映射下未建立先行证明，不能单独断言外部控制失效。循环/yield、异步 callback、复杂别名、动态分派和数据库级资源绑定仍可能 UNKNOWN。

`OBSERVED` 仅表示已建模的局部路径和操作员合同前提下观察到控制使用。所有报告仍为 `complete=false`、`securityVerified=false`；无违反项的门禁仍是 `REVIEW`。
