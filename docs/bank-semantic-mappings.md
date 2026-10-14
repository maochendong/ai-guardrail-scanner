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

`mappingCoverage` 分别给出合同定义数、源码匹配声明数、实际命中调用位置、return/yield 边界、候选绑定、参数绑定失败与分析函数数。位置计数按相对路径、行号和符号去重，同一行同一 API 多次调用可能合并；这些是映射使用统计，不是安全覆盖率。仅有声明不会计作实际调用。

## 保留的分析边界

本轮支持常量 Map/字典字段、显式构造器和值载体、对象判定、受限 Python receiver 和默认参数，未实现完整跨过程分析。循环/yield、异步 callback、复杂别名、动态分派和数据库级资源绑定仍可能 UNKNOWN。受限循环体中的候选操作只用于暴露待复核位置，不证明执行顺序或所有迭代。

`OBSERVED` 仅表示已建模的局部路径和操作员合同前提下观察到控制使用。所有报告仍为 `complete=false`、`securityVerified=false`；无违反项的门禁仍是 `REVIEW`。
