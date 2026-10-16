# 如何编写业务语义规则包

适用版本：0.8.0。本文说明当前已实现的能力，不把未来扩展当成现有功能。

## 1. 哪些 UNKNOWN 可以靠补规则包处理

可以处理一部分，不能全部处理。当前外部 JSON 是 **真实 API 语义合同**：把应用接口映射到内置检测机制，而不是任意编写新检测逻辑的脚本插件。

0.7.0 验收基线中，三个项目共 78 项 UNKNOWN，其中 21 项来自七条 Business 专项规则，57 项来自通用 Java/Python 规则。专项规则中，9 项缺映射、5 项证据不足、7 项暂不支持；通用规则的 57 项均为证据不足。这是评估记录数，不是独立漏洞数。

0.8.0 通过单次共享语义分析，把外部合同证据供给 4 条同义通用规则：Java `AI-GUARD-002`、`AI-L2-003`，Python `AI-PY-005`、`AI-PY-002`。其中检索权限同时需要同位置的身份及文档 ACL 结果；局部观察不能替代未覆盖路径。其他通用规则尚未复用该语义，不应期待补一份 JSON 就关闭原 57 项通用 UNKNOWN。

| 缺口 | 规则包能做什么 | 不能替代什么 |
| --- | --- | --- |
| 找不到实际模型、权限检查或输出 API | 映射真实来源、检查和输出边界 | 不能虚构应用没有的控制 |
| 参数、返回值或接收者角色不清楚 | 指明身份槽、资源槽、布尔/对象判定与受限接收者 | 不能用声明证明任意动态实现、反射或复杂别名 |
| 控制语义或资源范围缺依据 | 取得审查依据后记录候选/已审查、失败语义、公开/受限范围 | 不替代实现审查、业务权限制度与部署负测 |
| 跨函数、异步、流式路径或预算不支持 | 给已有分析能力提供准确语义 | 不能用 JSON 增加未实现的控制流或时序模型 |
| 通用规则 UNKNOWN | Guard 和检索权限四条规则可消费同义语义证据 | 其他规则与尚未覆盖的路径仍需扩展，不用局部 OBSERVED 覆盖整体 UNKNOWN |

原 9 项缺映射均为 `NO_RESOLVED_MAPPED_SINK`：CodeBuddy 是两条客户场景规则；wm-sales-atlas-analysis 是两条客户场景规则以及文档权限、工具能力规则；RAG 项目是两条客户场景规则和工具能力规则。先确认业务是否存在，再映射真实边界。调整 profile 是改变评估范围，不是证明安全；补完 sink 后也可能转为其他 UNKNOWN 或发现 VIOLATED。

## 2. 一个可维护的包应包含什么

建议按下列目录管理。**扫描器只读取显式指定的 JSON，其余文件是配套审查和测试资料，当前不会自动加载。**

```text
business-rule-pack/
  contracts.v2.json       # 真正被扫描器加载的 API 合同
  review.md              # 适用场景、接口实现、审查人、日期、依赖版本与证据
  changelog.md            # 包的发行版本与语义变化
  fixtures/
    protected/           # 有效使用控制的合成用例
    violated/            # 忽略结果、错值校验、先释放等反例
    unknown/             # 动态绑定、证据不足、能力不支持
  expected.json          # 各用例预期规则与处置，供验收程序使用
```

`version: 2` 是合同格式版本，不是自定义包的发行号。当前 JSON 顶层只支持 `version`、`contracts`、`receivers`、`sourceDigests`；不要直接添加 `author`、`description`、`tests` 等字段，否则加载会拒绝。审查说明和包版本放在旁边的文档。

| 内容 | 关键字段 | 编写要点 |
| --- | --- | --- |
| API 身份 | `symbol`、`arity` | Java 用全限定类型 `#` 方法；Python 用精确模块/类来源；同一 symbol/arity 只能登记一个角色 |
| 数据来源 source | `label` | 区分敏感数据、模型输出、可信或不可信身份；不按参数名授信 |
| 转换 transform | `control`、`arg` | 脱敏追踪实际返回值；`preserve` 只能用于已审查的透明传递 |
| 校验 check | `control`、`args`、`accept`/`mode`、`decision` | 说明检查哪些值、什么结果允许、结果对象如何判定；存在调用不等于生效 |
| 输出或执行 sink | `channel`、`args`、`identity`、`boundary` | 明确外发、资源访问、检索、用户输出或工具执行；可用 call/return/yield 边界 |
| 资格与失败语义 | `assurance`、`failureMode`、`scope` | 未确认用 candidate/unknown，不能为了减少 UNKNOWN 写 reviewed/closed/public |
| 真实调用适配 | `parameterNames`、`defaults`、`receivers` | 参数名与默认值支持受限 Python 调用；当前 receivers 仅由 Python 适配器用于受限 `self.field.method`，不用于配置 Java 的任意依赖注入 |
| 精确数据边界 | `valuePath`、`when`、`requiresLabel` | 定位对象/事件中的实际内容，区分内容事件与状态事件 |
| 源码快照 | `sourceDigests` | 绑定已审查源码摘要；源码变化需复核，不能只替换摘要以继续放行 |

限制：文件最多 64 KiB，256 条合同、128 条 receiver、16 个源码摘要，单个 arity 为 0–32。未知字段、重复键、重复 selector 和越界槽位会被拒绝。目前不支持自动合并多个包、任意新增 rule ID、规则热加载或通过 MCP 请求替换策略。

`sourceDigests` 可省略，表示不绑定快照；一旦声明，须包含 1–16 个不重复的 64 位小写十六进制摘要，不能填写空数组。

## 3. 最小 Guard 示例

完整可解析 JSON 见 [虚构 Guard 合同](../examples/business-guard-contracts.example.json)。三个接口分别描述：

1. `example.Port#generate/0`：返回模型输出。
2. `example.Port#allow/1`：检查第 0 个参数，返回 true 才允许，假定其已审查为失败阻断。
3. `example.Port#publish/1`：第 0 个参数是用户输出边界。

关键的 check 合同如下：

```json
{
  "symbol": "example.Port#allow",
  "arity": 1,
  "kind": "check",
  "control": "guard",
  "args": [0],
  "accept": true,
  "failureMode": "closed",
  "assurance": "reviewed"
}
```

这些是虚构 API。这里的 reviewed/closed 是合成用例的明确假设，不能原样赋予真实接口。v2 的 assurance 默认 reviewed，因此实际编写时建议显式填写，未审查接口明确写 candidate；failureMode 默认 unknown。

对应代码关系：

```java
String text = Port.generate();
if (!Port.allow(text)) {
    return;
}
Port.publish(text);
```

验收至少覆盖下列差异，只核对 Guard 规则，其他未映射规则可能仍 UNKNOWN：

| 用例 | 应有的局部判断 |
| --- | --- |
| 检查同一 text，拒绝分支终止，再 publish(text) | OBSERVED；不代表应用认证通过 |
| 调用 allow(text) 但忽略返回值，再 publish(text) | VIOLATED |
| 先 publish(text)，后 allow(text) | VIOLATED；后置检查不能补救已释放边界 |
| 完全相同的代码，但检查 assurance 为 candidate | UNKNOWN |

上述四种用例已使用 0.7.0 成品 JAR，在真实 JDK 1.7.0_79 与 1.8.0_40 分别运行，8 次扫描的 Guard 处置均符合表中预期。这是虚构合同的局部验证，不是三个目标项目的新一轮安全验收；记录保存在本地 `scan-results/business-rule-pack-example-20261015.json`。

对真实 Guard 还要覆盖检查返回对象、异常/超时、回退内容、错误变量、替换数据、流式首包以及调用方取消。对象判定写 `decision`；抛异常式断言使用 `mode: "normal-return"`；不应把日志、质量评分或名称含 guard 的方法直接当安全控制。

## 4. 身份隔离与文档 ACL 怎么映射

假设真实检索接口为 `retrieve(principal, query, allowedScope)`，受限资源的 sink 可写：

```json
{
  "symbol": "example.Search#retrieve",
  "arity": 3,
  "kind": "sink",
  "channel": "retrieve",
  "identity": 0,
  "args": [1, 2],
  "scope": "restricted",
  "assurance": "reviewed"
}
```

它要求校验绑定 **同一个主体、query、allowedScope，且顺序一致**。需要对应可信身份 source、`scope` 检查及 `doc-acl` 检查；retrieve 同时参与 IAM 和文档权限评估。真实检查的参数顺序若不同，用 check.args 归一化。实际接口没有身份参数时写 `identity: -1`，保留缺口；不能把 query 或 top_k 当身份。

例如授权检查仅验证 `(principal, documentIds)`，实际检索却接收另一个过滤条件，不能在 JSON 中声称两者等价。应先证明值之间的关系，必要时扩展分析器或修改应用接口。单一 selector 不能重复登记为 scope 和 doc-acl 两个角色。

从 0.9.0 起，若同一检查返回对象必须满足多个布尔条件，可使用 `decision.all`（详见 [复合判定格式](bank-semantic-mappings.md#090-复合结果判定)）。例如“允许且无需二次审核”要声明两个叶子，并消费同一对象的两个结果；不能把 `allowed` 一个字段当成全部准入政策。该扩展只消除表达式分析缺口，不自动提高 `assurance` 或确认生产业务矩阵。

RAG 应覆盖实际存在的向量检索、关键词检索、混合召回、重排与缓存读取边界。`scope: public/restricted`、共享和撤权规则需业务/数据权限依据；配置里一个 `filter` 字段不能替代文档授权证明。

## 5. 编写、加载与验收流程

1. 从报告 `unknownReasons` 和 `reviewActions` 选取 `MAP_API` 项；先处理真实存在且位置明确的 API，其他事项分别分派。
2. 查真实定义及调用：入参/返回、调用资格、接受/拒绝、异常、缓存和输出位置；审查证据写入 review.md。
3. 先完整映射来源、控制和真实边界，再补关键字参数、字段投影与条件事件；不要只加一条 check。
4. 用正常、违反、未知三类合成用例检查映射是否真能区分结果，尤其防止错值/错主体也获得 OBSERVED。
5. 先扫描取得 `sourceDigest`，完成源码审查后写入 `sourceDigests`。只接受已审查摘要；摘要不是部署版本或权限系统的证明。
6. 将 JSON 放在操作员管理、被扫描仓库及 MCP 允许根目录之外，用启动参数加载，重新启动 MCP 后复扫。
7. 检查 `sourceDigestMatched`、实际命中调用和边界、`argumentBindingFailures`、逐位置原因、候选资格和截断；对比报告而不是只数 UNKNOWN。
8. 必须人工确认的身份信任、文档业务范围、控制职责以及部署负测仍单独留档。不要把工程验收当应用安全通过。

下面都是路径占位符，替换为实际目录；输出目录也应独立于应用目录：

```bash
/absolute/jdk7/bin/java -jar /absolute/ai-guardrail-scanner.jar \
  scan /absolute/application \
  --output /absolute/reports \
  --profile bank-common \
  --bank-policy /absolute/operator/business-rule-pack/contracts.v2.json
```

`generic` 可加载合同而不输出 BANK 评估；`bank-common` 启用共性三条；文档权限场景使用 `bank-internal`，确实覆盖全部业务场景再用 `bank-all`。类名已改为 Business，但参数和 rule ID 保留既有命名兼容。同一份合同在 generic 和业务 profile 下使用相同语义解释器，按所选 profile 控制业务专项输出。MCP 的 `guardrail_scan_start` 仍只接受 repository，不能在请求中临时传 policy；当前没有独立的 validate-policy CLI 子命令，解析校验在加载/启动时执行。

验收以报告和任务状态为准：扫描退出码 1 表示发现违反，2 可表示证据未完整或执行错误，不能只看退出码区分二者。不要把某条 Guard 为 OBSERVED 或缺映射数量减少解释为整个应用安全通过。

更多字段与完整约束见 [语义合同文档](bank-semantic-mappings.md) 和 [规则机制说明](banking-rules.md)。
