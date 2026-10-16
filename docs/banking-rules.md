# 银行规则包与操作员合同

本版在原有 Java/Python 规则上增加七条银行规则，检查数据出站、身份与资源绑定、Guard 失败阻断，以及客销和行内助手的指定控制路径。它使用操作员提供的 API 语义合同，在有界的局部源码路径上追踪“来源 → 转换或校验 → 输出或执行点”。

扫描不会导入 Python 模块、运行应用、执行构建脚本、调用模型或向外发送源码。合同不是 API 实现正确性的证明；本版不作银行合规认定或安全认证。

## 选择规则包

`--profile` 由 CLI 调用方或 MCP server 启动方指定，默认值为 `generic`。

| profile | 原有规则 | 新增银行规则 | Java 与 Python 均适用时的规则 ID 数 |
|---|---|---|---:|
| `generic` | Java 19 条、Python 7 条 | 无 | 26 |
| `bank-common` | 保留 | DATA、IAM、GUARD | 29 |
| `bank-customer` | 保留 | 共性三条 + CUST 两条 | 31 |
| `bank-internal` | 保留 | 共性三条 + INTERNAL 两条 | 31 |
| `bank-all` | 保留 | 全部七条 | 33 |

单一语言项目仅产生该语言适用的原有规则评估；银行规则按 profile 选择。规则 ID 数与评估记录数不同，同一 ID 可以产生多条原有规则评估。

MCP 保持五个工具：`guardrail_rules`、`guardrail_scan_start`、`guardrail_scan_status`、`guardrail_scan_cancel`、`guardrail_scan_result`。`guardrail_rules` 始终返回完整的 33 条规则目录，目录不表示本次扫描启用了所有规则。

`guardrail_scan_start` 只接受 `repository`；请求不能覆盖 profile、合同或允许扫描的根目录。仓库内的文件、注释也不能选择较宽松的策略。修改启动配置后，需重启或重新连接 MCP server。

## 七条银行规则

| 规则 | 包 / 领域 | 根据合同检查的局部关系 |
|---|---|---|
| `BANK-DATA-001` | 共性 / L3 | 已声明为敏感的数据到达 `egress` 时，是否实际使用 `redaction` 的返回值。仅调用脱敏函数而继续发送原值不能覆盖。未分类的数据保持 UNKNOWN。 |
| `BANK-IAM-001` | 共性 / L2 | `access` 和 `retrieve` 的身份是否来自 `trusted-identity`，并且存在接受分支上的 `scope` 校验，绑定同一身份与同一组资源值。 |
| `BANK-GUARD-001` | 共性 / L7 | `release` 前是否使用同一输出值的 `guard` 校验结果；拒绝后返回或抛出才能停止该路径。先释放再校验、忽略结果、拒绝后继续释放、异常回退释放均不能借校验调用获得覆盖。 |
| `BANK-CUST-001` | 客销 / L7 | `recommend` 前是否存在同一推荐数据的 `facts` 校验接受分支。合同声明该 API 检查事实与时效，扫描器不自行判断产品条款或日期是否正确。 |
| `BANK-CUST-002` | 客销 / L7 | `recommend` 是否使用可信身份，并接受了绑定同一身份与推荐数据的 `suitability` 校验。它不代替业务适当性规则。 |
| `BANK-INTERNAL-001` | 行内 / L2 | `retrieve` 前是否接受绑定同一身份与文档范围的 `doc-acl` 校验；此通道同时触发共性 IAM 检查。 |
| `BANK-INTERNAL-002` | 行内 / L2 | `tool` 前是否接受针对同一组工具输入、能力或操作参数的 `capability` 校验。需要参与授权的值必须进入合同的 `args`；扫描器不按工具名称推断权限。 |

没有映射到适用输出点时，规则输出 UNKNOWN。名称包含 `auth`、`mask`、`guard`、`risk` 等字样不构成合同，也不自动建立控制证据。

0.5.0 增加向后兼容的 [v2 真实语义映射与 UNKNOWN 分类](bank-semantic-mappings.md)，包括对象判定、参数缺省值和 return/yield 边界。下文合同字段说明以 v1 为基准，v2 差异以该文档为准。

## 从外部加载合同

合同是 UTF-8 JSON，必须显式传入 `--bank-policy`。文件由操作员维护，应放在被扫描仓库之外；MCP 启动时还会检查文件不在配置的允许根目录内。扫描请求会再次核验。目标应用不能通过提交仓库文件来替换合同。

[示例合同](../examples/bank-contracts.example.json) 含 40 条纯虚构映射，分别覆盖 Java `org.example.bank.Port` 和 Python `example_port` 的七条规则；没有真实业务数据。先把样例复制到操作员控制的外部目录，再根据实际可信 API 修改。不要把样例名称当作真实系统已接入的控制。

```sh
java -jar /opt/guardrail/ai-guardrail-scanner.jar scan /workspace/application \
  --output /var/tmp/guardrail-reports \
  --profile bank-all \
  --bank-policy /etc/guardrail/bank-contracts.json
```

MCP 启动示例：

```sh
java -jar /opt/guardrail/ai-guardrail-scanner.jar mcp \
  --allow-root /workspace/application \
  --output /var/tmp/guardrail-reports \
  --profile bank-all \
  --bank-policy /etc/guardrail/bank-contracts.json
```

这些是路径占位示例。应指定实际 Java 7 或 Java 8 可执行文件、打包产物和操作员目录。未传 `--bank-policy` 时启用空合同，银行规则保持缺少映射的 UNKNOWN；0.8.0 起 `generic` 也接受显式外部合同，为对应通用规则提供语义证据，但仍不输出 BANK 专项评估。当前只复用 Guard 与检索权限的同义关系，不扩展所有控制域。

合同顶层只有两个必需字段：

```json
{
  "version": 1,
  "contracts": []
}
```

未知字段、缺失字段、重复 JSON key、重复 `symbol/arity`、未知 profile、无效参数槽会被拒绝。当前上限为 64 KiB、256 条合同；`arity` 为 0–32 的整数。文件必须是普通文件，路径中的符号链接会被拒绝。

## 调用身份与参数槽

每条合同必需 `symbol`、`arity`、`kind`，其余字段由 `kind` 决定。

- Java 使用全限定类型与方法，例如 `org.example.bank.Port#release`。适配器依据导入和可解析类型关系定位调用，不按短方法名匹配。
- Python 使用精确导入来源，例如 `example_port.release`；`from example_port import release as publish` 仍可定位同一来源。受限的局部单次工厂绑定也可形成 `supplier.Client.send` 形式，表示“导入调用来源及其返回对象的方法合同”，不证明运行时对象确属某个类。
- `arity` 是源码调用的实际参数数量，不含接收者。参数槽从 0 开始。Python 关键字参数、`*args`、`**kwargs` 不能据名称或顺序猜测槽位，保持未知。
- 遮蔽、重新赋值、属性修改、重复或条件导入、无法解析的动态调用不能沿用原调用身份。Java 同参数个数的重载及动态分派也可能需要复核。

`args` 的顺序参与同值校验匹配，并非集合。它允许把实际 API 参数顺序归一化：若实际校验调用是 `check(resource, principal)`，供身份绑定规则使用的 `check.args` 应为 `[1, 0]`，即身份在前、资源在后。

对于 `access`、`retrieve`、`recommend`，输出点用单独的 `identity` 指定身份槽，`args` 指定数据槽；引擎按“身份 + 数据槽顺序”寻找相应校验。身份槽不能再出现在该输出点的 `args` 中。

其他通道不接受 `identity` 字段。`tool` 如需绑定员工身份、工具名和输入，应把这些值按同一顺序全部放入输出点与 `capability` 校验的 `args`；规则只观察这组参数绑定，不独立证明身份认证实现。

## 四类合同

### `source`：声明返回值来源

除公共字段外，必需 `label`，可取：

| label | 含义 |
|---|---|
| `sensitive` | 返回值需作为敏感数据追踪。 |
| `trusted-identity` | 操作员声明该 API 从服务端可信认证上下文返回身份。 |
| `untrusted-identity` | 操作员声明该身份由请求、模型或其他不可信渠道提供。 |
| `model-output` | 模型输出来源。 |
| `knowledge` | 知识或文档范围来源。 |
| `recommendation` | 推荐数据来源。 |
| `tool-input` | 工具输入来源。 |

后四类保留明确来源，不自行赋予安全性、正确性或权限。`source` 返回值的业务含义是操作员假设；给用户传入的账号接口标记 `trusted-identity` 会破坏检查前提。应先审查接口实现，再登记合同。

### `transform`：使用脱敏结果

必需 `control: "redaction"` 和输入槽 `arg`。只有返回值标记为已转换；扫描器不把一次原地修改调用当成返回值已替换。

```python
from example_port import sensitive_data, redact, send

payload = sensitive_data()
safe_payload = redact(payload)
send(safe_payload)
```

若最后一行变成 `send(payload)`，不能借 `redact(payload)` 的存在获得脱敏覆盖。脱敏方法是否真正去除敏感内容，仍需实现审查与运行测试。

### `check`：声明布尔结果的接受含义

必需 `control`、非空的 `args` 和布尔字段 `accept`。`control` 可取 `guard`、`scope`、`facts`、`suitability`、`doc-acl`、`capability`。

`accept: true` 表示返回 `true` 才允许；`accept: false` 适用于返回 `true` 表示拒绝的 API。校验调用本身不建立允许关系，结果必须用于控制分支。示例合同将 `guard_rejected` 声明为 `accept: false`：

```python
from example_port import model_output, guard_rejected, release

def answer():
    output = model_output()
    if guard_rejected(output):
        return
    release(output)
```

扫描保留否定与支持范围内的布尔比较语义。校验错误变量、丢弃返回值、在放行后替换数据、用无关条件放行，都不能复用原校验证据。未知调用可能修改对象，相关值和已生效的校验会被保守失效。

### `sink`：声明输出或执行点

必需 `channel` 与非空的 `args`。以下通道由引擎固定组合规则：

| channel | 必须有 `identity` | 触发的银行检查 |
|---|---|---|
| `egress` | 否 | DATA |
| `access` | 是 | IAM |
| `release` | 否 | GUARD |
| `recommend` | 是 | CUST-001 与 CUST-002 |
| `retrieve` | 是 | IAM 与 INTERNAL-001 |
| `tool` | 否 | INTERNAL-002 |

同一个 `symbol/arity` 只能声明一条合同。若业务过程有推荐、用户展示及外部发送三个不同边界，应分别映射实际调用点；不能添加多条同名合同来假定同一边界已经具备所有控制。输出点返回内容未知，不自动视作已校验的数据。

## 报告与门禁

JSON、Markdown、SARIF 记录所选 `policy`，包括 profile、`bank-policy-v1/v2`、合同数和策略摘要；源文件摘要 `sourceDigest` 与策略摘要分开。源码不变而策略不同，应作为不同评估条件保留。

银行证据包含相对路径、行号、受控描述以及 `source`、`transform`、`control`、`sink` 角色和 `nodeId`。它们用于复核局部来源关系，不包含原始提示词、客户数据或合同正文。

- `VIOLATED`：在操作员合同前提下，找到缺少所需同值控制的可分析局部路径。
- `OBSERVED`：在已建模范围观察到同值控制使用；不证明被调用实现、部署或运行时行为正确。
- `UNKNOWN`：缺少映射、来源不明、存在不支持的语义、解析失败或预算不足；不代表通过。

任意规则产生 `VIOLATED`，`gateDecision` 为 `BLOCK`；其余为 `REVIEW`。当前静态扫描始终 `complete=false`、`securityVerified=false`，不输出 `ALLOW`。MCP 状态与报告使用相同门禁。CLI 扫描发现违反时退出码为 1，证据不完整或失败时为 2，取消为 130；退出码 2 不应被 CI 当作通过。

## 适用边界与运行验收

本版主要覆盖函数内部的有限赋值、直接调用、布尔分支、返回/抛出及 try/catch 或 try/except/finally。异常分支按可能抛出处理，不以“通常不会失败”跳过。以下仍可能需要人工或受控运行验证：

- 跨函数及对象字段状态、继承分派、工厂链、反射、Python 装饰器、动态导入与别名修改。
- 复杂容器、拼接、推导式、循环和其他未完整建模的表达式；观察到数据传递不等于已证明其精确值。
- 真实超时、异步取消、并发、重试、模型切换、流式内容已发送后的处理及外部系统授权效果。
- 数据分类和脱敏有效性、认证强度、文档 ACL 正确性、事实及有效期判定、业务适当性、工具能力政策的正确实现。
- 配额、模型准入审批、审计留存及完整治理制度。这些没有因为七条局部规则而获得合规结论。

未建模语义会保留 UNKNOWN 或诊断；有限路径、节点和证据预算意味着报告不是穷尽证明。应配合跨主体访问、拒绝、异常、超时、流式释放及错误映射反例进行运行验收。

JDK 7/8 支持指扫描器的语法、字节码和原生运行兼容。它不代表旧 JDK 的补丁、安全维护或银行部署资格得到认可；部署方仍需独立管理受支持运行环境、依赖风险与补丁。
