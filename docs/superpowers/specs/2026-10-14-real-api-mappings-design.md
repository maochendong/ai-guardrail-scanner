# 真实 API 映射与 UNKNOWN 原因设计

用户已要求继续实现、验证并推送；沿用银行外置合同、静态证据不等于安全认证的已确认边界。

## 范围和取舍

对三个授权项目进行只读源码审查，记录实际 API、参数、返回判定、输出边界和源码摘要。真实合同放在操作员私有目录，不把项目名称写进规则引擎，不执行目标应用。公开仓库提供通用能力、改名合成测试、使用文档和不含源码的验收汇总。

采用源码审查加外置合同。自动按 auth/guard/userId 名称授信会造成错误结论；完整动态验证需要目标运行环境和身份数据，不在本轮静态范围内。接口没有认证主体、没有文档密级证据、只有质量校验时，映射必须明确这种不足，不能补造 trusted-identity、scope 或 doc-acl。

## 向后兼容的合同 v2

保留 v1。v2 可选 sourceDigests 数组绑定审查快照；摘要不匹配时禁用该合同的银行评估，报告缺少有效映射，通用规则照常扫描。

合同仍以全限定 symbol、声明 arity 和 kind 标识。新增可选功能：parameterNames/defaults 归一化关键字和省略参数；source 的 outboundArgs 表示同一 API 兼具请求出站和返回来源；check 的 decision 指定返回对象的精确判定 accessor（arg=-1 表示接收者），mode=normal-return 表示异常中止的断言；transform preserve 表示操作员审查的值载体。assurance=candidate 不产生已覆盖证明，failureMode=open/unknown/closed 与布尔接受路径分开。

sink 的 boundary 可为 call/return/yield；返回边界的虚拟参数为返回值加函数实参，valuePath 选择结构化字段。requiresLabel 限定模型输出来源，避免固定错误提示误报。identity=-1 明确 API 无身份槽；scope=unknown 时不能把未知数据范围直接判为越权。

Python 接收者映射通过 owner/field/type 声明，并带 reviewed/candidate 来源可信度；保留注入或动态替换的不确定性。通用 IR 保留属性、容器、构造器、关键字和 yield；未建模循环/回调/跨过程状态仍标暂不支持，不凭合同隐藏。

## 原因与报告

每条 UNKNOWN 有主分类 unknownCategory 和受控 unknownReasons：MISSING_MAPPING（缺少有效映射）、INSUFFICIENT_EVIDENCE（证据不足）、UNSUPPORTED（暂不支持）。旧规则无定位证据归证据不足，不能自动认定不适用。诊断中的跳过/截断/语法边界另列分类，不强行把全局诊断归因于所有发现。

已知映射的调用、定义/消费、候选绑定及返回路径分别统计；只有定义而无调用的检查不能算已接入。所有格式保留分类、策略摘要和 BLOCK/REVIEW，complete/securityVerified 始终 false。

## 验收

通用正反例覆盖对象判定、参数顺序/默认值、未知接收者、断言异常、载体/返回输出、无身份检索、candidate 控制、过期映射，以及三种 UNKNOWN。真实 JDK 7/8 全量 JUnit、MCP 双 JVM、三个项目及新 Codex 会话均重新验证。保存目标 Git 状态和源码摘要，检查通用旧证据差异，明确仍未支持的路径后提交并推送。
