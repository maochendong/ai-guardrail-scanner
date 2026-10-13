# 自定义模型网关、Guard 调用链与 Function Calling 扩展

用户已授权继续实现、泛化规则并在两个真实项目复验；随后明确加入 function calling。沿用只读、离线、证据导向边界，不另设实现审批。

## 选择与范围

采用模型协议证据结合有界 Java 调用图。纯类名或方法名启发式不能证明模型来源或 Guard 语义；全程序控制流、完整框架装配和运行时验证超出本轮范围。源内自定义包装、接口候选和局部数据关系必须留下不确定性。

不包含任何目标项目名称、包名、业务类型名或供应商专属配置键的匹配规则。目标项目仅作为只读验证输入。JSON 协议键、标准 HTTP/日志/SSE API 和 Java 语言构造可作为通用协议适配规则。

## 模块

1. `LocalCallGraph`：索引源码类型/方法，解析局部 receiver、声明类型、工厂返回类型、接口候选和方法委托。声明定位不代表调用执行，也不代表实际 Spring Bean 已确定。重复类型、重载歧义和动态调用不得随意选取目标。
2. `GatewayModel`：以真实 HTTP 调用与相关模型请求/响应协议组合识别网关；追踪明确返回委托及有限局部来源；对流式 Consumer 参数单独建立摘要。普通 HTTP、仅有关键词、无关返回值不得成为模型来源。
3. `CustomGuardRules`：记录网关入口/委托/网络边界，以及与输入/输出值相关的局部判定、拒绝分支、发送顺序和原始内容日志。检查函数名称不作为控制含义或有效性证明。
4. `FunctionCallingRules`：标准 `tool_calls/function/name/arguments` 或已确认模型来源的自定义 JSON 分派，追踪到注册表/固定分支/动态执行；分别呈现工具选择限制、参数处理与独立上下文参数。JSON 解码和 Schema 声明不等于执行时参数校验，独立身份参数不等于可信身份与授权。
5. `Scanner`：同一次清点构建共享图与模型分析，合并既有规则和新规则/诊断/模型识别元数据。既有 11 条 Spring AI 规则保持原义，新规则不依赖 Spring AI 版本。

## 共享接口

`LocalCallGraph.build(SourceProject, BooleanSupplier)`；`methods()`、`callsFrom(MethodId)`、`resolve(MethodCallExpr)`、`reachable(MethodId,int)`、`method(MethodId)`、`enclosing(Node)`、`qualifiedType(Node,String)`、`expressionType(Expression)`、`diagnostics()`。

内部记录 `MethodId(path,ownerFqn,name,parameterTypes,line)`、`MethodInfo(id,source,declaration)`、`Edge(caller,callsite,targets,resolution,reasons)`。`Resolution` 分为 RESOLVED/CANDIDATE/UNKNOWN，AST 不出现在外部报告。

`GatewayModel.build(SourceProject,LocalCallGraph,BooleanSupplier)`；`gateways()`、`origin(Expression)`、`isInvocation(MethodCallExpr)`、`participatingMethods()`、`trace(MethodCallExpr)`、`diagnostics()`。

内部记录 `Gateway(method,protocol,streaming,callbackArguments,evidence)`、`Origin(evidence,candidateDispatch)`。候选运行时分派不能支持确定的违反结论。

两个新规则模块各提供 `catalog()` 和 `assess(SourceProject,LocalCallGraph,GatewayModel,BooleanSupplier)`。评估沿用已有结构，调用链步骤按证据位置及受控说明呈现，不导出代码或配置原文。

## 结果边界

- `OBSERVED`：明确记录协议构造、调用边、判定消费或局部拒绝结构；不等于防护成功。
- `VIOLATED`：仅支持来源与执行/输出位置均有直接证据的具体危险模式，例如已确认模型输出直入日志/危险执行，或相同输出已经发送后才被明确拒绝分支检查。
- `UNKNOWN`：动态分派、跨集合/异步关系、未支持的输入变换、实际参数校验、业务授权或完整控制覆盖无法确定时独立保留。
- Guard 声明、工具注册、Schema 出现或零违反均不能成为安全通过依据。所有报告恒定 `securityVerified=false`。

## 预算与失败

图最多 30,000 方法、100,000 调用、单调用 16 个候选、可达深度最多 8。解析、来源跟踪和候选扩展均检查取消，达到预算产生诊断并降低完整性。外部类型不下载依赖或执行反射；外部 HTTP API 仅匹配已有 AST 声明。原有文件、字节、任务和报告预算继续有效。

## 验收

1. 通用人工 fixture 覆盖网关协议、委托、工厂、接口、多实现、重载、命名遮蔽、回调流式和未知封装。
2. 包/类/业务方法重命名后核心判断不变；普通 HTTP、注释、同名 Guard 和与模型值无关的检查不误报。
3. 判定未消费、先发后查、仅另一个变量被检查、条件检查、catch/fallback、流式独立路径均不虚报已保护。
4. Function calling 覆盖固定分支/注册表、未知工具拒绝、参数解析与校验区别、模型参数伪装身份和危险动态执行；标准和自定义协议均需来源证据。
5. 保持旧测试通过，新代码加入有意义反例；打包 JAR 实际 MCP 流程通过。
6. 安装新版本独立副本并更新 Codex 原 server 配置，完整复扫 codebuddy 和 wm-sales，读取三种格式并比较原先 11 项 UNKNOWN 的覆盖变化。真实项目不要求人为凑出违规；未支持的路径继续如实未知。
