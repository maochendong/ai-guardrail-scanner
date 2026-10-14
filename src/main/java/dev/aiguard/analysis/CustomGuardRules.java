package dev.aiguard.analysis;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import dev.aiguard.analysis.rules.AstSupport;
import dev.aiguard.model.ScanModel.*;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

/** Structural evidence only: application identifiers never define a guard's security semantics. */
public final class CustomGuardRules {
    private CustomGuardRules() {}
    private static final List<String> LIMITS=List.of(
        "自定义类型与业务方法名称不用于证明模型或安全控制；使用协议、源码调用关系和局部数据证据。",
        "接口/虚调用候选不等于实际 Bean；调用图不证明调用必然执行，复杂分支、集合、反射及异步传播仍可能未知。",
        "判定结果参与局部退出只表示结构存在，不证明拒绝极性、检查算法、权限或全路径防护有效。",
        "同一规则的 UNKNOWN 独立保留；每种证据最多 40 个位置，OBSERVED 不表示安全通过。");
    private static Rule rule(String id,Domain domain,String title,String description,String advice) {
        return new Rule(id,domain,title,description,advice,List.of());
    }
    private static final List<Rule> RULES=List.of(
        rule("AI-GW-001",Domain.L1,"自定义模型协议与调用链","依据 HTTP 调用和关联模型协议识别边界，记录有界源码委托关系。","核实部署时实际模型实现、协议适配及所有调用入口。"),
        rule("AI-GW-002",Domain.L3,"自定义网关响应日志","跟踪有协议来源的原始模型响应直接进入 SLF4J 日志；分派不确定时保留未知。","避免记录原始模型响应；核实脱敏、日志级别、访问与保留策略。"),
        rule("AI-GUARD-001",Domain.L1,"网关前的局部拒绝分支","识别可到达模型边界的方法内，自定义判定结果控制提前退出的局部结构。","核实判定的真实输入、拒绝含义及正常/备用路径覆盖；不能仅以调用顺序认定安全。"),
        rule("AI-GUARD-002",Domain.L7,"模型输出判定消费","跟踪模型值进入源码内布尔判定或布尔结果记录，并检查结果是否用于提前退出。","消费检查结果并建立明确拒绝路径；核实检查输入、输出值及全路径一致性。"),
        rule("AI-GUARD-003",Domain.L5,"输出释放与局部判定顺序","区分 SSE 发送同一模型值之前或之后的局部拒绝判定，流式路径单独评估。","在向外释放对应内容之前完成判定；集合、跨方法与回调传输需要单独验证。")
    );
    public static List<Rule> catalog() { return RULES; }
    private record CheckSite(MethodCallExpr call,Expression payload,IfStmt decision,GatewayModel.Origin origin) {}

    public static List<Assessment> assess(SourceProject project,LocalCallGraph graph,GatewayModel model,BooleanSupplier cancelled) {
        Map<String,Bucket> buckets=new LinkedHashMap<>();
        RULES.forEach(r->buckets.put(r.id(),new Bucket(r)));
        for(var gateway:model.gateways()) {
            check(cancelled);
            buckets.get("AI-GW-001").add(Disposition.OBSERVED,gateway.evidence());
        }
        for(var method:graph.methods()) {
            check(cancelled);
            List<MethodCallExpr> calls=method.declaration().findAll(MethodCallExpr.class);
            List<CheckSite> decisions=new ArrayList<>();
            for(var call:calls) {
                check(cancelled);
                if(graph.enclosing(call).map(m->!m.id().equals(method.id())).orElse(true)) continue;
                if(model.isInvocation(call)) {
                    buckets.get("AI-GW-001").add(Disposition.OBSERVED,model.trace(call));
                    buckets.get("AI-GW-001").add(Disposition.OBSERVED,evidence(method,call,"此调用可沿有界源码关系到达已识别的模型协议边界；运行时分派另行核实。"));
                }
                if(AstSupport.logger(call)) for(Expression argument:call.getArguments()) {
                    var origin=model.origin(argument);
                    if(origin.isPresent()) {
                        var state=origin.get().candidateDispatch()?Disposition.UNKNOWN:Disposition.VIOLATED;
                        buckets.get("AI-GW-002").add(state,evidence(method,call,origin.get().candidateDispatch()
                            ?"候选网关响应直接进入日志参数；实际模型分派尚未确定。"
                            :"具有模型协议来源的原始响应直接进入日志参数；敏感内容、落盘和脱敏状态未验证。"));
                        buckets.get("AI-GW-002").add(state,origin.get().evidence());
                    }
                }
                Set<String> accessors=decisionAccessors(call,graph);
                if(accessors.isEmpty()) continue;
                IfStmt decision=consumingDecision(call,accessors,method.declaration());
                Optional<Expression> payload=call.getArguments().stream().filter(a->model.origin(a).isPresent()).findFirst();
                if(payload.isPresent()) {
                    var origin=model.origin(payload.get()).orElseThrow();
                    var state=decision==null?Disposition.UNKNOWN:Disposition.OBSERVED;
                    buckets.get("AI-GUARD-002").add(state,evidence(method,call,decision==null
                        ?"模型来源值进入自定义判定，但未确认该次返回结果控制局部拒绝退出。"
                        :"模型来源值进入源码内判定，该次结果被用于局部提前退出；检查算法与拒绝极性仍未证明。"));
                    buckets.get("AI-GUARD-002").add(state,origin.evidence());
                    if(decision!=null) {
                        buckets.get("AI-GUARD-002").add(state,evidence(method,decision,"判定条件的一侧分支明确 return 或 throw；不是完整控制流覆盖证明。"));
                        decisions.add(new CheckSite(call,payload.get(),decision,origin));
                    }
                } else if(decision!=null && model.participatingMethods().contains(method.id())) {
                    boolean precedes=calls.stream().anyMatch(c->model.isInvocation(c)&&ordered(decision,c));
                    if(precedes) {
                        buckets.get("AI-GUARD-001").add(Disposition.OBSERVED,evidence(method,call,"此自定义判定的返回结果参与模型调用前的局部提前退出；输入数据关联和业务含义未证明。"));
                        buckets.get("AI-GUARD-001").add(Disposition.OBSERVED,evidence(method,decision,"局部拒绝分支位于后续可达模型调用之前；其他路径仍需核实。"));
                    }
                }
            }
            for(var send:calls) {
                check(cancelled);
                if(!send.getNameAsString().equals("send")||!AstSupport.receiverType(send,"org.springframework.web.servlet.mvc.method.annotation.SseEmitter")) continue;
                for(Expression payload:sentPayloads(send)) {
                    var origin=model.origin(payload);
                    if(origin.isEmpty()) continue;
                    Optional<CheckSite> late=decisions.stream().filter(d->sameValue(d.payload,payload)&&ordered(send,d.decision)).findFirst();
                    Optional<CheckSite> early=decisions.stream().filter(d->sameValue(d.payload,payload)&&ordered(d.decision,send)).findFirst();
                    Disposition state=late.isPresent()||early.isPresent()?Disposition.OBSERVED:Disposition.UNKNOWN;
                    buckets.get("AI-GUARD-003").add(state,evidence(method,send,early.isPresent()
                        ?"发送同一值之前存在消费判定结果的局部退出结构；仍需验证拒绝语义和完整流覆盖。"
                        :late.isPresent()?"同一模型来源值先发送，后进入自定义判定的提前退出分支；该判定是否具有安全语义仍未知，不能据此确认违反。"
                        :"模型来源值进入 SSE 发送，未在支持的同一语句块范围内确认发送前拒绝判定。"));
                    buckets.get("AI-GUARD-003").add(state,origin.get().evidence());
                    late.ifPresent(d->buckets.get("AI-GUARD-003").add(state,evidence(method,d.decision,"已发送内容对应的局部判定发生在此处。")));
                }
            }
        }
        List<Assessment> result=new ArrayList<>();
        for(Bucket b:buckets.values()) result.addAll(b.finish(!model.gateways().isEmpty()));
        return List.copyOf(result);
    }

    private static Set<String> decisionAccessors(MethodCallExpr call,LocalCallGraph graph) {
        var edge=graph.resolve(call);
        if(edge.targets().isEmpty()||edge.targets().size()>16) return Set.of();
        Set<String> common=null;
        for(var id:edge.targets()) {
            var info=graph.method(id);
            if(info.isEmpty()||info.get().declaration().getBody().isEmpty()) continue;
            var method=info.get().declaration();
            boolean parameterUsed=method.getParameters().stream().anyMatch(p->method.getBody().orElseThrow().findAll(NameExpr.class).stream().anyMatch(n->n.getNameAsString().equals(p.getNameAsString())));
            if(!parameterUsed) return Set.of();
            Set<String> names=new HashSet<>();
            String type=method.getTypeAsString();
            if(type.equals("boolean")||type.equals("Boolean")||type.equals("java.lang.Boolean")) names.add("");
            String qualified=graph.qualifiedType(method,type);
            for(var record:info.get().source().unit().findAll(RecordDeclaration.class)) {
                String actual=graph.qualifiedType(record,record.getNameAsString());
                if(!qualified.isEmpty()&&qualified.equals(actual)) for(var p:record.getParameters()) if(p.getTypeAsString().equals("boolean")) names.add(p.getNameAsString());
            }
            // Java 8 result objects: only source-visible, no-argument accessors that
            // directly return a boolean field, not arbitrary is*/get* method names.
            for(var accessor:graph.methods()) {
                var getter=accessor.declaration();
                if(!accessor.id().ownerFqn().equals(qualified)||!getter.getParameters().isEmpty()
                    ||!getter.getTypeAsString().equals("boolean")||getter.getBody().isEmpty()) continue;
                var statements=getter.getBody().orElseThrow().getStatements();
                if(statements.size()!=1||!statements.get(0).isReturnStmt()) continue;
                var returned=statements.get(0).asReturnStmt().getExpression().orElse(null);
                String field=returned instanceof NameExpr n?n.getNameAsString():returned instanceof FieldAccessExpr f&&f.getScope().isThisExpr()?f.getNameAsString():"";
                Optional<TypeDeclaration<?>> owner=getter.findAncestor(TypeDeclaration.class).map(t->(TypeDeclaration<?>)t);
                if(!field.isEmpty()&&owner.isPresent()&&owner.get().getFields().stream()
                    .flatMap(f->f.getVariables().stream()).anyMatch(v->v.getNameAsString().equals(field)&&v.getTypeAsString().equals("boolean"))) names.add(getter.getNameAsString());
            }
            if(common==null) common=names; else common.retainAll(names);
        }
        return common==null?Set.of():common;
    }
    private static IfStmt consumingDecision(MethodCallExpr call,Set<String> accessors,MethodDeclaration method) {
        var initializer=call.findAncestor(VariableDeclarator.class).filter(v->v.getInitializer().map(e->e==call).orElse(false));
        for(IfStmt condition:method.findAll(IfStmt.class)) {
            if(condition.findAncestor(MethodDeclaration.class).orElse(null)!=method) continue;
            if(!condition.getCondition().findAll(AssignExpr.class).isEmpty()) continue;
            if(!terminates(condition.getThenStmt())&&!condition.getElseStmt().map(CustomGuardRules::terminates).orElse(false)) continue;
            if(accessors.contains("")&&condition.getCondition().findAll(MethodCallExpr.class).stream().anyMatch(c->c==call)) return condition;
            if(initializer.isEmpty()||!AstSupport.before(call,condition)) continue;
            var variable=initializer.get();
            boolean conditionMutation=condition.getCondition().findAll(MethodCallExpr.class).stream().anyMatch(c->
                c.getArguments().stream().anyMatch(a->references(a,variable))
                ||c.getScope().filter(s->references(s,variable)).isPresent()&&(!accessors.contains(c.getNameAsString())||!c.getArguments().isEmpty()));
            if(conditionMutation) continue;
            boolean changed=method.findAll(AssignExpr.class).stream().anyMatch(a->references(a.getTarget(),variable)&&AstSupport.before(call,a)&&AstSupport.before(a,condition));
            changed|=method.findAll(MethodCallExpr.class).stream().anyMatch(c->(c.getScope().filter(s->references(s,variable)).isPresent()||c.getArguments().stream().anyMatch(a->references(a,variable)))&&AstSupport.before(call,c)&&AstSupport.before(c,condition));
            if(changed) continue;
            boolean used=condition.getCondition().findAll(NameExpr.class).stream().anyMatch(n->AstSupport.declaration(n).orElse(null)==variable && (accessors.contains("") || n.getParentNode().filter(p->p instanceof MethodCallExpr c&&c.getScope().orElse(null)==n&&accessors.contains(c.getNameAsString())&&c.getArguments().isEmpty()).isPresent()));
            if(used) return condition;
        }
        return null;
    }
    private static boolean references(Expression expression,VariableDeclarator variable) {
        return expression.findAll(NameExpr.class).stream().anyMatch(n->AstSupport.declaration(n).orElse(null)==variable);
    }
    private static boolean terminates(Statement s) {
        if(s.isReturnStmt()||s.isThrowStmt()) return true;
        if(s.isBlockStmt()) return s.asBlockStmt().getStatements().getLast().map(CustomGuardRules::terminates).orElse(false);
        return s.isIfStmt()&&terminates(s.asIfStmt().getThenStmt())&&s.asIfStmt().getElseStmt().map(CustomGuardRules::terminates).orElse(false);
    }
    /** Only direct siblings in one block; text order across branches is not execution order. */
    private static boolean ordered(Node before,Node after) {
        Node a=directStatement(before),b=directStatement(after);
        return a!=null&&b!=null&&a!=b&&a.getParentNode().orElse(null)==b.getParentNode().orElse(null)&&AstSupport.before(a,b);
    }
    private static Node directStatement(Node node) {
        Node current=node;
        while(current.getParentNode().isPresent()) {
            if(current instanceof Statement) return current.getParentNode().get() instanceof BlockStmt?current:null;
            if(current instanceof LambdaExpr||current instanceof MethodDeclaration) return null;
            current=current.getParentNode().get();
        }
        return null;
    }
    private static boolean sameValue(Expression a,Expression b) {
        if(a instanceof NameExpr an&&b instanceof NameExpr bn) {
            var ad=AstSupport.declaration(an);var bd=AstSupport.declaration(bn);
            if(ad.isEmpty()||bd.isEmpty()||ad.get()!=bd.get()) return false;
            var owner=a.findAncestor(MethodDeclaration.class);
            if(owner.isEmpty()||owner.get()!=b.findAncestor(MethodDeclaration.class).orElse(null)) return false;
            Node first=AstSupport.before(a,b)?a:b,last=first==a?b:a;
            return owner.get().findAll(AssignExpr.class).stream().noneMatch(x->x.getTarget().isNameExpr()&&x.getTarget().asNameExpr().getNameAsString().equals(an.getNameAsString())&&AstSupport.before(first,x)&&AstSupport.before(x,last));
        }
        return a==b;
    }
    private static List<Expression> sentPayloads(MethodCallExpr send) {
        List<Expression> values=new ArrayList<>();
        for(Expression arg:send.getArguments()) {
            values.add(arg);
            for(var call:arg.findAll(MethodCallExpr.class)) if(call.getNameAsString().equals("data")&&call.getArguments().size()==1&&AstSupport.chainType(call,"org.springframework.web.servlet.mvc.method.annotation.SseEmitter")) values.add(call.getArgument(0));
            // SseEmitter.event() is a static factory, not a declared receiver expression.
            for(var call:arg.findAll(MethodCallExpr.class)) if(call.getNameAsString().equals("data")&&call.getArguments().size()==1&&AstSupport.chainCalls(call).stream().anyMatch(c->c.getNameAsString().equals("event")&&AstSupport.staticScope(c,"org.springframework.web.servlet.mvc.method.annotation.SseEmitter"))) values.add(call.getArgument(0));
        }
        return values;
    }
    private static Evidence evidence(LocalCallGraph.MethodInfo method,Node at,String detail) { return new Evidence(method.source().path(),AstSupport.line(at),detail); }
    private static void check(BooleanSupplier stop) { if(stop.getAsBoolean()) throw new CancellationException("scan cancelled"); }
    private static final class Bucket {
        final Rule rule;final Map<Disposition,List<Evidence>> evidence=new EnumMap<>(Disposition.class);
        Bucket(Rule rule) { this.rule=rule; }
        void add(Disposition d,Evidence e) { var list=evidence.computeIfAbsent(d,k->new ArrayList<>());if(list.size()<40&&!list.contains(e)) list.add(e); }
        void add(Disposition d,List<Evidence> items) { items.forEach(e->add(d,e)); }
        List<Assessment> finish(boolean modelSeen) {
            List<Assessment> result=new ArrayList<>();
            for(var e:evidence.entrySet()) if(!e.getValue().isEmpty()) result.add(new Assessment(rule.id(),rule.domain(),e.getKey(),e.getKey()==Disposition.VIOLATED?rule.domain()==Domain.L3?Severity.MEDIUM:Severity.HIGH:Severity.INFO,rule.title(),rule.description(),rule.recommendation(),e.getValue(),LIMITS));
            // A positive structural observation never hides unknown runtime coverage or algorithm semantics.
            if(result.stream().noneMatch(a->a.disposition()==Disposition.UNKNOWN)) result.add(new Assessment(rule.id(),rule.domain(),Disposition.UNKNOWN,Severity.INFO,rule.title(),modelSeen?"已识别模型协议边界，但控制语义、运行时分派及完整路径尚未验证。":"未识别到支持的自定义模型协议组合；不能证明不存在自定义 AI 路径。",rule.recommendation(),List.of(),LIMITS));
            return result;
        }
    }
}
