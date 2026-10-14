package dev.aiguard.analysis;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.*;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import dev.aiguard.model.ScanModel.Diagnostic;
import dev.aiguard.model.ScanModel.Evidence;
import java.util.*;
import java.util.function.BooleanSupplier;
import java.util.concurrent.CancellationException;

/** Bounded protocol and value-flow evidence; a discovered gateway is not a security verdict. */
public final class GatewayModel {
    public record Gateway(LocalCallGraph.MethodId method, String protocol, boolean streaming,
                          Set<Integer> callbackArguments, List<Evidence> evidence) {
        public Gateway { callbackArguments=Set.copyOf(callbackArguments); evidence=List.copyOf(evidence); }
    }
    public record Origin(List<Evidence> evidence, boolean candidateDispatch) {
        public Origin { evidence=List.copyOf(evidence); }
    }
    private static final int MAX_DEPTH=24, MAX_ROUNDS=10, MAX_EVIDENCE=16;
    private final SourceProject project;
    private final LocalCallGraph graph;
    private final BooleanSupplier cancelled;
    private final List<Gateway> gateways=new ArrayList<>();
    private final List<Diagnostic> diagnostics=new ArrayList<>();
    private final Map<Expression,Origin> sources=new IdentityHashMap<>();
    private final Set<Expression> transportEnvelopes=Collections.newSetFromMap(new IdentityHashMap<>());
    private final Map<Parameter,Origin> parameters=new IdentityHashMap<>();
    private final Map<LocalCallGraph.MethodId,Origin> returns=new LinkedHashMap<>();
    private final Map<LocalCallGraph.MethodId,Set<Integer>> callbacks=new LinkedHashMap<>();
    private final Set<LocalCallGraph.MethodId> participants=new LinkedHashSet<>();
    private final Map<LocalCallGraph.MethodId,Set<Integer>> returnDependencies=new HashMap<>();
    private final List<MethodCallExpr> calls;
    private GatewayModel(SourceProject project, LocalCallGraph graph, BooleanSupplier cancelled) {
        this.project=project; this.graph=graph; this.cancelled=cancelled;
        this.calls=project.sources().stream().flatMap(s -> s.unit().findAll(MethodCallExpr.class).stream()).toList();
    }
    public static GatewayModel build(SourceProject project, LocalCallGraph graph, BooleanSupplier cancelled) {
        var result=new GatewayModel(project,graph,cancelled);
        result.discover(); result.propagate(); return result;
    }
    public List<Gateway> gateways() { return List.copyOf(gateways); }
    public List<Diagnostic> diagnostics() { return List.copyOf(diagnostics); }
    public Optional<Origin> origin(Expression expression) { return envelope(expression)?Optional.empty():value(expression,0,identitySet()); }
    public boolean isInvocation(MethodCallExpr call) {
        return graph.resolve(call).targets().stream().anyMatch(t -> returns.containsKey(t) || callbacks.containsKey(t)
            || gateways.stream().anyMatch(g -> g.method().equals(t)));
    }
    public Set<LocalCallGraph.MethodId> participatingMethods() { return Set.copyOf(participants); }
    public List<Evidence> trace(MethodCallExpr call) {
        var out=new ArrayList<Evidence>(); out.add(evidence(call,"Local call bound to a discovered model gateway or its return wrapper."));
        origin(call).ifPresent(o -> out.addAll(o.evidence()));
        for(var target:graph.resolve(call).targets()) for(var gateway:gateways)
            if(gateway.method().equals(target)) out.addAll(gateway.evidence());
        return bounded(out);
    }

    private void discover() {
        for(var method:graph.methods()) {
            check(); var declaration=method.declaration();
            boolean streaming=false; var evidence=new ArrayList<Evidence>(); var callbackIndices=new LinkedHashSet<Integer>();
            for(var call:declaration.findAll(MethodCallExpr.class)) {
                check();
                if(call.getNameAsString().equals("execute") && call.getScope().orElse(null) instanceof MethodCallExpr send
                    && send.getNameAsString().equals("newCall") && send.getArguments().size()==1
                    && send.getScope().filter(s -> typeIs(s,"okhttp3.OkHttpClient")).isPresent()
                    && knownRequest(send.getArgument(0))) {
                    if(!graph.enclosing(call).map(m -> m.id().equals(method.id())).orElse(false)) continue;
                    var item=evidence(call,"Typed HTTP request uses a model protocol endpoint; this expression receives the HTTP response.");
                    sources.put(call,new Origin(List.of(item),false)); transportEnvelopes.add(call); evidence.add(item);
                }
                if(restResponse(call)) {
                    if(!graph.enclosing(call).map(m -> m.id().equals(method.id())).orElse(false)) continue;
                    var item=evidence(call,"Typed HTTP request and associated request/response wire shapes identify a model protocol response.");
                    sources.put(call,new Origin(List.of(item),false)); evidence.add(item);
                }
                if(call.getNameAsString().equals("newEventSource") && call.getArguments().size()==2
                    && call.getScope().filter(this::eventFactory).isPresent() && knownRequest(call.getArgument(0))) {
                    if(!graph.enclosing(call).map(m -> m.id().equals(method.id())).orElse(false)) continue;
                    streaming=true;
                    var item=evidence(call,"Typed event-stream HTTP request uses a model protocol endpoint."); evidence.add(item);
                    Expression listener=unfold(call.getArgument(1),0);
                    if(listener instanceof ObjectCreationExpr creation && qualified(creation,creation.getType().asString()).equals("okhttp3.sse.EventSourceListener")) {
                        for(var event:creation.findAll(MethodDeclaration.class)) {
                            if(!event.getNameAsString().equals("onEvent") || event.getParameters().size()!=4
                                || !qualified(event.getParameter(0),event.getParameter(0).getTypeAsString()).equals("okhttp3.sse.EventSource")
                                || event.getParameters().subList(1,4).stream().anyMatch(p -> !qualified(p,p.getTypeAsString()).equals("java.lang.String"))) continue;
                            Parameter data=event.getParameter(3);
                            parameters.put(data,new Origin(List.of(item,evidence(data,"HTTP event callback supplies the model response frame.")),false));
                        }
                        for(var accept:creation.findAll(MethodCallExpr.class)) {
                            if(!accept.getNameAsString().equals("accept") || accept.getArguments().size()!=1
                                || !(accept.getScope().orElse(null) instanceof NameExpr name) || origin(accept.getArgument(0)).isEmpty()) continue;
                            for(int i=0;i<declaration.getParameters().size();i++) {
                                Parameter parameter=declaration.getParameter(i);
                                if(parameter.getNameAsString().equals(name.getNameAsString())
                                    && qualified(parameter,parameter.getType().asString()).startsWith("java.util.function.Consumer")) callbackIndices.add(i);
                            }
                        }
                    }
                }
            }
            if(!evidence.isEmpty()) {
                gateways.add(new Gateway(method.id(),"openai-chat-compatible",streaming,callbackIndices,bounded(evidence)));
                if(!callbackIndices.isEmpty()) callbacks.put(method.id(),Set.copyOf(callbackIndices));
                participants.add(method.id());
            }
        }
    }

    private boolean knownRequest(Expression expression) {
        Expression request=unfold(expression,0);
        if(!(request instanceof MethodCallExpr call)) return false;
        List<MethodCallExpr> chain=scopeChain(call);
        Expression root=chain.get(chain.size()-1).getScope().map(s -> unfold(s,0)).orElse(null);
        if(!(root instanceof ObjectCreationExpr creation) || !qualified(creation,creation.getType().asString()).equals("okhttp3.Request.Builder")) return false;
        boolean post=chain.stream().anyMatch(c -> c.getNameAsString().equals("post") && c.getArguments().size()==1);
        return post && chain.stream().anyMatch(c -> c.getNameAsString().equals("url")
            && c.getArguments().size()==1 && protocolEndpoint(c.getArgument(0)));
    }
    private boolean eventFactory(Expression expression) {
        Expression scope=unfold(expression,0);
        if(scope instanceof MethodCallExpr call && call.getNameAsString().equals("createFactory") && call.getArguments().size()==1
            && call.getScope().map(s -> graph.expressionType(s).isEmpty() && qualified(s,s.toString()).equals("okhttp3.sse.EventSources")).orElse(false)) {
            return typeIs(call.getArgument(0),"okhttp3.OkHttpClient");
        }
        return typeIs(expression,"okhttp3.sse.EventSource.Factory");
    }
    private boolean restResponse(MethodCallExpr call) {
        if(!call.getNameAsString().equals("body") || call.getArguments().size()!=1 || !(call.getArgument(0) instanceof ClassExpr responseType)) return false;
        List<MethodCallExpr> chain=scopeChain(call);
        if(chain.stream().noneMatch(c -> c.getNameAsString().equals("retrieve"))) return false;
        var post=chain.stream().filter(c -> c.getNameAsString().equals("post") && c.getScope().filter(s -> typeIs(s,"org.springframework.web.client.RestClient")).isPresent()).findFirst();
        if(post.isEmpty()) return false;
        boolean endpoint=chain.stream().anyMatch(c -> c.getNameAsString().equals("uri") && !c.getArguments().isEmpty() && protocolEndpoint(c.getArgument(0)));
        if(endpoint) return true;
        var body=chain.stream().filter(c -> c!=call && c.getNameAsString().equals("body") && c.getArguments().size()==1).findFirst();
        if(body.isEmpty()) return false;
        Expression payload=unfold(body.get().getArgument(0),0);
        if(!(payload instanceof ObjectCreationExpr creation)) return false;
        String requestFqn=qualified(creation,creation.getType().asString());
        String responseFqn=qualified(responseType,responseType.getType().asString());
        return hasFields(requestFqn,Set.of("model","messages")) && hasFields(responseFqn,Set.of("choices"))
            && nestedFieldShape(requestFqn,"messages",Set.of("role","content"),0)
            && nestedFieldShape(responseFqn,"choices",Set.of("message"),0)
            && nestedFieldShape(fieldElementType(responseFqn,"choices"),"message",Set.of("content"),0);
    }
    private boolean hasFields(String type,Set<String> fields) { return typeDeclaration(type).map(d -> fieldsOf(d).keySet().containsAll(fields)).orElse(false); }
    private boolean nestedFieldShape(String type,String field,Set<String> fields,int depth) {
        if(depth>3) return false;
        return hasFields(fieldElementType(type,field),fields);
    }
    private String fieldElementType(String type,String field) {
        var declaration=typeDeclaration(type); if(declaration.isEmpty()) return "";
        String fieldType=fieldsOf(declaration.get()).get(field); if(fieldType==null) return "";
        String raw=fieldType;
        if(raw.contains("<")) raw=raw.substring(raw.indexOf('<')+1,raw.lastIndexOf('>'));
        return qualified(declaration.get(),raw);
    }
    private Optional<TypeDeclaration<?>> typeDeclaration(String fqn) {
        if(fqn.isBlank()) return Optional.empty();
        for(var source:project.sources()) for(TypeDeclaration<?> declaration:source.unit().findAll(TypeDeclaration.class))
            if(qualified(declaration,declaration.getNameAsString()).equals(fqn)) return Optional.of(declaration);
        return Optional.empty();
    }
    private Map<String,String> fieldsOf(TypeDeclaration<?> declaration) {
        var result=new LinkedHashMap<String,String>();
        if(declaration instanceof RecordDeclaration record) for(var p:record.getParameters()) result.put(p.getNameAsString(),p.getType().asString());
        for(var field:declaration.getFields()) for(var v:field.getVariables()) result.put(v.getNameAsString(),v.getType().asString());
        return result;
    }
    private boolean protocolEndpoint(Expression expression) {
        Expression expanded=unfold(expression,0);
        if(expanded instanceof StringLiteralExpr text) return text.asString().matches(".*?/chat/completions/?(?:\\?.*)?");
        if(expanded instanceof BinaryExpr binary && binary.getOperator()==BinaryExpr.Operator.PLUS)
            return protocolEndpoint(binary.getRight()) || protocolEndpoint(binary.getLeft());
        return false;
    }

    private void propagate() {
        boolean changed=false;
        for(int round=0;round<MAX_ROUNDS;round++) {
            check(); changed=false;
            for(var method:graph.methods()) {
                Origin merged=null; boolean unknownReturn=false;
                for(var statement:method.declaration().findAll(ReturnStmt.class)) {
                    if(!graph.enclosing(statement).map(m -> m.id().equals(method.id())).orElse(false) || statement.getExpression().isEmpty()) continue;
                    var origin=origin(statement.getExpression().get());
                    if(origin.isPresent()) merged=merge(merged,origin.get(),false); else unknownReturn=true;
                }
                if(merged!=null) {
                    if(unknownReturn) merged=new Origin(merged.evidence(),true);
                    Origin old=returns.put(method.id(),merged); changed|=!merged.equals(old);
                }
            }
            for(var call:calls) {
                check(); var edge=graph.resolve(call);
                if(edge.targets().isEmpty()) continue;
                boolean candidate=edge.resolution()!=LocalCallGraph.Resolution.RESOLVED;
                for(var target:edge.targets()) {
                    var targetMethod=graph.method(target); if(targetMethod.isEmpty()) continue;
                    var declaration=targetMethod.get().declaration();
                    for(int i=0;i<Math.min(call.getArguments().size(),declaration.getParameters().size());i++) {
                        var source=origin(call.getArgument(i));
                        if(source.isPresent()) {
                            Parameter parameter=declaration.getParameter(i);
                            // This is a context-insensitive parameter summary, never proof that every invocation receives model data.
                            Origin incoming=merge(source.get(),new Origin(List.of(evidence(call,"Model-derived argument reaches a source-local method parameter; invocation context remains uncertain.")),true),true);
                            Origin next=merge(parameters.get(parameter),incoming,true);
                            Origin old=parameters.put(parameter,next); changed|=!next.equals(old);
                        }
                    }
                    for(int index:callbacks.getOrDefault(target,Set.of())) {
                        if(index>=call.getArguments().size()) continue;
                        Expression argument=unfold(call.getArgument(index),0);
                        Origin callback=new Origin(traceGateway(target,call),candidate);
                        if(argument instanceof LambdaExpr lambda && lambda.getParameters().size()==1) {
                            Parameter parameter=lambda.getParameter(0); Origin next=merge(parameters.get(parameter),callback,candidate);
                            Origin old=parameters.put(parameter,next); changed|=!next.equals(old);
                        } else if(argument instanceof NameExpr name) {
                            var owner=graph.enclosing(call);
                            if(owner.isPresent()) for(int j=0;j<owner.get().declaration().getParameters().size();j++) {
                                if(owner.get().declaration().getParameter(j).getNameAsString().equals(name.getNameAsString())) {
                                    var indices=new LinkedHashSet<>(callbacks.getOrDefault(owner.get().id(),Set.of()));
                                    if(indices.add(j)) { callbacks.put(owner.get().id(),Set.copyOf(indices)); changed=true; }
                                }
                            }
                        }
                    }
                }
                if(edge.targets().stream().anyMatch(participants::contains))
                    changed|=graph.enclosing(call).map(m -> participants.add(m.id())).orElse(false);
            }
            if(!changed) break;
        }
        if(changed) diagnostics.add(new Diagnostic("GATEWAY_FLOW_BOUND","","Gateway source propagation reached its bounded iteration limit; unresolved paths remain unknown."));
    }
    private List<Evidence> traceGateway(LocalCallGraph.MethodId target,MethodCallExpr call) {
        var result=new ArrayList<Evidence>(); result.add(evidence(call,"A model-output callback is supplied to a source-local gateway call."));
        gateways.stream().filter(g -> g.method().equals(target)).forEach(g -> result.addAll(g.evidence()));
        return bounded(result);
    }
    private Optional<Origin> value(Expression expression,int depth,Set<Node> seen) {
        check(); if(depth>MAX_DEPTH || !seen.add(expression)) return Optional.empty();
        try {
            Origin direct=sources.get(expression); if(direct!=null) return Optional.of(direct);
            if(expression instanceof EnclosedExpr enclosed) return value(enclosed.getInner(),depth+1,seen);
            if(expression instanceof CastExpr cast) return value(cast.getExpression(),depth+1,seen);
            if(expression instanceof NameExpr name) return nameValue(name,depth,seen);
            if(expression instanceof ConditionalExpr conditional) {
                var left=value(conditional.getThenExpr(),depth+1,seen); var right=value(conditional.getElseExpr(),depth+1,seen);
                if(left.isEmpty() && right.isEmpty()) return Optional.empty();
                return Optional.of(merge(left.orElse(null),right.orElse(null),left.isEmpty()||right.isEmpty()));
            }
            if(expression instanceof BinaryExpr binary && binary.getOperator()==BinaryExpr.Operator.PLUS) {
                return optionalMerge(value(binary.getLeft(),depth+1,seen),value(binary.getRight(),depth+1,seen),false);
            }
            if(expression instanceof MethodCallExpr call) {
                var edge=graph.resolve(call); Origin result=null; boolean missing=false;
                for(var target:edge.targets()) {
                    var origin=returns.get(target);
                    var dependencies=returnParameterDependencies(target);
                    if(!dependencies.isEmpty() && dependencies.stream().noneMatch(i -> i<call.getArguments().size()
                        && value(call.getArgument(i),depth+1,seen).isPresent())) origin=null;
                    if(origin==null) missing=true; else result=merge(result,origin,false);
                }
                if(result!=null) return Optional.of(merge(result,new Origin(List.of(evidence(call,"Source-local return flow carries model-derived data.")),false),
                    missing||edge.resolution()!=LocalCallGraph.Resolution.RESOLVED));
                String name=call.getNameAsString();
                if(name.equals("readTree") && call.getArguments().size()==1 && call.getScope().filter(s -> typeIs(s,"com.fasterxml.jackson.databind.ObjectMapper")).isPresent())
                    return value(call.getArgument(0),depth+1,seen);
                if(call.getScope().isPresent() && preservedConversion(call)) return value(call.getScope().get(),depth+1,seen);
            }
            return Optional.empty();
        } finally { seen.remove(expression); }
    }
    private boolean preservedConversion(MethodCallExpr call) {
        String name=call.getNameAsString();
        if(name.equals("toString") && call.getScope().filter(this::envelope).isPresent()) return false;
        if(Set.of("path","get").contains(name)) {
            if(call.getArguments().size()!=1) return false;
            if(call.getArgument(0) instanceof StringLiteralExpr key && Set.of("usage","prompt_tokens","completion_tokens",
                "total_tokens","model","id","created","finish_reason","object","system_fingerprint").contains(key.asString())) return false;
            return true;
        }
        return call.getArguments().isEmpty() && Set.of("body","string","asText","textValue","asInt","asLong","asDouble","asBoolean",
            "toString","trim","strip","choices","message","content","delta").contains(name);
    }
    private Set<Integer> returnParameterDependencies(LocalCallGraph.MethodId target) {
        if(returnDependencies.containsKey(target)) return returnDependencies.get(target);
        var result=new LinkedHashSet<Integer>();
        var method=graph.method(target); if(method.isEmpty()) return result;
        for(var statement:method.get().declaration().findAll(ReturnStmt.class)) {
            if(graph.enclosing(statement).map(m -> m.id().equals(target)).orElse(false))
                statement.getExpression().ifPresent(e -> parameterDependencies(e,method.get().declaration(),result,0));
        }
        returnDependencies.put(target,Set.copyOf(result)); return result;
    }
    private void parameterDependencies(Expression expression,MethodDeclaration method,Set<Integer> result,int depth) {
        if(depth>12) return;
        if(expression instanceof NameExpr name) {
            Node declaration=binding(name);
            if(declaration instanceof Parameter parameter) {
                int index=method.getParameters().indexOf(parameter); if(index>=0) result.add(index);
            } else if(declaration instanceof VariableDeclarator variable)
                variable.getInitializer().ifPresent(e -> parameterDependencies(e,method,result,depth+1));
        } else if(expression instanceof EnclosedExpr enclosed) parameterDependencies(enclosed.getInner(),method,result,depth+1);
        else if(expression instanceof CastExpr cast) parameterDependencies(cast.getExpression(),method,result,depth+1);
        else if(expression instanceof MethodCallExpr call && preservedConversion(call))
            call.getScope().ifPresent(s -> parameterDependencies(s,method,result,depth+1));
        else if(expression instanceof MethodCallExpr call && call.getNameAsString().equals("readTree") && call.getArguments().size()==1)
            parameterDependencies(call.getArgument(0),method,result,depth+1);
    }
    private Optional<Origin> nameValue(NameExpr name,int depth,Set<Node> seen) {
        var binding=binding(name); if(binding==null) return Optional.empty();
        List<AssignExpr> assignments=assignments(name,binding);
        if(!assignments.isEmpty()) {
            AssignExpr last=assignments.get(assignments.size()-1);
            if(last.getOperator()!=AssignExpr.Operator.ASSIGN) return Optional.empty();
            // Only a straight-line assignment in the use's enclosing block replaces the value conclusively.
            if(scope(last)==scope(name)) return value(last.getValue(),depth+1,seen);
            if(assignments.size()==1 && last.getParentNode().orElse(null) instanceof ExpressionStmt statement
                && statement.getParentNode().orElse(null) instanceof BlockStmt body
                && body.getParentNode().orElse(null) instanceof TryStmt guarded && guarded.getTryBlock()==body
                && guarded.getFinallyBlock().isEmpty() && !guarded.getCatchClauses().isEmpty()
                && guarded.getCatchClauses().stream().allMatch(c -> terminates(c.getBody()))
                && scope(guarded)==scope(name)) {
                return value(last.getValue(),depth+1,seen).map(o -> new Origin(o.evidence(),true));
            }
            // A conditional write makes prior evidence insufficient. Do not silently keep stale taint.
            return Optional.empty();
        }
        if(binding instanceof Parameter parameter) return Optional.ofNullable(parameters.get(parameter));
        if(binding instanceof VariableDeclarator variable && variable.getInitializer().isPresent()) return value(variable.getInitializer().get(),depth+1,seen);
        return Optional.empty();
    }
    private Node binding(NameExpr expression) {
        String name=expression.getNameAsString();
        Node current=expression;
        while(current.getParentNode().isPresent()) {
            current=current.getParentNode().get();
            if(current instanceof LambdaExpr lambda) {
                var parameter=lambda.getParameters().stream().filter(p -> p.getNameAsString().equals(name)).findFirst();
                if(parameter.isPresent()) return parameter.get();
            }
            if(current instanceof MethodDeclaration method) {
                var parameter=method.getParameters().stream().filter(p -> p.getNameAsString().equals(name)).findFirst();
                Node local=method.findAll(VariableDeclarator.class).stream()
                    .filter(v -> v.getNameAsString().equals(name) && before(v,expression) && contains(scope(v),expression))
                    .max(Comparator.comparingInt(GatewayModel::position)).orElse(null);
                if(local!=null) return local;
                if(parameter.isPresent()) return parameter.get();
                // Anonymous callback methods may capture variables and parameters of their outer method.
            }
        }
        return null;
    }
    private List<AssignExpr> assignments(NameExpr use,Node declaration) {
        Node container=declaration.findAncestor(MethodDeclaration.class).map(m -> (Node)m).orElse(declaration);
        return container.findAll(AssignExpr.class).stream().filter(a -> a.getTarget() instanceof NameExpr target
            && target.getNameAsString().equals(use.getNameAsString()) && binding(target)==declaration
            && before(declaration,a) && before(a,use)).sorted(Comparator.comparingInt(GatewayModel::position)).toList();
    }
    private Expression unfold(Expression expression,int depth) {
        if(depth>8) return expression;
        if(expression instanceof EnclosedExpr e) return unfold(e.getInner(),depth+1);
        if(expression instanceof NameExpr name) {
            Node declaration=binding(name);
            if(declaration!=null) {
                var assignments=assignments(name,declaration);
                if(!assignments.isEmpty()) return unfold(assignments.get(assignments.size()-1).getValue(),depth+1);
                if(declaration instanceof VariableDeclarator v && v.getInitializer().isPresent()) return unfold(v.getInitializer().get(),depth+1);
            }
        }
        return expression;
    }
    private boolean typeIs(Expression expression,String expected) { return erase(graph.expressionType(expression)).equals(expected); }
    private boolean envelope(Expression expression) {
        if(transportEnvelopes.contains(expression) || transportEnvelopes.contains(unfold(expression,0))
            || typeIs(expression,"okhttp3.Response") || typeIs(expression,"okhttp3.ResponseBody")) return true;
        return expression instanceof MethodCallExpr call && call.getNameAsString().equals("body")
            && call.getScope().filter(this::envelope).isPresent();
    }
    private static boolean terminates(BlockStmt body) {
        if(body.getStatements().isEmpty()) return false;
        Statement last=body.getStatement(body.getStatements().size()-1); return last instanceof ReturnStmt || last instanceof ThrowStmt;
    }
    private String qualified(Node node,String type) { return erase(graph.qualifiedType(node,type)); }
    private static String erase(String type) { int index=type.indexOf('<'); return index<0?type:type.substring(0,index); }
    private Evidence evidence(Node node,String detail) {
        String path=graph.enclosing(node).map(m -> m.source().path()).orElseGet(() -> project.sources().stream()
            .filter(s -> contains(s.unit(),node)).map(SourceProject.JavaSource::path).findFirst().orElse(""));
        return new Evidence(path,node.getBegin().map(p -> p.line).orElse(1),detail);
    }
    private static List<MethodCallExpr> scopeChain(MethodCallExpr call) {
        var chain=new ArrayList<MethodCallExpr>(); MethodCallExpr cursor=call;
        while(true) { chain.add(cursor); if(cursor.getScope().orElse(null) instanceof MethodCallExpr parent) cursor=parent; else break; }
        return chain;
    }
    private static Node scope(Node node) {
        Node cursor=node;
        while(cursor.getParentNode().isPresent()) {
            cursor=cursor.getParentNode().get();
            if(cursor instanceof BlockStmt || cursor instanceof LambdaExpr || cursor instanceof ForStmt || cursor instanceof ForEachStmt
                || cursor instanceof TryStmt || cursor instanceof MethodDeclaration) return cursor;
        }
        return cursor;
    }
    private static boolean contains(Node parent,Node child) {
        if(parent==null) return false;
        Node cursor=child; while(true) { if(cursor==parent) return true; if(cursor.getParentNode().isEmpty()) return false; cursor=cursor.getParentNode().get(); }
    }
    private static int position(Node node) { return node.getBegin().map(p -> p.line*100000+p.column).orElse(-1); }
    private static boolean before(Node left,Node right) { return position(left)<position(right); }
    private static Origin merge(Origin left,Origin right,boolean candidate) {
        var evidence=new ArrayList<Evidence>(); if(left!=null) evidence.addAll(left.evidence()); if(right!=null) evidence.addAll(right.evidence());
        return new Origin(bounded(evidence),candidate||(left!=null&&left.candidateDispatch())||(right!=null&&right.candidateDispatch()));
    }
    private static Optional<Origin> optionalMerge(Optional<Origin> left,Optional<Origin> right,boolean candidate) {
        return left.isEmpty()&&right.isEmpty()?Optional.empty():Optional.of(merge(left.orElse(null),right.orElse(null),candidate));
    }
    private static List<Evidence> bounded(List<Evidence> evidence) { return evidence.stream().distinct().limit(MAX_EVIDENCE).toList(); }
    private static Set<Node> identitySet() { return Collections.newSetFromMap(new IdentityHashMap<>()); }
    private void check() { if(cancelled.getAsBoolean()) throw new CancellationException("scan cancelled"); }
}
