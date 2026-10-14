package dev.aiguard.analysis;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import dev.aiguard.model.ScanModel.ProjectMetadata;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CancellationException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class LocalCallGraphTest {
    private static SourceProject project(String... sources) {
        var parser = new JavaParser(new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));
        var units = new ArrayList<SourceProject.JavaSource>();
        for (int i = 0; i < sources.length; i++) units.add(new SourceProject.JavaSource("src/F" + i + ".java", parser.parse(sources[i]).getResult().orElseThrow()));
        return new SourceProject(Path.of("/fixture"), units, Map.of(), new ProjectMetadata("", "UNKNOWN", units.size(), 0, false), "digest", List.of());
    }
    private static LocalCallGraph graph(String... sources) { return LocalCallGraph.build(project(sources), () -> false); }
    private static MethodCallExpr call(LocalCallGraph graph, String method, String name) {
        return graph.methods().stream().filter(m -> m.id().name().equals(method)).findFirst().orElseThrow().declaration()
            .findAll(MethodCallExpr.class).stream().filter(c -> c.getNameAsString().equals(name)).findFirst().orElseThrow();
    }
    @Test void explicitNewResolvesAndPreservesLocalCallSites() {
        var g = graph("package p; final class Target { String send(String s) {return s;} } class App { String run(){return new Target().send(\"x\");} }");
        var e = g.resolve(call(g, "run", "send"));
        assertEquals(LocalCallGraph.Resolution.RESOLVED, e.resolution());
        assertEquals("p.Target", e.targets().getFirst().ownerFqn());
        assertEquals("java.lang.String", g.expressionType(e.callsite()));
        assertEquals(e.caller(), g.enclosing(e.callsite()).orElseThrow().id());
    }
    @Test void factoryInterfaceReturnFindsBothImplementationsWithoutSelectingBean() {
        var g = graph("package p; interface Api { String run(String p); } class A implements Api { public String run(String p){return p;} } class B implements Api { public String run(String p){return p;} } class App { Api factory(){return null;} String invoke(){return factory().run(\"x\");} }");
        var e = g.resolve(call(g, "invoke", "run"));
        assertEquals(LocalCallGraph.Resolution.CANDIDATE, e.resolution());
        assertEquals(Set.of("p.A", "p.B"), new HashSet<>(e.targets().stream().map(LocalCallGraph.MethodId::ownerFqn).toList()));
    }
    @Test void singleInterfaceImplementationRemainsCandidate() {
        var g = graph("interface Api { String send(String p); } class A implements Api { public String send(String p){return p;} } class App { Api field; String run(){return field.send(\"x\");} }");
        assertEquals(LocalCallGraph.Resolution.CANDIDATE, g.resolve(call(g, "run", "send")).resolution());
    }
    @Test void exactOverloadUsesArgumentType() {
        var g = graph("class A { private void use(String s){} private void use(int i){} void run(){ use(\"x\");} }");
        var e = g.resolve(call(g, "run", "use"));
        assertEquals(LocalCallGraph.Resolution.RESOLVED, e.resolution());
        assertEquals(List.of("java.lang.String"), e.targets().getFirst().parameterTypes());
    }
    @Test void unknownArgumentDoesNotChooseAnOverload() {
        var g = graph("class A { void use(String s){} void use(Integer i){} void run(){ use(external());} }");
        var e = g.resolve(call(g, "run", "use"));
        assertEquals(LocalCallGraph.Resolution.CANDIDATE, e.resolution());
        assertEquals(2, e.targets().size());
        assertTrue(e.reasons().contains(LocalCallGraph.Reason.AMBIGUOUS_OVERLOAD));
    }
    @Test void duplicateQualifiedTypesAreNotFirstWins() {
        var g = graph("package p; class A { void send(){} }", "package p; class A { void send(){} }", "package p; class App { A a; void run(){a.send();} }");
        assertEquals(LocalCallGraph.Resolution.UNKNOWN, g.resolve(call(g, "run", "send")).resolution());
        assertTrue(g.diagnostics().stream().anyMatch(d -> d.code().equals("CALL_GRAPH_DUPLICATE_TYPE")));
    }
    @Test void shadowedFieldUsesNearestParameterType() {
        var g = graph("class A { void send(){} } class B { void send(){} } class App { A value; void run(B value){value.send();} }");
        assertEquals("B", g.resolve(call(g, "run", "send")).targets().getFirst().ownerFqn());
    }
    @Test void nestedRecordAccessorAndReturnTypesResolve() {
        var g = graph("package p; class App { record Decision(boolean pass){} private Decision check(String v){ return new Decision(true); } boolean run(){return check(\"x\").pass();} }");
        assertEquals("p.App.Decision", g.expressionType(call(g, "run", "check")));
        assertEquals("boolean", g.expressionType(call(g, "run", "pass")));
    }
    @Test void inheritedImplementationIsReachable() {
        var g = graph("class Base { String send(String p){ return p; } } final class Sub extends Base {} class App { String run(){return new Sub().send(\"x\");} }");
        var e = g.resolve(call(g, "run", "send"));
        assertEquals("Base", e.targets().getFirst().ownerFqn());
        assertEquals(LocalCallGraph.Resolution.RESOLVED, e.resolution());
    }
    @Test void recursiveCallsTerminateAndReachabilityIsBounded() {
        var g = graph("class A { private void a(){b();} private void b(){a();} }");
        var start = g.methods().stream().filter(m -> m.id().name().equals("a")).findFirst().orElseThrow().id();
        assertEquals(2, g.reachable(start, 8).size());
        assertTrue(g.reachable(start, 0).isEmpty());
    }
    @Test void importedExternalReceiverDoesNotBindSameNamedLocalMethod() {
        var g = graph("import external.Remote; class App { Remote r; void send(){} void run(){r.send();} }");
        var e = g.resolve(call(g, "run", "send"));
        assertEquals(LocalCallGraph.Resolution.UNKNOWN, e.resolution());
        assertTrue(e.targets().isEmpty());
    }
    @Test void qualifiedTypeDoesNotInventUnknownSimpleNames() {
        var g = graph("package p; import java.util.List; class App { void run(){} }");
        var n = g.methods().getFirst().declaration();
        assertEquals("java.util.List", g.qualifiedType(n, "List<String>"));
        assertEquals("", g.qualifiedType(n, "Unresolved"));
    }
    @Test void anonymousMethodsHaveSeparateOwnersAndEnclosingMethods() {
        var g = graph("class App { void run(){new Runnable(){public void run(){ helper(); }};} void helper(){} }");
        assertEquals(3, g.methods().size());
        var nested = g.methods().stream().filter(m -> m.id().ownerFqn().contains("$anonymous")).findFirst().orElseThrow();
        assertEquals(nested.id(), g.enclosing(nested.declaration().findFirst(MethodCallExpr.class).orElseThrow()).orElseThrow().id());
    }
    @Test void cancellationIsCooperative() {
        assertThrows(CancellationException.class, () -> LocalCallGraph.build(project("class A { void run(){} }"), () -> true));
    }
    @Test void wildcardJdkTypesAndGenericRecordElementsResolve() {
        var g = graph("package p; import java.util.*; class App { record Message(String content){} record Response(List<Message> messages){} String run(Response r){return r.messages().get(0).content();} }");
        assertEquals("java.util.List", g.expressionType(call(g, "run", "messages")));
        assertEquals("p.App.Message", g.expressionType(call(g, "run", "get")));
        assertEquals("java.lang.String", g.expressionType(call(g, "run", "content")));
    }
    @Test void unresolvedOverloadsOnSameLineAreRetained() {
        var g = graph("class A { void send(ExternalOne a){} void send(ExternalTwo b){} void run(){send(null);} }");
        assertEquals(2, g.resolve(call(g, "run", "send")).targets().size());
    }
    @Test void sourceStaticImportsResolveWithoutExecutingClass() {
        var g = graph("package p; class Utility { static String transform(String v){return v;} }", "package q; import static p.Utility.transform; class App {String run(){return transform(\"x\");} }");
        var e = g.resolve(call(g, "run", "transform"));
        assertEquals(LocalCallGraph.Resolution.RESOLVED, e.resolution());
        assertEquals("p.Utility", e.targets().getFirst().ownerFqn());
    }
    @Test void targetBudgetIsDiagnosedRatherThanReportingCompleteBinding() {
        StringBuilder code = new StringBuilder("interface Api {void send();} class App {Api a; void run(){a.send();}}");
        for (int i = 0; i < 18; i++) code.append("class Impl").append(i).append(" implements Api {public void send(){}}");
        var g = graph(code.toString());
        var e = g.resolve(call(g, "run", "send"));
        assertEquals(16, e.targets().size());
        assertEquals(LocalCallGraph.Resolution.CANDIDATE, e.resolution());
        assertTrue(e.reasons().contains(LocalCallGraph.Reason.BUDGET));
        assertTrue(g.diagnostics().stream().anyMatch(d -> d.code().equals("CALL_GRAPH_TARGET_LIMIT")));
    }
    @Test void defaultPackageTypeCannotShadowAnotherPackagesJavaLangType() {
        var g = graph("class Runtime {}", "package p; class App {void run(){}}");
        var method = g.methods().getFirst().declaration();
        assertEquals("java.lang.Runtime", g.qualifiedType(method, "Runtime"));
    }
    @Test void explicitImportIsNotReplacedBySamePackageSimpleName() {
        var g = graph("package p; class Remote {}", "package p; import remote.Remote; class App {void run(){}}");
        assertEquals("remote.Remote", g.qualifiedType(g.methods().getFirst().declaration(), "Remote"));
    }
    @Test void namedSourceAndTypeParametersShadowKnownPlatformNames() {
        var g = graph("package p; class Runtime {} class App<String> {void run(){}}");
        var method = g.methods().getFirst().declaration();
        assertEquals("p.Runtime", g.qualifiedType(method, "Runtime"));
        assertEquals("", g.qualifiedType(method, "String"));
    }
    @Test void wildcardNestedTypesResolveButRespectSourceOuterShadowing() {
        var g = graph("package p; import okhttp3.*; import okhttp3.sse.*; class App {void run(){}}");
        var method = g.methods().getFirst().declaration();
        assertEquals("okhttp3.Request.Builder", g.qualifiedType(method, "Request.Builder"));
        assertEquals("okhttp3.sse.EventSource.Factory", g.qualifiedType(method, "EventSource.Factory"));
        var shadowed = graph("package p; import okhttp3.*; class Request {} class App {void run(){}}");
        assertEquals("", shadowed.qualifiedType(shadowed.methods().getFirst().declaration(), "Request.Builder"));
    }
    @Test void inheritedOverloadRemainsCandidateWhenArgumentTypeIsUnknown() {
        var g = graph("class Base {void send(String s){}} class App extends Base {void send(Integer i){} void run(){send(external());}}");
        var e = g.resolve(call(g, "run", "send"));
        assertEquals(2, e.targets().size());
        assertEquals(LocalCallGraph.Resolution.CANDIDATE, e.resolution());
    }
    @Test void directAnonymousOverrideIsNotResolvedAsItsBaseImplementation() {
        var g = graph("class Base {String send(){return \"base\";}} class App {String run(){return new Base(){String send(){return \"other\";}}.send();}}");
        var e = g.resolve(call(g, "run", "send"));
        assertEquals(LocalCallGraph.Resolution.UNKNOWN, e.resolution());
        assertTrue(e.targets().isEmpty());
    }
}
