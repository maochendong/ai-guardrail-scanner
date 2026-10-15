package dev.aiguard.compat;

import static org.junit.Assert.*;

import dev.aiguard.compat.JavaSyntax.*;
import java.util.*;
import java.util.concurrent.CancellationException;
import org.junit.Test;

public class JavaSyntaxGraphTest {
  static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  @Test
  public void wideTypeCallLookupStaysWithinLinearWorkAllowance() {
    StringBuilder source = new StringBuilder("final class Wide { int target(){return 1;}");
    for (int i = 0; i < 500; i++)
      source.append("int member").append(i).append("(){return target();}");
    source.append("}");
    Unit unit = JavaSyntax.parse(new SourceFile("src/Wide.java", source.toString()), NONE);
    assertEquals(0, unit.syntaxErrors);
    final int[] checks = {0};
    JavaGraph graph =
        new JavaGraph(
            Arrays.asList(unit),
            new Cancel() {
              public void check() {
                if (++checks[0] > 30000)
                  throw new AssertionError("Wide-type lookup work allowance exceeded");
              }
            });
    assertTrue(graph.diagnostics().toString(), graph.diagnostics().isEmpty());
    assertEquals(1, graph.resolve(call(graph, "target")).targets.size());
  }

  static JavaGraph graph(String... sources) {
    List<Unit> units = new ArrayList<Unit>();
    int i = 0;
    for (String source : sources) {
      Unit unit = JavaSyntax.parse(new SourceFile("src/T" + (i++) + ".java", source), NONE);
      assertEquals(unit.diagnostics.toString(), 0, unit.syntaxErrors);
      units.add(unit);
    }
    return new JavaGraph(units, NONE);
  }

  static Node call(JavaGraph graph, String name) {
    for (Unit unit : graph.units)
      for (Node call : JavaSyntax.find(unit.root, "CALL")) if (call.name.equals(name)) return call;
    throw new AssertionError(name);
  }

  @Test
  public void modernSyntaxRunsOnLegacyRuntime() {
    JavaGraph g =
        graph(
            "record Shape(String text) { String render(int n) {"
                + " java.util.function.Function<String,String> f=x->x; return switch(n){case"
                + " 1->\"\"\"\n"
                + "hello\n"
                + "\"\"\"; default->f.apply(text);};} }");
    assertEquals(1, g.methods().size());
    assertEquals(1, JavaSyntax.find(g.units.get(0).root, "SWITCH").size());
    assertEquals(1, JavaSyntax.find(g.units.get(0).root, "LAMBDA").size());
    assertEquals("java.lang.String", g.qualifiedType(g.methods.get(0).node, "String"));
  }

  @Test
  public void nestedImportsAndShadowing() {
    JavaGraph g =
        graph("import okhttp3.*;class Use { void run(){new Request.Builder();} } class Runtime{} ");
    Node n = JavaSyntax.find(g.units.get(0).root, "NEW").get(0);
    assertEquals("okhttp3.Request.Builder", g.declaredType(n));
    assertEquals("Runtime", g.qualifiedType(n, "Runtime"));
    assertEquals("java.lang.ProcessBuilder", g.qualifiedType(n, "ProcessBuilder"));
  }

  @Test
  public void interfaceFactoryAndMultipleImplementationsRemainCandidates() {
    JavaGraph g =
        graph(
            "interface Port { String fetch(String x); } class A implements Port { public String"
                + " fetch(String x){return x;} } class B implements Port { public String"
                + " fetch(String x){return null;} } class Use { Port create(){return new"
                + " A();}String run(){return create().fetch(\"x\");} }");
    JavaGraph.Edge e = g.resolve(call(g, "fetch"));
    assertTrue(e.candidate);
    assertFalse(e.unknown);
    assertEquals(3, e.targets.size());
  }

  @Test
  public void overloadChoosesExactTypeAndDoesNotPreferAmbiguousNull() {
    JavaGraph g =
        graph(
            "final class A { String take(String x){return x;} String take(Integer x){return null;}"
                + " void run(){take(\"x\"); take(null);} }");
    List<Node> calls = JavaSyntax.find(g.units.get(0).root, "CALL");
    assertEquals(1, g.resolve(calls.get(0)).targets.size());
    assertFalse(g.resolve(calls.get(0)).candidate);
    assertEquals(2, g.resolve(calls.get(1)).targets.size());
    assertTrue(g.resolve(calls.get(1)).candidate);
  }

  @Test
  public void initialOverloadsRespectTheDispatchTargetBudget() {
    for (String modifier : Arrays.asList("", "final ")) {
      for (int count : Arrays.asList(16, 17)) {
        StringBuilder source = new StringBuilder();
        for (int i = 0; i < count; i++) source.append("class T").append(i).append(" {}");
        source.append(modifier).append("class Overloads {");
        for (int i = 0; i < count; i++) source.append("void pick(T").append(i).append(" value) {}");
        source.append("void run() { pick(null); } }");
        JavaGraph graph = graph(source.toString());
        JavaGraph.Edge edge = graph.resolve(call(graph, "pick"));
        if (count == 16) {
          assertFalse(edge.unknown);
          assertTrue(edge.candidate);
          assertEquals(16, edge.targets.size());
          assertTrue(graph.diagnostics().isEmpty());
        } else {
          assertTrue(edge.unknown);
          assertTrue(edge.targets.isEmpty());
          assertTrue(edge.reasons.contains("TARGET_LIMIT"));
          assertEquals(1, graph.diagnostics().size());
          assertEquals("CALL_GRAPH_TARGET_LIMIT", graph.diagnostics().get(0).get("code"));
        }
      }
    }
  }

  @Test
  public void duplicateTypeNeverFirstWins() {
    JavaGraph g =
        graph(
            "class A { String take(){return null;} }",
            "class A { String take(){return null;} } class B { A a;void run(){a.take();} }");
    assertTrue(g.resolve(call(g, "take")).unknown);
    assertFalse(g.diagnostics().isEmpty());
  }

  @Test
  public void lexicalShadowingAndAnonymousCapture() {
    JavaGraph g =
        graph(
            "class A { void run(String x){ {String x2=\"a\"; log(x2);} new Object(){void"
                + " use(){log(x);}};} void log(String x){} }");
    List<Node> calls = JavaSyntax.find(g.units.get(0).root, "CALL");
    Node captured = null;
    for (Node c : calls)
      if (c.name.equals("log") && c.args.get(0).name.equals("x")) captured = c.args.get(0);
    assertNotNull(captured);
    assertEquals("PARAM", g.declaration(captured).kind);
    assertEquals("run", g.declaration(captured).method.name);
  }

  @Test
  public void annotationsFieldsAndRecordAccessors() {
    JavaGraph g =
        graph(
            "import org.springframework.web.bind.annotation.*; class A {record R(boolean"
                + " accepted,String text){} @PostMapping String run(R r){return r.text();} }");
    Method m = g.methods.get(0);
    assertTrue(m.annotations.contains("PostMapping"));
    assertEquals(
        "org.springframework.web.bind.annotation.PostMapping",
        g.qualifiedType(m.node, "PostMapping"));
    assertEquals("java.lang.String", g.declaredType(call(g, "text")));
  }

  @Test
  public void assignmentAndForCollectionAreDistinct() {
    JavaGraph g =
        graph(
            "class A {void run(java.util.List<String> xs){String x=null; x=\"a\";for(String"
                + " y:xs){log(y);}}void log(String x){} }");
    Node assignment = JavaSyntax.find(g.units.get(0).root, "ASSIGN").get(0);
    assertSame(assignment.args.get(1), assignment.initializer);
    Node element = g.declaration(call(g, "log").args.get(0));
    assertNotNull(element.collection);
    assertNull(element.initializer);
  }

  @Test
  public void parseFailureDiscardsPartialEvidence() {
    Unit unit = JavaSyntax.parse(new SourceFile("x.java", "class A{void broken(}"), NONE);
    assertTrue(unit.syntaxErrors > 0);
    assertNull(unit.root);
    assertTrue(unit.methods.isEmpty());
  }

  @Test(expected = CancellationException.class)
  public void cancellationStopsParse() {
    JavaSyntax.parse(
        new SourceFile("x.java", "class A{}"),
        new Cancel() {
          public void check() {
            throw new CancellationException();
          }
        });
  }

  @Test
  public void javaSevenSyntaxIncludesDiamondResourcesMultiCatchAndStringSwitch() {
    JavaGraph g =
        graph(
            "class Legacy { void run(String value) { java.util.List<String> values = new"
                + " java.util.ArrayList<>(); try (java.io.InputStream input = new"
                + " java.io.ByteArrayInputStream(new byte[0])) { switch(value) { case \"a\": break;"
                + " default: break; } } catch(java.io.IOException | IllegalArgumentException error)"
                + " { return; } } }");
    assertEquals(1, JavaSyntax.find(g.units.get(0).root, "TRY").size());
    assertEquals(1, JavaSyntax.find(g.units.get(0).root, "CATCH").size());
    assertEquals(1, JavaSyntax.find(g.units.get(0).root, "SWITCH").size());
  }

  @Test
  public void javaEightDefaultMethodsLambdasAndReferencesAreIndexed() {
    JavaGraph g =
        graph(
            "interface Modern { default void run() { java.util.function.Function<String,String> f ="
                + " x -> x.trim(); java.util.function.Consumer<String> sink = System.out::println;"
                + " } }");
    assertEquals(1, g.methods().size());
    assertEquals(1, JavaSyntax.find(g.units.get(0).root, "LAMBDA").size());
    assertEquals(1, JavaSyntax.find(g.units.get(0).root, "METHOD_REF").size());
  }

  @Test
  public void lombokLoggerRequiresExactAnnotationAndRespectsShadow() {
    JavaGraph g =
        graph("import lombok.extern.slf4j.Slf4j;@Slf4j class A{void use(){log.info(\"x\");}}");
    assertEquals("org.slf4j.Logger", g.declaredType(call(g, "info").receiver));
    JavaGraph shadow =
        graph(
            "import lombok.extern.slf4j.Slf4j;@Slf4j class A{String log;void"
                + " use(){log.info(\"x\");}}");
    assertEquals("java.lang.String", shadow.declaredType(call(shadow, "info").receiver));
  }
}
