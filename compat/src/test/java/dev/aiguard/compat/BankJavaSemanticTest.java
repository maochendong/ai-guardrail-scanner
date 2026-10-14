package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.Arrays;
import org.junit.Test;

public class BankJavaSemanticTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private BankFlow.Function function(String source, String name) {
    BankFlow.Program program =
        BankJavaAnalysis.adapt(
            Arrays.asList(new SourceFile("src/Case.java", source)), NONE, BankPolicy.generic());
    assertTrue(program.diagnostics.toString(), program.diagnostics.isEmpty());
    for (BankFlow.Function function : program.functions)
      if (function.symbol.endsWith("#" + name)) return function;
    throw new AssertionError(name);
  }

  @Test
  public void declarationNamesAreSeparateFromLexicalIds() {
    BankFlow.Function f = function("class A {String f(String who,int resource){return who;}}", "f");
    assertEquals(Arrays.asList("who", "resource"), f.parameterNames);
    assertEquals(f.params.get(0), f.body.get(0).expr.name);
    assertFalse(f.params.get(0).equals("who"));
  }

  @Test
  public void fieldSelectionRetainsItsSpecificReceiver() {
    BankFlow.Function f =
        function(
            "import remote.Decision; class A {Object f(Decision first,Decision second){"
                + "Object a=first.allowed;Object b=second.allowed;return a;}}",
            "f");
    BankFlow.Expr a = f.body.get(0).expr, b = f.body.get(1).expr;
    assertEquals("MEMBER", a.kind);
    assertEquals("allowed", a.name);
    assertEquals(f.params.get(0), a.receiver.name);
    assertEquals(f.params.get(1), b.receiver.name);
  }

  @Test
  public void unknownReceiverDoesNotAcquireAnApiOwner() {
    BankFlow.Function f =
        function("class A {Object f(Object value){return value.unknown.allow();}}", "f");
    BankFlow.Expr call = f.body.get(0).expr;
    assertEquals("CALL", call.kind);
    assertEquals("", call.symbol);
    assertTrue(call.bindingUncertain);
    assertEquals("MEMBER", call.receiver.kind);
  }

  @Test
  public void exactReceiverTypeSupportsUndeclaredGeneratedGetterWithoutNameGuessing() {
    BankFlow.Function f =
        function(
            "import vendor.Decision; class A {boolean f(Decision first){return"
                + " first.isAccepted();}}",
            "f");
    BankFlow.Expr call = f.body.get(0).expr;
    assertEquals("vendor.Decision#isAccepted", call.symbol);
    assertFalse(call.bindingUncertain);
    assertEquals(f.params.get(0), call.receiver.name);
    BankFlow.Function other =
        function(
            "import unrelated.Decision;class A {boolean f(Decision first){return"
                + " first.isAccepted();}}",
            "f");
    assertEquals("unrelated.Decision#isAccepted", other.body.get(0).expr.symbol);
  }

  @Test
  public void overloadWithUnresolvedArgumentCannotEstablishExactBinding() {
    BankFlow.Function f =
        function(
            "final class Gate {boolean allow(String x){return true;}boolean allow(Integer x){return"
                + " false;}}class A {boolean f(Gate gate){return gate.allow(null);}}",
            "f");
    assertEquals("Gate#allow", f.body.get(0).expr.symbol);
    assertTrue(f.body.get(0).expr.bindingUncertain);
  }

  @Test
  public void uniquelyTypedOverloadRemainsBound() {
    BankFlow.Function f =
        function(
            "final class Gate {boolean allow(String x){return true;}boolean allow(Integer x){return"
                + " false;}}class A {boolean f(Gate gate){return gate.allow(\"x\");}}",
            "f");
    assertFalse(f.body.get(0).expr.bindingUncertain);
  }

  @Test
  public void constructorKeepsQualifiedTypeAndExactArguments() {
    BankFlow.Function f =
        function(
            "import vendor.Decision;class A {Object f(String text){return new"
                + " Decision(text,true);}}",
            "f");
    BankFlow.Expr value = f.body.get(0).expr;
    assertEquals("NEW", value.kind);
    assertEquals("vendor.Decision#<init>", value.symbol);
    assertEquals(f.params.get(0), value.args.get(0).name);
    assertEquals(Boolean.TRUE, value.args.get(1).literal);
    assertEquals(Arrays.asList("", ""), value.argNames);
  }

  @Test
  public void unresolvedConstructorArrayAndAnonymousClassStayUnknown() {
    for (String creation :
        Arrays.asList(
            "new Missing()",
            "new String[0]",
            "new String[]{}",
            "new Object(){public String toString(){return \"safe\";}}")) {
      BankFlow.Function f = function("class A {Object f(){return " + creation + ";}}", "f");
      assertEquals(creation, "UNKNOWN", f.body.get(0).expr.kind);
    }
  }

  @Test
  public void fixedMapFactoryPreservesNamedValuesAndConstantKeySelection() {
    BankFlow.Function f =
        function(
            "import java.util.Map; class A {Object f(String text,boolean ok){"
                + "Map<String,Object> d=Map.of(\"accepted\",ok,\"payload\",text);"
                + "return d.get(\"accepted\");}}",
            "f");
    BankFlow.Expr map = f.body.get(0).expr, member = f.body.get(1).expr;
    assertEquals("MAP", map.kind);
    assertEquals(2, map.members.size());
    assertEquals(f.params.get(1), map.members.get("accepted").name);
    assertEquals(f.params.get(0), map.members.get("payload").name);
    assertTrue(map.args.isEmpty());
    assertEquals("MEMBER", member.kind);
    assertEquals("accepted", member.name);
    assertEquals(f.body.get(0).target, member.receiver.name);
  }

  @Test
  public void duplicateDynamicOrOddMapArgumentsStayCalls() {
    for (String arguments : Arrays.asList("\"k\",true,\"k\",false", "key,true", "\"k\"")) {
      BankFlow.Function f =
          function(
              "import java.util.Map; class A {Object f(String key){return Map.of("
                  + arguments
                  + ");}}",
              "f");
      assertEquals(arguments, "CALL", f.body.get(0).expr.kind);
      assertTrue(f.body.get(0).expr.members.isEmpty());
    }
  }

  @Test
  public void lookalikeMapDoesNotBecomeIntrinsic() {
    BankFlow.Function f =
        function(
            "import vendor.Map;class A {Object f(Map result){Object d=Map.of(\"ok\",true);return"
                + " result.get(\"ok\");}}",
            "f");
    assertEquals("CALL", f.body.get(0).expr.kind);
    assertEquals("vendor.Map#of", f.body.get(0).expr.symbol);
    assertEquals("CALL", f.body.get(1).expr.kind);
    assertEquals("vendor.Map#get", f.body.get(1).expr.symbol);
  }

  @Test
  public void dynamicMapLookupAndStringMethodsRemainOperatorCalls() {
    BankFlow.Function f =
        function(
            "import java.util.Map;class A {Object f(Map result,String key){Object"
                + " a=result.get(key);return key.trim();}}",
            "f");
    assertEquals("CALL", f.body.get(0).expr.kind);
    assertEquals("java.util.Map#get", f.body.get(0).expr.symbol);
    assertEquals("CALL", f.body.get(1).expr.kind);
    assertEquals("java.lang.String#trim", f.body.get(1).expr.symbol);
  }

  @Test
  public void stringSubscriptRetainsStructureButDynamicSubscriptStaysUnknown() {
    BankFlow.Function f =
        function(
            "class A {Object f(Object source,String key){Object a=source[\"ok\"];return"
                + " source[key];}}",
            "f");
    assertEquals("MEMBER", f.body.get(0).expr.kind);
    assertEquals("ok", f.body.get(0).expr.name);
    assertEquals(f.params.get(0), f.body.get(0).expr.receiver.name);
    assertEquals("UNKNOWN", f.body.get(1).expr.kind);
  }
}
