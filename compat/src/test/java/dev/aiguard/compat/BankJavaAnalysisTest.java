package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import org.junit.Test;

public class BankJavaAnalysisTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };

  private BankFlow.Program program(String... sources) {
    List<SourceFile> files = new ArrayList<SourceFile>();
    for (int i = 0; i < sources.length; i++)
      files.add(new SourceFile("src/Case" + i + ".java", sources[i]));
    return BankJavaAnalysis.adapt(files, NONE);
  }

  private BankFlow.Function function(BankFlow.Program program, String symbol) {
    assertTrue(program.diagnostics.toString(), program.diagnostics.isEmpty());
    for (BankFlow.Function function : program.functions)
      if (function.symbol.equals(symbol)) return function;
    throw new AssertionError("Missing function " + symbol);
  }

  private List<BankFlow.Expr> calls(BankFlow.Function function) {
    List<BankFlow.Expr> calls = new ArrayList<BankFlow.Expr>();
    statements(function.body, calls);
    return calls;
  }

  private void statements(List<BankFlow.Stmt> statements, List<BankFlow.Expr> calls) {
    for (BankFlow.Stmt statement : statements) {
      expressions(statement.expr, calls);
      statements(statement.body, calls);
      statements(statement.otherwise, calls);
      statements(statement.finalizer, calls);
      for (List<BankFlow.Stmt> handler : statement.handlers) statements(handler, calls);
    }
  }

  private void expressions(BankFlow.Expr expression, List<BankFlow.Expr> calls) {
    if (expression == null) return;
    if (expression.kind.equals("CALL")) calls.add(expression);
    expressions(expression.receiver, calls);
    for (BankFlow.Expr argument : expression.args) expressions(argument, calls);
  }

  @Test
  public void preservesLocalDataAndGuardControlFlow() {
    BankFlow.Function f =
        function(
            program(
                "package example; import remote.Data; import remote.Guard; import"
                    + " remote.Output;final class Use {void run(String customer){String"
                    + " value=Data.load(customer);boolean"
                    + " allowed=Guard.accept(value);if(!allowed)return;Output.send(value);}}"),
            "example.Use#run");
    assertEquals(1, f.params.size());
    assertEquals(4, f.body.size());
    BankFlow.Stmt source = f.body.get(0), guard = f.body.get(1), branch = f.body.get(2);
    assertEquals("ASSIGN", source.kind);
    assertEquals("remote.Data#load", source.expr.symbol);
    assertEquals(f.params.get(0), source.expr.args.get(0).name);
    assertEquals("remote.Guard#accept", guard.expr.symbol);
    assertEquals(source.target, guard.expr.args.get(0).name);
    assertEquals("IF", branch.kind);
    assertEquals("!", branch.expr.operator);
    assertEquals(guard.target, branch.expr.args.get(0).name);
    assertEquals("RETURN", branch.body.get(0).kind);
    assertEquals(source.target, f.body.get(3).expr.args.get(0).name);
  }

  @Test
  public void retainsTrueFalseEqualityAndElseThrow() {
    BankFlow.Function f =
        function(
            program(
                "class Use {void run(boolean accepted){if(accepted==true){send();}"
                    + "else {throw new IllegalArgumentException();} if(accepted!=false)return;}"
                    + "private void send(){}}"),
            "Use#run");
    BankFlow.Stmt first = f.body.get(0), second = f.body.get(1);
    assertEquals("==", first.expr.operator);
    assertEquals(Boolean.TRUE, first.expr.args.get(1).literal);
    assertEquals("THROW", first.otherwise.get(0).kind);
    assertEquals("!=", second.expr.operator);
    assertEquals(Boolean.FALSE, second.expr.args.get(1).literal);
  }

  @Test
  public void declaredReceiverTypeBindsInstanceCalls() {
    BankFlow.Function f =
        function(
            program(
                "import remote.Gateway; class Use {void run(Gateway client,String text)"
                    + "{client.send(text);}}"),
            "Use#run");
    BankFlow.Expr call = calls(f).get(0);
    assertEquals("remote.Gateway#send", call.symbol);
    assertEquals(1, call.args.size());
    assertEquals(f.params.get(0), call.receiver.name);
    assertEquals(f.params.get(1), call.args.get(0).name);
  }

  @Test
  public void qualifiedStaticCallsAreNotCollapsedToSimpleNames() {
    BankFlow.Function f =
        function(
            program("class Use {void run(String x){remote.policy.Guard.accept(x);}}"), "Use#run");
    assertEquals("remote.policy.Guard#accept", calls(f).get(0).symbol);
    assertNull(calls(f).get(0).receiver);
  }

  @Test
  public void importedStaticQualifierHasNoRuntimeReceiver() {
    BankFlow.Function f =
        function(
            program("import remote.Guard;class Use {void run(String x){Guard.accept(x);}}"),
            "Use#run");
    assertEquals("remote.Guard#accept", calls(f).get(0).symbol);
    assertNull(calls(f).get(0).receiver);
  }

  @Test
  public void sourceTypeShadowingCannotMatchExternalType() {
    BankFlow.Function f =
        function(
            program(
                "import remote.Guard; class Guard {static boolean accept(String x){return true;}}"
                    + "class Use {void run(String x){Guard.accept(x);}}"),
            "Use#run");
    assertEquals("Guard#accept", calls(f).get(0).symbol);
  }

  @Test
  public void localValueShadowingCannotMatchImportedType() {
    BankFlow.Function f =
        function(
            program(
                "import remote.Guard; class Use {void run(Object Guard,String x)"
                    + "{Guard.accept(x);}}"),
            "Use#run");
    assertEquals("java.lang.Object#accept", calls(f).get(0).symbol);
  }

  @Test
  public void unresolvedDottedValueIsNotAQualifiedType() {
    BankFlow.Function f =
        function(
            program("class Use {void run(Object remote,String x){remote.policy.Guard.accept(x);}}"),
            "Use#run");
    assertEquals("", calls(f).get(0).symbol);
  }

  @Test
  public void exactStaticImportBindsExternalApi() {
    BankFlow.Function f =
        function(
            program("import static remote.Guard.accept;class Use {void run(String x){accept(x);}}"),
            "Use#run");
    assertEquals("remote.Guard#accept", calls(f).get(0).symbol);
  }

  @Test
  public void ambiguousAndWildcardStaticImportsRemainUnknown() {
    for (String imports :
        Arrays.asList(
            "import static remote.Guard.accept;import static another.Guard.accept;",
            "import static remote.Guard.*;",
            "import static remote.Guard.accept;import static another.Guard.*;")) {
      BankFlow.Function f =
          function(program(imports + "class Use {void run(String x){accept(x);}}"), "Use#run");
      assertEquals("", calls(f).get(0).symbol);
    }
  }

  @Test
  public void localMethodShadowsStaticImport() {
    BankFlow.Function f =
        function(
            program(
                "import static remote.Guard.accept;final class Use {void run(String x){accept(x);}"
                    + "private boolean accept(String x){return false;}}"),
            "Use#run");
    assertEquals("Use#accept", calls(f).get(0).symbol);
  }

  @Test
  public void lexicalShadowingAndReassignmentUseDeclarationIds() {
    BankFlow.Function f =
        function(
            program(
                "import remote.Data;import remote.Output;class Use {void run(){"
                    + "{String value=Data.load();value=Data.other();Output.send(value);}"
                    + "{String value=Data.load();Output.send(value);}}}"),
            "Use#run");
    assertEquals(f.body.get(0).target, f.body.get(1).target);
    assertEquals(f.body.get(0).target, f.body.get(2).expr.args.get(0).name);
    assertFalse(f.body.get(0).target.equals(f.body.get(3).target));
    assertEquals(f.body.get(3).target, f.body.get(4).expr.args.get(0).name);
  }

  @Test
  public void callArityExcludesReceiverAndPreservesNestedReceiverCalls() {
    BankFlow.Function f =
        function(
            program(
                "final class Client {Client create(){return this;}void send(String x,int n){}"
                    + "void run(String x){create().send(x,2);}}"),
            "Client#run");
    BankFlow.Expr outer = calls(f).get(0);
    assertEquals("Client#send", outer.symbol);
    assertEquals(2, outer.args.size());
    assertEquals("CALL", outer.receiver.kind);
    assertEquals("Client#create", outer.receiver.symbol);
    assertEquals(0, outer.receiver.args.size());
    assertEquals(Long.valueOf(2), outer.args.get(1).literal);
  }

  @Test
  public void javaSevenNumericAndNullLiteralsRemainTyped() {
    BankFlow.Function f =
        function(
            program(
                "import remote.Output;class Use {void"
                    + " run(){Output.send(0b1_010,0xff,2L,1.5,null);}}"),
            "Use#run");
    List<BankFlow.Expr> args = calls(f).get(0).args;
    assertEquals(Long.valueOf(10), args.get(0).literal);
    assertEquals(Long.valueOf(255), args.get(1).literal);
    assertEquals(Long.valueOf(2), args.get(2).literal);
    assertEquals(Double.valueOf(1.5), args.get(3).literal);
    assertNull(args.get(4).literal);
    assertEquals("LITERAL", args.get(4).kind);
  }

  @Test
  public void duplicateTypesNeverEstablishDefiniteApiBinding() {
    BankFlow.Program result =
        program(
            "package remote;class Guard {static boolean accept(String x){return true;}}",
            "package remote;class Guard {static boolean accept(String x){return false;}}",
            "import remote.Guard;class Use {void run(String x){Guard.accept(x);}}");
    assertFalse(result.diagnostics.isEmpty());
    assertEquals("", calls(result.functions.get(2)).get(0).symbol);
  }

  @Test
  public void preservesJavaSevenResourcesMultiCatchAndFinally() {
    BankFlow.Function f =
        function(
            program(
                "import remote.Guard;import remote.Output; class Use {void run(String"
                    + " value){try(java.io.InputStream resource=new"
                    + " java.io.ByteArrayInputStream(new byte[0])){"
                    + "if(!Guard.accept(value))return;Output.send(value);}catch(java.io.IOException|IllegalArgumentException"
                    + " error){Output.send(value);}finally{Output.close();}}}"),
            "Use#run");
    BankFlow.Stmt attempt = f.body.get(0);
    assertEquals("TRY", attempt.kind);
    assertEquals("ASSIGN", attempt.body.get(0).kind);
    assertEquals("IF", attempt.body.get(1).kind);
    assertEquals(1, attempt.handlers.size());
    assertEquals("remote.Output#send", attempt.handlers.get(0).get(0).expr.symbol);
    assertEquals("remote.Output#close", attempt.finalizer.get(0).expr.symbol);
  }

  @Test
  public void unsupportedControlFlowKeepsCallsButCannotProveBarrier() {
    BankFlow.Function f =
        function(
            program(
                "import remote.Guard;import remote.Output;class Use {void run(String x){"
                    + "while(true){if(!Guard.accept(x))return;break;}Output.send(x);}}"),
            "Use#run");
    assertEquals("UNKNOWN", f.body.get(0).kind);
    assertEquals("remote.Guard#accept", calls(f).get(0).symbol);
    assertEquals("remote.Output#send", calls(f).get(1).symbol);
  }

  @Test
  public void lambdaBodyIsNotEagerlyExecuted() {
    BankFlow.Function f =
        function(
            program(
                "import remote.Guard;class Use {void run(String x){"
                    + "Runnable job=()->{Guard.accept(x);};}}"),
            "Use#run");
    assertEquals("ASSIGN", f.body.get(0).kind);
    assertEquals("UNKNOWN", f.body.get(0).expr.kind);
    assertTrue(calls(f).isEmpty());
  }

  @Test
  public void fieldStateCannotContaminateLocalFlow() {
    BankFlow.Function f =
        function(
            program("class Use {String value;void run(String x){value=x;String local=value;}}"),
            "Use#run");
    assertEquals("UNKNOWN", f.body.get(0).kind);
    assertEquals("ASSIGN", f.body.get(1).kind);
    assertEquals("UNKNOWN", f.body.get(1).expr.kind);
  }

  @Test
  public void missingMethodBodyIsExplicitlyUnknown() {
    BankFlow.Function f =
        function(program("interface Port {boolean check(String value);}"), "Port#check");
    assertEquals(1, f.params.size());
    assertEquals("UNKNOWN", f.body.get(0).kind);
  }

  @Test
  public void parseFailureDoesNotLeakPartialFunctionEvidence() {
    BankFlow.Program result = program("class Use {void broken(}");
    assertTrue(result.functions.isEmpty());
    assertEquals("BANK_JAVA_PARSE_INCOMPLETE", result.diagnostics.get(0).get("code"));
  }

  @Test(expected = CancellationException.class)
  public void cancellationStopsAdaptation() {
    BankJavaAnalysis.adapt(
        Arrays.asList(new SourceFile("Use.java", "class Use {}")),
        new Cancel() {
          public void check() {
            throw new CancellationException();
          }
        });
  }
}
