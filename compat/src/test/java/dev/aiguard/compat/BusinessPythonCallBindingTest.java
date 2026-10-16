package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

public class BusinessPythonCallBindingTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private BusinessFlow.Program adapt(String source) {
    return BusinessPythonAnalysis.adapt(
        Arrays.asList(new SourceFile("sample/workflow.py", source)), NEVER);
  }

  private BusinessFlow.Function function(BusinessFlow.Program program, String suffix) {
    for (BusinessFlow.Function function : program.functions)
      if (function.symbol.endsWith(suffix)) return function;
    throw new AssertionError("Missing function " + suffix);
  }

  private List<BusinessFlow.Expr> calls(BusinessFlow.Function function) {
    List<BusinessFlow.Expr> found = new ArrayList<BusinessFlow.Expr>();
    collect(function.body, found);
    return found;
  }

  private void collect(List<BusinessFlow.Stmt> body, List<BusinessFlow.Expr> found) {
    for (BusinessFlow.Stmt statement : body) {
      collect(statement.expr, found);
      collect(statement.body, found);
      collect(statement.otherwise, found);
      collect(statement.finalizer, found);
      for (List<BusinessFlow.Stmt> handler : statement.handlers) collect(handler, found);
    }
  }

  private void collect(BusinessFlow.Expr expr, List<BusinessFlow.Expr> found) {
    if (expr == null) return;
    if ("CALL".equals(expr.kind)) found.add(expr);
    collect(expr.receiver, found);
    for (BusinessFlow.Expr arg : expr.args) collect(arg, found);
    for (BusinessFlow.Expr member : expr.members.values()) collect(member, found);
  }

  private void noTarget(String source) {
    BusinessFlow.Program program = adapt(source);
    assertTrue("Fixture must parse", program.incompletePaths.isEmpty());
    int seen = 0;
    for (BusinessFlow.Function function : program.functions)
      for (BusinessFlow.Expr call : calls(function)) {
        seen++;
        assertEquals("Unexpected local target at line " + call.line, "", call.localTargetId);
      }
    assertTrue("Fixture must retain a call", seen > 0);
  }

  @Test
  public void moduleFunctionReceivesUniqueSourceIdentityAndOrderedParameters() {
    BusinessFlow.Program program =
        adapt(
            "def forward(subject, resource):\n"
                + "    return subject\n"
                + "def entry(user, key):\n"
                + "    return forward(user, key)\n");
    BusinessFlow.Function target = function(program, ".forward");
    BusinessFlow.Expr call = calls(function(program, ".entry")).get(0);
    assertTrue(target.id.startsWith("sample/workflow.py:"));
    assertFalse(target.id.equals(function(program, ".<module>").id));
    assertEquals(target.id, call.localTargetId);
    assertFalse(call.localTargetCandidate);
    assertEquals("", call.symbol);
    assertEquals(Arrays.asList("subject", "resource"), target.parameterNames);
    assertEquals("user", call.args.get(0).name);
    assertEquals("key", call.args.get(1).name);
    assertTrue(program.diagnostics.isEmpty());
  }

  @Test
  public void keywordNamesRetainEvaluationOrderForCoreArgumentBinding() {
    BusinessFlow.Program program =
        adapt(
            "def forward(subject, resource):\n"
                + "    return subject\n"
                + "def entry(user, key):\n"
                + "    return forward(resource=key, subject=user)\n");
    BusinessFlow.Expr call = calls(function(program, ".entry")).get(0);
    assertEquals(function(program, ".forward").id, call.localTargetId);
    assertEquals(Arrays.asList("resource", "subject"), call.argNames);
    assertEquals("key", call.args.get(0).name);
    assertEquals("user", call.args.get(1).name);
  }

  @Test
  public void positionalAndKeywordArgumentsCanFillUniqueSlots() {
    BusinessFlow.Program program =
        adapt(
            "def forward(subject, resource):\n"
                + "    return subject\n"
                + "forward('u', resource='r')\n");
    BusinessFlow.Expr call = calls(function(program, ".<module>")).get(0);
    assertEquals(function(program, ".forward").id, call.localTargetId);
    assertEquals(Arrays.asList("", "resource"), call.argNames);
  }

  @Test
  public void recursiveBindingRemainsExplicitForCoreBudgetHandling() {
    BusinessFlow.Program program = adapt("def repeat(subject):\n    return repeat(subject)\n");
    BusinessFlow.Function target = function(program, ".repeat");
    assertEquals(target.id, calls(target).get(0).localTargetId);
  }

  @Test
  public void targetsAreIsolatedAcrossFilesWithSameSymbolAndArity() {
    String source = "def forward(value):\n    return value\nforward('x')\n";
    BusinessFlow.Program program =
        BusinessPythonAnalysis.adapt(
            Arrays.asList(new SourceFile("a.py", source), new SourceFile("b.py", source)), NEVER);
    BusinessFlow.Function a = function(program, "a.forward");
    BusinessFlow.Function b = function(program, "b.forward");
    assertFalse(a.id.equals(b.id));
    assertEquals(a.id, calls(function(program, "a.<module>")).get(0).localTargetId);
    assertEquals(b.id, calls(function(program, "b.<module>")).get(0).localTargetId);
  }

  @Test
  public void forwardDeclarationsDoNotAssumeModuleInitializationOrder() {
    noTarget("forward('x')\ndef forward(value):\n    return value\n");
    noTarget(
        "def entry(value):\n    return forward(value)\ndef forward(value):\n    return value\n");
  }

  @Test
  public void duplicateDefinitionsDoNotSelectFirstOrLastTarget() {
    noTarget(
        "def forward(value):\n    return value\n"
            + "def forward(other):\n    return other\nforward('x')\n");
    noTarget(
        "def forward(value):\n    return value\n"
            + "def forward(value, other):\n    return other\nforward('x')\n");
  }

  @Test
  public void conditionalDefinitionsAndClassNameCollisionsStayUnresolved() {
    noTarget("if enabled:\n    def forward(value):\n        return value\nforward('x')\n");
    noTarget("def forward(value):\n    return value\nclass forward:\n    pass\nforward('x')\n");
  }

  @Test
  public void moduleRebindingDeletionAndImportPreventLocalTarget() {
    String definition = "def forward(value):\n    return value\n";
    noTarget(definition + "forward = replacement\nforward('x')\n");
    noTarget(definition + "forward('x')\nforward = replacement\n");
    noTarget(definition + "del forward\nforward('x')\n");
    noTarget(definition + "forward, other = pair\nforward('x')\n");
    noTarget(definition + "from foreign import forward\nforward('x')\n");
  }

  @Test
  public void parameterAndFunctionLocalAssignmentsShadowModuleTarget() {
    String definition = "def forward(value):\n    return value\n";
    noTarget(definition + "def entry(forward):\n    return forward('x')\n");
    noTarget(definition + "def entry():\n    forward = replacement\n    return forward('x')\n");
    noTarget(definition + "def entry():\n    forward('x')\n    forward = replacement\n");
    noTarget(
        definition + "def entry():\n    from foreign import forward\n    return forward('x')\n");
  }

  @Test
  public void nestedDefinitionsAndInstanceMethodsNeverBecomeEagerModuleCalls() {
    noTarget(
        "def entry(value):\n"
            + "    def forward(item):\n        return item\n"
            + "    return forward(value)\n");
    noTarget(
        "class Flow:\n"
            + "    def forward(self, value):\n        return value\n"
            + "    def entry(self, value):\n        return self.forward(value)\n");
  }

  @Test
  public void decoratorsAndAsyncFunctionsNeverBecomeSynchronousTargets() {
    noTarget("@decorate\ndef forward(value):\n    return value\nforward('x')\n");
    noTarget("async def forward(value):\n    return value\nforward('x')\n");
  }

  @Test
  public void defaultsVariadicAndEvaluatedAnnotationsStayUnresolved() {
    noTarget("def forward(value='x'):\n    return value\nforward('y')\n");
    noTarget("def forward(*values):\n    return values\nforward('x')\n");
    noTarget("def forward(**values):\n    return values\nforward(value='x')\n");
    noTarget("def forward(value: str):\n    return value\nforward('x')\n");
    noTarget("def forward(value) -> str:\n    return value\nforward('x')\n");
  }

  @Test
  public void generatorCreationDoesNotExecuteYieldBody() {
    noTarget("def forward(value):\n    yield value\nforward('x')\n");
    noTarget("def forward(value):\n    yield from value\nforward('x')\n");
    noTarget("def forward(value):\n    answer = (yield value)\nforward('x')\n");
  }

  @Test
  public void nestedGeneratorDoesNotMakeOuterSynchronousFunctionLazy() {
    BusinessFlow.Program program =
        adapt(
            "def forward(value):\n"
                + "    def deferred():\n        yield value\n"
                + "    return value\nforward('x')\n");
    assertEquals(
        function(program, ".forward").id,
        calls(function(program, ".<module>")).get(0).localTargetId);
  }

  @Test
  public void invalidArityOrKeywordBindingNeverSelectsLocalFunction() {
    String definition = "def forward(subject, resource):\n    return subject\n";
    noTarget(definition + "forward('x')\n");
    noTarget(definition + "forward('x', 'y', 'z')\n");
    noTarget(definition + "forward('x', subject='y')\n");
    noTarget(definition + "forward(subject='x', other='y')\n");
  }

  @Test
  public void dynamicModuleNamespaceChangesDisableLocalTargets() {
    String definition = "def forward(value):\n    return value\n";
    noTarget(definition + "exec(code)\nforward('x')\n");
    noTarget(definition + "globals()['forward'] = replacement\nforward('x')\n");
    noTarget(definition + "from foreign import *\nforward('x')\n");
    noTarget(
        definition
            + "def change():\n    global forward\n    forward = replacement\nforward('x')\n");
  }

  @Test
  public void importedFunctionKeepsExistingExternalSymbolAndNoLocalTarget() {
    BusinessFlow.Program program =
        adapt("from foreign.access import inspect as forward\nforward('x')\n");
    BusinessFlow.Expr call = calls(function(program, ".<module>")).get(0);
    assertEquals("foreign.access.inspect", call.symbol);
    assertEquals("", call.localTargetId);
  }

  @Test
  public void decoratedAsyncAndDynamicFunctionsDoNotClaimSynchronousExecution() {
    for (String source :
        Arrays.asList(
            "@wrap\ndef forward(value):\n    return value\n",
            "async def forward(value):\n    return value\n",
            "def forward(value):\n    global setting\n    return value\n")) {
      BusinessFlow.Function function = function(adapt(source), ".forward");
      assertTrue(source, function.executionUncertain);
      assertEquals("UNKNOWN", function.body.get(0).kind);
    }
    assertTrue(function(adapt("exec(code)\n"), ".<module>").executionUncertain);
  }

  @Test
  public void ordinaryAdditionRetainsOperandsWithoutClaimingSynchronousValueEquality() {
    BusinessFlow.Function function =
        function(
            adapt("def forward(chunk):\n    full = ''\n    full += chunk\n    return full\n"),
            ".forward");
    assertFalse(function.executionUncertain);
    assertEquals("ASSIGN", function.body.get(1).kind);
    assertEquals("BINARY", function.body.get(1).expr.kind);
    assertEquals("+", function.body.get(1).expr.operator);
    assertEquals("full", function.body.get(1).expr.args.get(0).name);
    assertEquals("chunk", function.body.get(1).expr.args.get(1).name);
    assertFalse(function.body.get(1).orderUncertain);
  }

  @Test
  public void controlTransfersDoNotBecomeLinearCalculationStatements() {
    for (String expression :
        Arrays.asList(
            "full += item if enabled else other",
            "full += (enabled and item)",
            "full += (yield item)",
            "full += [item for item in values]")) {
      BusinessFlow.Function function =
          function(adapt("def forward():\n    " + expression + "\n"), ".forward");
      assertEquals(expression, "UNKNOWN", function.body.get(0).kind);
      assertTrue(expression, function.body.get(0).orderUncertain);
    }
  }

  @Test
  public void unknownWithControlKeepsOrderUncertain() {
    BusinessFlow.Function function =
        function(adapt("def forward():\n    with resource:\n        send()\n"), ".forward");
    assertEquals("UNKNOWN", function.body.get(0).kind);
    assertTrue(function.body.get(0).orderUncertain);
  }
}
