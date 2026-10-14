package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import org.junit.Test;

public class BankPythonAnalysisTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private BankFlow.Program adapt(String source) {
    return BankPythonAnalysis.adapt(Arrays.asList(new SourceFile("package/app.py", source)), NEVER);
  }

  private List<BankFlow.Expr> calls(BankFlow.Program p) {
    List<BankFlow.Expr> found = new ArrayList<BankFlow.Expr>();
    for (BankFlow.Function f : p.functions) collect(f.body, found);
    return found;
  }

  private void collect(List<BankFlow.Stmt> body, List<BankFlow.Expr> found) {
    for (BankFlow.Stmt s : body) {
      collect(s.expr, found);
      collect(s.body, found);
      collect(s.otherwise, found);
      collect(s.finalizer, found);
      for (List<BankFlow.Stmt> handler : s.handlers) collect(handler, found);
    }
  }

  private void collect(BankFlow.Expr e, List<BankFlow.Expr> found) {
    if (e == null) return;
    if ("CALL".equals(e.kind)) found.add(e);
    collect(e.receiver, found);
    for (BankFlow.Expr a : e.args) collect(a, found);
  }

  private BankFlow.Function function(BankFlow.Program p, String name) {
    for (BankFlow.Function f : p.functions) if (f.symbol.endsWith("." + name)) return f;
    throw new AssertionError("Missing function " + name);
  }

  private boolean symbol(BankFlow.Program p, String name) {
    for (BankFlow.Expr e : calls(p)) if (name.equals(e.symbol)) return true;
    return false;
  }

  @Test
  public void resolvesAliasedImportsAndPositionalSlots() {
    BankFlow.Program p =
        adapt(
            "from boundary import outbound as publish\n"
                + "def use(payload):\n"
                + "    publish(payload, True)\n");
    assertTrue(symbol(p, "boundary.outbound"));
    BankFlow.Expr call = calls(p).get(0);
    assertEquals(2, call.args.size());
    assertEquals("payload", call.args.get(0).name);
    assertEquals(Boolean.TRUE, call.args.get(1).literal);
    assertEquals("package/app.py", call.path);
    assertEquals(3, call.line);
  }

  @Test
  public void resolvesDottedImportsWithoutSuffixMatching() {
    BankFlow.Program p =
        adapt(
            "import company.boundary\n"
                + "import unrelated as other\n"
                + "company.boundary.send(value)\n"
                + "other.send(value)\n");
    assertTrue(symbol(p, "company.boundary.send"));
    assertTrue(symbol(p, "unrelated.send"));
    assertFalse(symbol(p, "boundary.send"));
  }

  @Test
  public void parametersShadowImportedIdentity() {
    assertFalse(
        symbol(
            adapt("import boundary\ndef use(boundary):\n    boundary.send(value)\n"),
            "boundary.send"));
  }

  @Test
  public void localAssignmentShadowsThroughoutFunction() {
    assertFalse(
        symbol(
            adapt("import boundary\ndef use():\n    boundary.send(value)\n    boundary = other\n"),
            "boundary.send"));
  }

  @Test
  public void sourceDefinitionsDoNotMasqueradeAsImportedContracts() {
    assertFalse(
        symbol(
            adapt("from boundary import send\ndef send(value):\n    pass\nsend(value)\n"),
            "boundary.send"));
  }

  @Test
  public void conditionalRelativeAndStarImportsRemainUnknown() {
    assertFalse(
        symbol(
            adapt("if enabled:\n    from boundary import send\nsend(value)\n"), "boundary.send"));
    assertFalse(symbol(adapt("from .boundary import send\nsend(value)\n"), "boundary.send"));
    assertFalse(
        symbol(
            adapt("import boundary\nfrom dynamic import *\nboundary.send(value)\n"),
            "boundary.send"));
  }

  @Test
  public void callBeforeLocalImportIsNotResolved() {
    assertFalse(
        symbol(
            adapt("def use(value):\n    send(value)\n    from boundary import send\n"),
            "boundary.send"));
    assertTrue(
        symbol(
            adapt("def use(value):\n    from boundary import send\n    send(value)\n"),
            "boundary.send"));
  }

  @Test
  public void repeatedImportDoesNotPickAnArbitraryIdentity() {
    assertFalse(
        symbol(
            adapt("from first import send\nfrom second import send\nsend(value)\n"), "first.send"));
    assertFalse(
        symbol(
            adapt("from first import send\nfrom second import send\nsend(value)\n"),
            "second.send"));
  }

  @Test
  public void singleLocalFactoryOriginQualifiesInstanceMethods() {
    BankFlow.Program p =
        adapt(
            "from supplier import Client as Port\n"
                + "def use(value):\n"
                + "    port = Port()\n"
                + "    port.send(value)\n");
    assertTrue(symbol(p, "supplier.Client.send"));
    for (BankFlow.Expr call : calls(p))
      if ("supplier.Client.send".equals(call.symbol)) {
        assertEquals(1, call.args.size());
        assertEquals("NAME", call.receiver.kind);
        assertEquals("port", call.receiver.name);
      }
  }

  @Test
  public void reassigningFactoryResultPreventsInferredInstanceContract() {
    assertFalse(
        symbol(
            adapt(
                "from supplier import Client\n"
                    + "def use(value):\n"
                    + "    port = Client()\n"
                    + "    port = replacement\n"
                    + "    port.send(value)\n"),
            "supplier.Client.send"));
  }

  @Test
  public void conditionalFactoryBindingIsUnknown() {
    assertFalse(
        symbol(
            adapt(
                "from supplier import Client\n"
                    + "def use(value):\n"
                    + "    if enabled:\n"
                    + "        port = Client()\n"
                    + "    port.send(value)\n"),
            "supplier.Client.send"));
  }

  @Test
  public void mutatingAnImportedOrInstanceAttributeInvalidatesIdentity() {
    assertFalse(
        symbol(
            adapt("import boundary\nboundary.send = replacement\nboundary.send(value)\n"),
            "boundary.send"));
    assertFalse(
        symbol(
            adapt(
                "from supplier import Client\n"
                    + "port = Client()\n"
                    + "port.send = replacement\n"
                    + "port.send(value)\n"),
            "supplier.Client.send"));
    assertFalse(
        symbol(
            adapt(
                "import boundary\nsetattr(boundary, 'send', replacement)\nboundary.send(value)\n"),
            "boundary.send"));
  }

  @Test
  public void aliasEscapeInvalidatesFactoryOrModuleIdentity() {
    assertFalse(
        symbol(
            adapt(
                "from supplier import Client\n"
                    + "port = Client()\n"
                    + "alias = port\n"
                    + "alias.send = replacement\n"
                    + "port.send(value)\n"),
            "supplier.Client.send"));
    assertFalse(
        symbol(
            adapt(
                "import boundary\n"
                    + "alias = boundary\n"
                    + "alias.send = replacement\n"
                    + "boundary.send(value)\n"),
            "boundary.send"));
  }

  @Test
  public void dynamicGetattrAndFactoriesDoNotAcquireExactIdentity() {
    assertFalse(
        symbol(adapt("import boundary\ngetattr(boundary, 'send')(value)\n"), "boundary.send"));
    assertFalse(
        symbol(
            adapt("import boundary\nboundary.factory().send(value)\n"), "boundary.factory.send"));
  }

  @Test
  public void keywordAndStarCallsCannotGuessPolicySlots() {
    assertFalse(symbol(adapt("from boundary import send\nsend(payload=value)\n"), "boundary.send"));
    assertFalse(symbol(adapt("from boundary import send\nsend(*values)\n"), "boundary.send"));
    assertFalse(symbol(adapt("from boundary import send\nsend(**values)\n"), "boundary.send"));
  }

  @Test
  public void retainsIfPolarityAndRejectingReturn() {
    BankFlow.Program p =
        adapt(
            "from boundary import check, send\n"
                + "def use(value):\n"
                + "    allowed = check(value)\n"
                + "    if not allowed:\n"
                + "        return\n"
                + "    send(value)\n");
    BankFlow.Function f = function(p, "use");
    assertEquals("ASSIGN", f.body.get(0).kind);
    assertEquals("allowed", f.body.get(0).target);
    BankFlow.Stmt branch = f.body.get(1);
    assertEquals("IF", branch.kind);
    assertEquals("UNARY", branch.expr.kind);
    assertEquals("not", branch.expr.operator);
    assertEquals("allowed", branch.expr.args.get(0).name);
    assertEquals("RETURN", branch.body.get(0).kind);
  }

  @Test
  public void elifAndElseAreDistinctPaths() {
    BankFlow.Function f =
        function(
            adapt(
                "def use(value):\n"
                    + "    if value == False:\n"
                    + "        return\n"
                    + "    elif value != True:\n"
                    + "        raise ValueError()\n"
                    + "    else:\n"
                    + "        value = None\n"),
            "use");
    BankFlow.Stmt first = f.body.get(0);
    assertEquals("==", first.expr.operator);
    assertEquals(Boolean.FALSE, first.expr.args.get(1).literal);
    BankFlow.Stmt second = first.otherwise.get(0);
    assertEquals("!=", second.expr.operator);
    assertEquals("THROW", second.body.get(0).kind);
    assertEquals("ASSIGN", second.otherwise.get(0).kind);
  }

  @Test
  public void tryExceptElseFinallyRetainsEveryRegion() {
    BankFlow.Function f =
        function(
            adapt(
                "def use(value):\n"
                    + "    try:\n"
                    + "        value = 1\n"
                    + "    except First:\n"
                    + "        value = 2\n"
                    + "    except Second:\n"
                    + "        return\n"
                    + "    else:\n"
                    + "        value = 3\n"
                    + "    finally:\n"
                    + "        value = 4\n"),
            "use");
    BankFlow.Stmt s = f.body.get(0);
    assertEquals("TRY", s.kind);
    assertEquals(1, s.body.size());
    assertEquals(2, s.handlers.size());
    assertEquals("RETURN", s.handlers.get(1).get(0).kind);
    assertEquals(Long.valueOf(3), s.otherwise.get(0).expr.literal);
    assertEquals(Long.valueOf(4), s.finalizer.get(0).expr.literal);
  }

  @Test
  public void unsupportedLoopKeepsCandidateCallsButNotDefiniteFlow() {
    BankFlow.Program p =
        adapt("from boundary import send\nfor value in values:\n    send(value)\n");
    assertEquals("UNKNOWN", p.functions.get(0).body.get(0).kind);
    assertTrue(symbol(p, "boundary.send"));
    assertFalse(p.diagnostics.isEmpty());
  }

  @Test
  public void commentsAndStringContentsAreNotExecutableCalls() {
    BankFlow.Program p =
        adapt("import boundary\n# boundary.send(value)\ntext = 'boundary.send(value)'\n");
    assertEquals(0, calls(p).size());
  }

  @Test
  public void parserFailureDiscardsAllFlow() {
    BankFlow.Program p = adapt("import boundary\nboundary.send(value)\ndef broken(:\n    pass\n");
    assertTrue(p.functions.isEmpty());
    assertEquals("BANK_PYTHON_PARSE_FAILED", p.diagnostics.get(0).get("code"));
  }

  @Test
  public void decoratorsAndGlobalMutationDoNotCreateDefiniteCoverage() {
    BankFlow.Function decorated =
        function(adapt("@wrapped\ndef use(value):\n    return value\n"), "use");
    assertEquals("UNKNOWN", decorated.body.get(0).kind);
    assertFalse(
        symbol(
            adapt(
                "import boundary\n"
                    + "def use(value):\n"
                    + "    global boundary\n"
                    + "    boundary.send(value)\n"),
            "boundary.send"));
  }

  @Test
  public void caseRemainsAValidSoftKeywordIdentifier() {
    BankFlow.Function f =
        function(adapt("def use(case):\n    case = False\n    return case\n"), "use");
    assertEquals("case", f.params.get(0));
    assertEquals("ASSIGN", f.body.get(0).kind);
  }

  @Test(expected = CancellationException.class)
  public void cancellationIsNotSwallowed() {
    BankPythonAnalysis.adapt(
        Arrays.asList(new SourceFile("app.py", "pass\n")),
        new Cancel() {
          public void check() {
            throw new CancellationException();
          }
        });
  }

  @Test
  public void excessiveTokensDiscardTheFileAndRemainUnknown() {
    StringBuilder source = new StringBuilder();
    for (int i = 0; i < 51000; i++) source.append("v=1\n");
    BankFlow.Program p = adapt(source.toString());
    assertTrue(p.functions.isEmpty());
    assertEquals("BANK_PYTHON_ANALYSIS_LIMIT", p.diagnostics.get(0).get("code"));
  }
}
