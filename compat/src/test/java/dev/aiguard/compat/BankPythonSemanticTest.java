package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

public class BankPythonSemanticTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private BankFlow.Program adapt(String source) {
    return BankPythonAnalysis.adapt(
        Arrays.asList(new SourceFile("renamed/workflow.py", source)), NEVER);
  }

  private BankFlow.Program adapt(String source, String assurance) throws Exception {
    BankPolicy policy =
        BankPolicy.parse(
            "bank-all",
            "{\"version\":2,\"receivers\":[{\"owner\":\"renamed.workflow.Flow\","
                + "\"field\":\"checker\",\"type\":\"external.policy.Decider\",\"assurance\":\""
                + assurance
                + "\"}]}");
    return BankPythonAnalysis.adapt(
        Arrays.asList(new SourceFile("renamed/workflow.py", source)), NEVER, policy);
  }

  private BankFlow.Function function(BankFlow.Program program, String symbol) {
    for (BankFlow.Function f : program.functions) if (f.symbol.endsWith(symbol)) return f;
    throw new AssertionError("Missing function " + symbol);
  }

  private List<BankFlow.Expr> calls(BankFlow.Program program) {
    List<BankFlow.Expr> found = new ArrayList<BankFlow.Expr>();
    for (BankFlow.Function f : program.functions) collect(f.body, found);
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
    for (BankFlow.Expr arg : e.args) collect(arg, found);
    for (BankFlow.Expr member : e.members.values()) collect(member, found);
  }

  private BankFlow.Expr call(BankFlow.Program program, String symbol) {
    for (BankFlow.Expr e : calls(program)) if (symbol.equals(e.symbol)) return e;
    throw new AssertionError("Missing call " + symbol);
  }

  @Test
  public void reorderedKeywordsKeepTheirNamesForContractNormalization() {
    BankFlow.Expr call =
        call(
            adapt(
                "from foreign.port import send as publish\n"
                    + "def forward(answer, target):\n"
                    + "    publish(answer, retries=2, destination=target)\n"),
            "foreign.port.send");
    assertEquals(Arrays.asList("", "retries", "destination"), call.argNames);
    assertEquals("answer", call.args.get(0).name);
    assertEquals(Long.valueOf(2), call.args.get(1).literal);
    assertEquals("target", call.args.get(2).name);
  }

  @Test
  public void ordinaryClassMethodHasExplicitParametersAndNoInventedDecorator() {
    BankFlow.Program p =
        adapt(
            "class Flow:\n"
                + "    def forward(self, answer, mode='plain'):\n"
                + "        return answer\n");
    BankFlow.Function f = function(p, ".Flow.forward");
    assertEquals(Arrays.asList("answer", "mode"), f.params);
    assertEquals(f.params, f.parameterNames);
    assertEquals("RETURN", f.body.get(0).kind);
    assertTrue(p.diagnostics.isEmpty());
  }

  @Test
  public void actualDecoratorStillPreventsDefiniteControlFlow() {
    BankFlow.Function f =
        function(
            adapt(
                "class Flow:\n"
                    + "    @classmethod\n"
                    + "    def forward(cls, answer):\n"
                    + "        return answer\n"),
            ".Flow.forward");
    assertEquals(Arrays.asList("answer"), f.params);
    assertEquals("UNKNOWN", f.body.get(0).kind);
  }

  @Test
  public void parameterNamedSelfOutsideAClassIsNotAnImplicitReceiver() {
    BankFlow.Function f =
        function(adapt("def forward(self, answer):\n    return answer\n"), ".forward");
    assertEquals(Arrays.asList("self", "answer"), f.params);
  }

  @Test
  public void returnDictionaryAndConstantMemberPathsRemainStructured() {
    BankFlow.Function f =
        function(
            adapt(
                "def forward(result):\n"
                    + "    return {'reply': {'text': result['answer']}, 'state': result.status}\n"),
            ".forward");
    BankFlow.Expr output = f.body.get(0).expr;
    assertEquals("MAP", output.kind);
    BankFlow.Expr answer = output.members.get("reply").members.get("text");
    assertEquals("MEMBER", answer.kind);
    assertEquals("answer", answer.name);
    assertEquals("result", answer.receiver.name);
    assertEquals("status", output.members.get("state").name);
  }

  @Test
  public void dynamicDictionaryKeysAndSubscriptsDoNotBecomeExactPaths() {
    BankFlow.Function dynamic =
        function(adapt("def forward(result, key):\n    return {key: result[key]}\n"), ".forward");
    assertEquals("UNKNOWN", dynamic.body.get(0).expr.kind);
    BankFlow.Function subscript =
        function(adapt("def forward(result, key):\n    return result[key]\n"), ".forward");
    assertEquals("UNKNOWN", subscript.body.get(0).expr.kind);
  }

  @Test
  public void literalKeysDecodeWithoutExecutingPython() {
    BankFlow.Function f =
        function(
            adapt("def forward(answer):\n    return {'an\\x73wer': answer, u'\\u540d': True}\n"),
            ".forward");
    assertTrue(f.body.get(0).expr.members.containsKey("answer"));
    assertTrue(f.body.get(0).expr.members.containsKey("名"));
    assertEquals(
        "UNKNOWN",
        function(adapt("def forward():\n    return b'answer'\n"), ".forward")
            .body
            .get(0)
            .expr
            .kind);
    assertEquals(
        "UNKNOWN",
        function(adapt("def forward():\n    return 'a' 'b'\n"), ".forward").body.get(0).expr.kind);
  }

  @Test
  public void yieldDictionaryKeepsReleaseFieldWithoutPretendingToReturn() {
    BankFlow.Function f =
        function(adapt("def forward(answer):\n    yield {'content': answer}\n"), ".forward");
    assertEquals("YIELD", f.body.get(0).kind);
    assertEquals("MAP", f.body.get(0).expr.kind);
    assertEquals("answer", f.body.get(0).expr.members.get("content").name);
  }

  @Test
  public void loopKeepsYieldBoundaryButDoesNotClaimExecution() {
    BankFlow.Function f =
        function(
            adapt("def forward(stream):\n    for part in stream:\n        yield {'text': part}\n"),
            ".forward");
    assertEquals("UNKNOWN", f.body.get(0).kind);
    assertEquals("YIELD", f.body.get(0).body.get(0).kind);
  }

  @Test
  public void operatorReceiverCandidateCarriesUncertainty() throws Exception {
    BankFlow.Expr e =
        call(
            adapt(
                "class Flow:\n"
                    + "    def forward(self, answer):\n"
                    + "        return self.checker.decide(content=answer)\n",
                "candidate"),
            "external.policy.Decider.decide");
    assertTrue(e.bindingUncertain);
    assertEquals(Arrays.asList("content"), e.argNames);
    assertEquals("MEMBER", e.receiver.kind);
    assertEquals("checker", e.receiver.name);
  }

  @Test
  public void reviewedReceiverDoesNotOverrideLocalMutationOrRebinding() throws Exception {
    BankFlow.Expr e =
        call(
            adapt(
                "class Flow:\n"
                    + "    def forward(self, answer):\n"
                    + "        return self.checker.decide(answer)\n",
                "reviewed"),
            "external.policy.Decider.decide");
    assertFalse(e.bindingUncertain);
    for (String assignment :
        Arrays.asList(
            "self.checker = replacement",
            "self = replacement",
            "setattr(self, 'checker', replacement)")) {
      BankFlow.Program mutated =
          adapt(
              "class Flow:\n"
                  + "    def forward(self, answer):\n"
                  + "        "
                  + assignment
                  + "\n        return self.checker.decide(answer)\n",
              "reviewed");
      for (BankFlow.Expr candidate : calls(mutated))
        assertFalse("external.policy.Decider.decide".equals(candidate.symbol));
    }
  }

  @Test
  public void noReceiverPolicyMeansNoGuessedTypeOrSuffixMatch() {
    BankFlow.Program p =
        adapt(
            "class Flow:\n"
                + "    def forward(self, answer):\n"
                + "        return self.checker.decide(answer)\n");
    for (BankFlow.Expr e : calls(p)) assertEquals("", e.symbol);
  }

  @Test
  public void invalidKeywordOrdersAndUnpackingStayUnknown() {
    for (String args :
        Arrays.asList("first=value, value", "first=value, first=other", "**values", "*values")) {
      BankFlow.Program p = adapt("from supplier import send\nsend(" + args + ")\n");
      for (BankFlow.Expr e : calls(p)) assertFalse("supplier.send".equals(e.symbol));
    }
  }
}
