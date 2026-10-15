package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

public class BusinessPythonSemanticTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private BusinessFlow.Program adapt(String source) {
    return BusinessPythonAnalysis.adapt(
        Arrays.asList(new SourceFile("renamed/workflow.py", source)), NEVER);
  }

  private BusinessFlow.Program adapt(String source, String assurance) throws Exception {
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-all",
            "{\"version\":2,\"receivers\":[{\"owner\":\"renamed.workflow.Flow\","
                + "\"field\":\"checker\",\"type\":\"external.policy.Decider\",\"assurance\":\""
                + assurance
                + "\"}]}");
    return BusinessPythonAnalysis.adapt(
        Arrays.asList(new SourceFile("renamed/workflow.py", source)), NEVER, policy);
  }

  private BusinessFlow.Function function(BusinessFlow.Program program, String symbol) {
    for (BusinessFlow.Function f : program.functions) if (f.symbol.endsWith(symbol)) return f;
    throw new AssertionError("Missing function " + symbol);
  }

  private List<BusinessFlow.Expr> calls(BusinessFlow.Program program) {
    List<BusinessFlow.Expr> found = new ArrayList<BusinessFlow.Expr>();
    for (BusinessFlow.Function f : program.functions) collect(f.body, found);
    return found;
  }

  private void collect(List<BusinessFlow.Stmt> body, List<BusinessFlow.Expr> found) {
    for (BusinessFlow.Stmt s : body) {
      collect(s.expr, found);
      collect(s.body, found);
      collect(s.otherwise, found);
      collect(s.finalizer, found);
      for (List<BusinessFlow.Stmt> handler : s.handlers) collect(handler, found);
    }
  }

  private void collect(BusinessFlow.Expr e, List<BusinessFlow.Expr> found) {
    if (e == null) return;
    if ("CALL".equals(e.kind)) found.add(e);
    collect(e.receiver, found);
    for (BusinessFlow.Expr arg : e.args) collect(arg, found);
    for (BusinessFlow.Expr member : e.members.values()) collect(member, found);
  }

  private BusinessFlow.Expr call(BusinessFlow.Program program, String symbol) {
    for (BusinessFlow.Expr e : calls(program)) if (symbol.equals(e.symbol)) return e;
    throw new AssertionError("Missing call " + symbol);
  }

  @Test
  public void reorderedKeywordsKeepTheirNamesForContractNormalization() {
    BusinessFlow.Expr call =
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
    BusinessFlow.Program p =
        adapt(
            "class Flow:\n"
                + "    def forward(self, answer, mode='plain'):\n"
                + "        return answer\n");
    BusinessFlow.Function f = function(p, ".Flow.forward");
    assertEquals(Arrays.asList("answer", "mode"), f.params);
    assertEquals(f.params, f.parameterNames);
    assertEquals("RETURN", f.body.get(0).kind);
    assertTrue(p.diagnostics.isEmpty());
  }

  @Test
  public void actualDecoratorStillPreventsDefiniteControlFlow() {
    BusinessFlow.Function f =
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
    BusinessFlow.Function f =
        function(adapt("def forward(self, answer):\n    return answer\n"), ".forward");
    assertEquals(Arrays.asList("self", "answer"), f.params);
  }

  @Test
  public void returnDictionaryAndConstantMemberPathsRemainStructured() {
    BusinessFlow.Function f =
        function(
            adapt(
                "def forward(result):\n"
                    + "    return {'reply': {'text': result['answer']}, 'state': result.status}\n"),
            ".forward");
    BusinessFlow.Expr output = f.body.get(0).expr;
    assertEquals("MAP", output.kind);
    BusinessFlow.Expr answer = output.members.get("reply").members.get("text");
    assertEquals("MEMBER", answer.kind);
    assertEquals("answer", answer.name);
    assertEquals("result", answer.receiver.name);
    assertEquals("status", output.members.get("state").name);
  }

  @Test
  public void dynamicDictionaryKeysAndSubscriptsDoNotBecomeExactPaths() {
    BusinessFlow.Function dynamic =
        function(adapt("def forward(result, key):\n    return {key: result[key]}\n"), ".forward");
    assertEquals("UNKNOWN", dynamic.body.get(0).expr.kind);
    BusinessFlow.Function subscript =
        function(adapt("def forward(result, key):\n    return result[key]\n"), ".forward");
    assertEquals("UNKNOWN", subscript.body.get(0).expr.kind);
  }

  @Test
  public void literalKeysDecodeWithoutExecutingPython() {
    BusinessFlow.Function f =
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
    BusinessFlow.Function f =
        function(adapt("def forward(answer):\n    yield {'content': answer}\n"), ".forward");
    assertEquals("YIELD", f.body.get(0).kind);
    assertEquals("MAP", f.body.get(0).expr.kind);
    assertEquals("answer", f.body.get(0).expr.members.get("content").name);
  }

  @Test
  public void loopKeepsYieldBoundaryButDoesNotClaimExecution() {
    BusinessFlow.Function f =
        function(
            adapt("def forward(stream):\n    for part in stream:\n        yield {'text': part}\n"),
            ".forward");
    assertEquals("ITERATE", f.body.get(0).kind);
    assertEquals("part", f.body.get(0).target);
    assertEquals("YIELD", f.body.get(0).body.get(0).kind);
  }

  @Test
  public void operatorReceiverCandidateCarriesUncertainty() throws Exception {
    BusinessFlow.Expr e =
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
    BusinessFlow.Expr e =
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
      BusinessFlow.Program mutated =
          adapt(
              "class Flow:\n"
                  + "    def forward(self, answer):\n"
                  + "        "
                  + assignment
                  + "\n        return self.checker.decide(answer)\n",
              "reviewed");
      for (BusinessFlow.Expr candidate : calls(mutated))
        assertFalse("external.policy.Decider.decide".equals(candidate.symbol));
    }
  }

  @Test
  public void noReceiverPolicyMeansNoGuessedTypeOrSuffixMatch() {
    BusinessFlow.Program p =
        adapt(
            "class Flow:\n"
                + "    def forward(self, answer):\n"
                + "        return self.checker.decide(answer)\n");
    for (BusinessFlow.Expr e : calls(p)) assertEquals("", e.symbol);
  }

  @Test
  public void invalidKeywordOrdersAndUnpackingStayUnknown() {
    for (String args :
        Arrays.asList("first=value, value", "first=value, first=other", "**values", "*values")) {
      BusinessFlow.Program p = adapt("from supplier import send\nsend(" + args + ")\n");
      for (BusinessFlow.Expr e : calls(p)) assertFalse("supplier.send".equals(e.symbol));
    }
  }
}
