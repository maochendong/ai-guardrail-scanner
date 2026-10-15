package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.Arrays;
import org.junit.Test;

/** Syntax evidence for bounded iteration; execution and proof semantics belong to BusinessAnalysis. */
public class BusinessPythonIterationTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private BusinessFlow.Function function(String source, BusinessPolicy policy) {
    BusinessFlow.Program program =
        BusinessPythonAnalysis.adapt(
            Arrays.asList(new SourceFile("renamed/workflow.py", source)), NEVER, policy);
    for (BusinessFlow.Function function : program.functions)
      if (function.symbol.endsWith(".forward")) return function;
    throw new AssertionError("Missing forward function");
  }

  private BusinessFlow.Function function(String source) {
    return function(source, BusinessPolicy.generic());
  }

  @Test
  public void simpleTargetKeepsIterableCallAndYieldValuePath() {
    BusinessFlow.Stmt loop =
        function(
                "from external.port import stream\n"
                    + "def forward(query):\n"
                    + "    for part in stream(query):\n"
                    + "        yield {'content': part}\n")
            .body
            .get(0);
    assertEquals("ITERATE", loop.kind);
    assertEquals("part", loop.target);
    assertEquals("external.port.stream", loop.expr.symbol);
    assertEquals("query", loop.expr.args.get(0).name);
    assertEquals(3, loop.line);
    assertEquals("YIELD", loop.body.get(0).kind);
    assertEquals("part", loop.body.get(0).expr.members.get("content").name);
  }

  @Test
  public void loopElseRemainsSeparateFromIterationBody() {
    BusinessFlow.Stmt loop =
        function(
                "def forward(stream):\n"
                    + "    for part in stream:\n"
                    + "        yield part\n"
                    + "    else:\n"
                    + "        return 'done'\n")
            .body
            .get(0);
    assertEquals("ITERATE", loop.kind);
    assertEquals("stream", loop.expr.name);
    assertEquals("YIELD", loop.body.get(0).kind);
    assertEquals("RETURN", loop.otherwise.get(0).kind);
  }

  @Test
  public void complexTargetsAndWhileLoopsStayUnknown() {
    for (String header :
        Arrays.asList("for first, second in stream:", "for result.part in stream:", "while active:")) {
      BusinessFlow.Stmt loop =
          function("def forward(stream, result, active):\n    " + header + "\n        yield result\n")
              .body
              .get(0);
      assertEquals("UNKNOWN", loop.kind);
      assertEquals("", loop.target);
      assertEquals("YIELD", loop.body.get(0).kind);
    }
  }

  @Test
  public void candidateReceiverIsNotPromotedByIteration() throws Exception {
    BusinessPolicy policy =
        BusinessPolicy.parse(
            "bank-all",
            "{\"version\":2,\"receivers\":[{\"owner\":\"renamed.workflow.Flow\","
                + "\"field\":\"generator\",\"type\":\"external.model.Client\","
                + "\"assurance\":\"candidate\"}]}");
    BusinessFlow.Stmt loop =
        function(
                "class Flow:\n"
                    + "    def forward(self, query):\n"
                    + "        for part in self.generator.stream(query):\n"
                    + "            yield {'content': part}\n",
                policy)
            .body
            .get(0);
    assertEquals("ITERATE", loop.kind);
    assertEquals("external.model.Client.stream", loop.expr.symbol);
    assertTrue(loop.expr.bindingUncertain);
  }

  @Test
  public void loopBodyUnknownFlowIsNotSilentlyDiscarded() {
    BusinessFlow.Stmt loop =
        function(
                "def forward(stream, total):\n"
                    + "    for part in stream:\n"
                    + "        total += part\n"
                    + "        yield {'content': part}\n")
            .body
            .get(0);
    assertEquals("ITERATE", loop.kind);
    assertEquals("UNKNOWN", loop.body.get(0).kind);
    assertEquals("YIELD", loop.body.get(1).kind);
  }

  @Test
  public void iterationBindingDoesNotRestoreShadowedImportedSymbol() {
    BusinessFlow.Stmt loop =
        function(
                "from external.port import emit\n"
                    + "def forward(stream):\n"
                    + "    for emit in stream:\n"
                    + "        emit()\n")
            .body
            .get(0);
    assertEquals("ITERATE", loop.kind);
    assertEquals("emit", loop.target);
    assertEquals("", loop.body.get(0).expr.symbol);
  }
}
