package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Independent adversarial fixtures for context-sensitive Python provenance. */
public class PythonContextIsolationTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private static final String SDK =
      "from openai import OpenAI\nimport logging\n"
          + "port=OpenAI()\n"
          + "response=port.chat.completions.create(model='m', messages=[])\n"
          + "raw=response.choices[0].message.content\n";

  private static final String HOLDER =
      "from openai import OpenAI\nimport logging\n"
          + "class Relay:\n"
          + "    def __init__(self, port):\n"
          + "        self.port=port\n"
          + "    def body(self):\n"
          + "        response=self.port.chat.completions.create(model='m', messages=[])\n"
          + "        return response.choices[0].message.content\n";

  private AnalysisResult scan(String source) {
    AnalysisResult result =
        PythonAnalysis.analyze(Arrays.asList(new SourceFile("sample.py", source)), NEVER);
    for (Map<String, Object> diagnostic : result.diagnostics)
      assertFalse("Fixture must be parsed", "PYTHON_PARSE_FAILED".equals(diagnostic.get("code")));
    return result;
  }

  private boolean has(AnalysisResult result, String id, String disposition) {
    for (Map<String, Object> assessment : result.assessments)
      if (id.equals(assessment.get("ruleId")) && disposition.equals(assessment.get("disposition")))
        return true;
    return false;
  }

  private void noDefiniteSink(AnalysisResult result) {
    assertFalse(has(result, "AI-PY-003", "VIOLATED"));
    assertFalse(has(result, "AI-PY-007", "VIOLATED"));
  }

  @Test
  public void twoInstanceContextsDoNotShareConstructorArguments() {
    noDefiniteSink(
        scan(
            HOLDER
                + "recognized=Relay(OpenAI())\n"
                + "recognized.body()\n"
                + "other=Relay(external_client)\n"
                + "logging.info(other.body())\n"));
  }

  @Test
  public void unknownInstanceFirstDoesNotHideLaterRecognizedInstance() {
    AnalysisResult result =
        scan(
            HOLDER
                + "other=Relay(external_client)\n"
                + "other.body()\n"
                + "recognized=Relay(OpenAI())\n"
                + "logging.info(recognized.body())\n");
    assertTrue(has(result, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void argumentBindingsDoNotLeakBetweenCallsOfSameFunction() {
    noDefiniteSink(
        scan(
            SDK
                + "def forward(value):\n    return value\n"
                + "forward(raw)\nlogging.info(forward('fixed'))\n"));
  }

  @Test
  public void literalCallFirstDoesNotHideLaterRawArgument() {
    AnalysisResult result =
        scan(
            SDK
                + "def forward(value):\n    return value\n"
                + "forward('fixed')\nlogging.info(forward(raw))\n");
    assertTrue(has(result, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void constructorKeywordArgumentsBindByName() {
    AnalysisResult result =
        scan(
            HOLDER.replace("self, port", "self, label, port")
                + "recognized=Relay(port=OpenAI(), label='safe')\n"
                + "logging.info(recognized.body())\n");
    assertTrue(has(result, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void constructorDefaultDoesNotOverrideExplicitUnknownArgument() {
    noDefiniteSink(
        scan(
            HOLDER.replace("self, port", "self, port=OpenAI()")
                + "defaulted=Relay()\ndefaulted.body()\n"
                + "other=Relay(port=None)\nlogging.info(other.body())\n"));
  }

  @Test
  public void visibleConstructorDefaultSuppliesSdkProvenance() {
    AnalysisResult result =
        scan(
            HOLDER.replace("self, port", "self, port=OpenAI()")
                + "recognized=Relay()\nlogging.info(recognized.body())\n");
    assertTrue(has(result, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void unknownStarArgumentsDoNotEstablishRawContent() {
    noDefiniteSink(scan(HOLDER + "other=Relay(*arguments)\nlogging.info(other.body())\n"));
  }

  @Test
  public void keywordUnpackingDoesNotOverrideUnknownConstructionBoundary() {
    noDefiniteSink(
        scan(
            HOLDER
                + "arguments={'port':OpenAI()}\n"
                + "other=Relay(**arguments)\nlogging.info(other.body())\n"));
  }

  @Test
  public void undefinedReturnNameDoesNotReusePriorCallerValue() {
    noDefiniteSink(
        scan(
            SDK
                + "def forward(value):\n    return missing_value\n"
                + "logging.info(forward(raw))\n"));
  }

  @Test
  public void implicitNoneReturnRemainsAmbiguous() {
    noDefiniteSink(
        scan(
            SDK
                + "def maybe(value):\n    if external_condition:\n        return value\n"
                + "logging.info(maybe(raw))\n"));
  }

  @Test
  public void mixedRawAndLiteralConditionalReturnRemainsAmbiguous() {
    noDefiniteSink(
        scan(
            SDK
                + "def maybe(value):\n    return value if external_condition else 'fixed'\n"
                + "logging.info(maybe(raw))\n"));
  }

  @Test
  public void mixedRawAndUnknownExplicitReturnRemainsAmbiguous() {
    noDefiniteSink(
        scan(
            SDK
                + "def maybe(value):\n"
                + "    if external_condition:\n        return value\n"
                + "    return external_result\n"
                + "logging.info(maybe(raw))\n"));
  }

  @Test
  public void localClientReassignmentStopsInjectedProvenance() {
    noDefiniteSink(
        scan(
            "from openai import OpenAI\nimport logging\n"
                + "def body(port):\n"
                + "    port=external_client\n"
                + "    response=port.chat.completions.create(model='m', messages=[])\n"
                + "    return response.choices[0].message.content\n"
                + "logging.info(body(OpenAI()))\n"));
  }

  private static final String CHECKER =
      "class Verdict:\n"
          + "    def __init__(self, payload):\n"
          + "        self.payload=payload\n"
          + "        self.label='fixed'\n"
          + "    def accepted(self):\n"
          + "        return self.payload != ''\n"
          + "    def unrelated(self):\n"
          + "        return True\n"
          + "def inspect(value):\n"
          + "    return Verdict(value)\n";

  private boolean hasConsumerResultAt(AnalysisResult result, int line) {
    for (Map<String, Object> assessment : result.assessments) {
      if (!"AI-PY-007".equals(assessment.get("ruleId"))
          || !"OBSERVED".equals(assessment.get("disposition"))) continue;
      for (Object item : (List<?>) assessment.get("evidence")) {
        Map<?, ?> evidence = (Map<?, ?>) item;
        if (((Number) evidence.get("line")).intValue() == line
            && String.valueOf(evidence.get("detail")).contains("consumer-result")) return true;
      }
    }
    return false;
  }

  private int lineOf(String source, String marker) {
    int index = source.indexOf(marker);
    assertTrue("Fixture marker must exist", index >= 0);
    return source.substring(0, index).split("\n", -1).length;
  }

  @Test
  public void consumedResultPayloadCanReachConditionThroughVisiblePredicate() {
    String source =
        SDK + CHECKER + "decision=inspect(raw)\nif decision.accepted():\n    emit('fixed')\n";
    AnalysisResult result = scan(source);
    assertTrue(hasConsumerResultAt(result, lineOf(source, "if decision")));
    noDefiniteSink(result);
  }

  @Test
  public void overwrittenResultDoesNotReachCondition() {
    String source =
        SDK + CHECKER + "decision=inspect(raw)\ndecision=True\nif decision:\n    emit('fixed')\n";
    assertFalse(hasConsumerResultAt(scan(source), lineOf(source, "if decision")));
  }

  @Test
  public void unrelatedConstantFieldDoesNotCarryConsumerResult() {
    String source =
        SDK + CHECKER + "decision=inspect(raw)\nif decision.label:\n    emit('fixed')\n";
    assertFalse(hasConsumerResultAt(scan(source), lineOf(source, "if decision")));
  }

  @Test
  public void unrelatedPredicateDoesNotCarryConsumerResult() {
    String source =
        SDK + CHECKER + "decision=inspect(raw)\nif decision.unrelated():\n    emit('fixed')\n";
    assertFalse(hasConsumerResultAt(scan(source), lineOf(source, "if decision")));
  }

  @Test
  public void laterLiteralCallDoesNotReuseEarlierConsumerResult() {
    String source =
        SDK
            + CHECKER
            + "inspect(raw)\ndecision=inspect('fixed')\n"
            + "if decision.accepted():\n    emit('fixed')\n";
    assertFalse(hasConsumerResultAt(scan(source), lineOf(source, "if decision")));
  }

  @Test
  public void uncalledPredicateDoesNotImplyConsumedDecision() {
    String source =
        SDK + CHECKER + "decision=inspect(raw)\nif unrelated_flag:\n    emit('fixed')\n";
    assertFalse(hasConsumerResultAt(scan(source), lineOf(source, "if unrelated_flag")));
  }

  @Test
  public void positionalArgumentDoesNotBindKeywordOnlyParameter() {
    noDefiniteSink(
        scan(SDK + "def forward(*, value):\n    return value\n" + "logging.info(forward(raw))\n"));
  }

  @Test
  public void staticMethodCalledThroughInstanceDoesNotConsumeArgumentAsSelf() {
    AnalysisResult result =
        scan(
            "from openai import OpenAI\nimport logging\n"
                + "class Relay:\n"
                + "    @staticmethod\n"
                + "    def forward(value):\n        return value\n"
                + "port=Relay().forward(OpenAI())\n"
                + "response=port.chat.completions.create(model='m', messages=[])\n"
                + "logging.info(response.choices[0].message.content)\n");
    assertTrue(result.aiDetected);
    noDefiniteSink(result);
  }

  @Test
  public void staticMethodDoesNotShiftClientIntoAnotherArgument() {
    AnalysisResult result =
        scan(
            "from openai import OpenAI\n"
                + "class Relay:\n"
                + "    @staticmethod\n"
                + "    def select(first, second):\n        return second\n"
                + "port=Relay().select(OpenAI(), external_client)\n"
                + "port.chat.completions.create(model='m', messages=[])\n");
    assertFalse(result.aiDetected);
    noDefiniteSink(result);
  }

  @Test
  public void opaqueClassDecoratorDoesNotProveSdkImplementation() {
    noDefiniteSink(
        scan(
            HOLDER.replace("class Relay:", "@external_decorator\nclass Relay:")
                + "other=Relay(OpenAI())\nlogging.info(other.body())\n"));
  }

  @Test
  public void booleanConsumerResultRetainsDependencyWithoutBecomingRawContent() {
    String source =
        SDK
            + "def bounded(text):\n    return len(text) < 10\n"
            + "decision=bounded(raw)\n"
            + "logging.info(decision)\n"
            + "if decision:\n    emit('fixed')\n";
    AnalysisResult result = scan(source);
    assertTrue(hasConsumerResultAt(result, lineOf(source, "if decision")));
    noDefiniteSink(result);
  }

  @Test
  public void returningConstantDoesNotFabricateValidationDependency() {
    String source =
        SDK
            + "def bounded(text):\n    return True\n"
            + "decision=bounded(raw)\nif decision:\n    emit('fixed')\n";
    assertFalse(hasConsumerResultAt(scan(source), lineOf(source, "if decision")));
  }

  @Test
  public void returningAnotherArgumentDoesNotFabricateValidationDependency() {
    String source =
        SDK
            + "def bounded(text, flag):\n    return flag\n"
            + "decision=bounded(raw, external_flag)\n"
            + "if decision:\n    emit('fixed')\n";
    assertFalse(hasConsumerResultAt(scan(source), lineOf(source, "if decision")));
  }

  @Test
  public void externalInstanceFieldWriteInvalidatesConstructorProvenance() {
    noDefiniteSink(
        scan(
            HOLDER
                + "relay=Relay(OpenAI())\nrelay.port=external_client\n"
                + "logging.info(relay.body())\n"));
  }

  @Test
  public void aliasedExternalFieldWriteInvalidatesConstructorProvenance() {
    noDefiniteSink(
        scan(
            HOLDER
                + "relay=Relay(OpenAI())\nalias=relay\nalias.port=external_client\n"
                + "logging.info(relay.body())\n"));
  }

  @Test
  public void overwrittenSelfDoesNotRetainConstructedInstance() {
    noDefiniteSink(
        scan(
            HOLDER.replace(
                    "    def body(self):\n",
                    "    def body(self):\n        self=external_instance\n")
                + "relay=Relay(OpenAI())\nlogging.info(relay.body())\n"));
  }

  @Test
  public void callerBoundContentReachesConditionInsideInvokedWrapper() {
    String source =
        SDK
            + "def bounded(text):\n    return len(text) < 10\n"
            + "def run(text):\n"
            + "    decision=bounded(text)\n"
            + "    if decision:\n        return 'ok'\n"
            + "    return 'bad'\n"
            + "run(raw)\n";
    assertTrue(hasConsumerResultAt(scan(source), lineOf(source, "if decision")));
  }

  @Test
  public void literalArgumentWrapperDoesNotReuseOtherRawValue() {
    String source =
        SDK
            + "def bounded(text):\n    return len(text) < 10\n"
            + "def run(text):\n"
            + "    decision=bounded(text)\n"
            + "    if decision:\n        return 'ok'\n"
            + "    return 'bad'\n"
            + "run('fixed')\n";
    assertFalse(hasConsumerResultAt(scan(source), lineOf(source, "if decision")));
  }
}
