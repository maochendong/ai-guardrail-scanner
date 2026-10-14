package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Map;
import org.junit.Test;

public class PythonProvenanceTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private AnalysisResult scan(String source) {
    return PythonAnalysis.analyze(Arrays.asList(new SourceFile("app.py", source)), NEVER);
  }

  private boolean chain(AnalysisResult result) {
    for (Map<String, Object> assessment : result.assessments)
      if ("OBSERVED".equals(assessment.get("disposition"))
          && String.valueOf(assessment.get("explanation")).contains("consumer-result")) return true;
    return false;
  }

  private boolean violation(AnalysisResult result) {
    for (Map<String, Object> assessment : result.assessments)
      if ("VIOLATED".equals(assessment.get("disposition"))) return true;
    return false;
  }

  private static final String SOURCE =
      "from openai import OpenAI\n"
          + "client=OpenAI()\nraw=client.chat.completions.create().choices[0].message.content\n";
  private static final String CONSUMER =
      "class Verdict:\n"
          + "    def __init__(self, payload):\n"
          + "        self.payload=payload\n"
          + "        self.label='constant'\n"
          + "    def chosen(self):\n"
          + "        return self.payload != ''\n"
          + "def inspect(value):\n"
          + "    return Verdict(value)\n";

  @Test
  public void crossFileConstructorKeywordInjectionReachesModelCall() {
    AnalysisResult result =
        PythonAnalysis.analyze(
            Arrays.asList(
                new SourceFile(
                    "ports.py", "from openai import OpenAI\ndef factory():\n    return OpenAI()\n"),
                new SourceFile(
                    "reader.py",
                    "class Reader:\n"
                        + "    def __init__(self, remote):\n"
                        + "        self.port=remote\n"
                        + "    def read(self):\n"
                        + "        return"
                        + " self.port.chat.completions.create().choices[0].message.content\n"),
                new SourceFile(
                    "app.py",
                    "from ports import factory\nfrom reader import Reader\n"
                        + "reader=Reader(remote=factory())\nbody=reader.read()\n")),
            NEVER);
    assertTrue(result.aiDetected);
    assertEquals(1, result.gatewayMethods);
  }

  @Test
  public void nestedFieldInjectionRetainsCandidateSdkProvenance() {
    AnalysisResult result =
        scan(
            "from openai import OpenAI\n"
                + "class Producer:\n"
                + "    def __init__(self, remote=None):\n"
                + "        self.remote=remote or OpenAI()\n"
                + "class Reader:\n"
                + "    def __init__(self, remote):\n"
                + "        self.port=remote\n"
                + "    def read(self):\n"
                + "        return self.port.chat.completions.create().choices[0].message.content\n"
                + "class Flow:\n"
                + "    def __init__(self, producer=None):\n"
                + "        self.producer=producer or Producer()\n"
                + "        self.reader=Reader(remote=self.producer.remote)\n"
                + "    def run(self):\n"
                + "        return self.reader.read()\n");
    assertTrue(result.aiDetected);
    assertFalse(violation(result));
  }

  @Test
  public void resultFieldAndPredicateAreObservedWithoutSecurityClaim() {
    AnalysisResult result =
        scan(SOURCE + CONSUMER + "decision=inspect(raw)\nif decision.chosen():\n    pass\n");
    assertTrue(chain(result));
    assertFalse(violation(result));
  }

  @Test
  public void returnedFieldAndStaticGetattrRetainResultChain() {
    assertTrue(
        chain(
            scan(
                SOURCE
                    + CONSUMER
                    + "def route():\n"
                    + "    decision=inspect(raw)\n"
                    + "    return getattr(decision,'payload',None)\n")));
  }

  @Test
  public void unrelatedConstantFieldDoesNotCarryResultChain() {
    assertFalse(
        chain(scan(SOURCE + CONSUMER + "decision=inspect(raw)\nif decision.label:\n    pass\n")));
  }

  @Test
  public void ignoredAndOverwrittenResultsDoNotCarryResultChain() {
    assertFalse(chain(scan(SOURCE + CONSUMER + "inspect(raw)\n")));
    assertFalse(
        chain(
            scan(
                SOURCE
                    + CONSUMER
                    + "decision=inspect(raw)\ndecision=True\nif decision:\n    pass\n")));
  }

  @Test
  public void unknownFunctionAndConstantReturnAreNotResultProof() {
    assertFalse(chain(scan(SOURCE + "decision=unknown(raw)\nif decision:\n    pass\n")));
    assertFalse(
        chain(
            scan(
                SOURCE
                    + "def inspect(value):\n"
                    + "    return True\n"
                    + "decision=inspect(raw)\n"
                    + "if decision:\n"
                    + "    pass\n")));
  }

  @Test
  public void renamedConsumerResultChainDoesNotDependOnGuardNames() {
    assertTrue(
        chain(
            scan(
                (SOURCE + CONSUMER + "verdict=inspect(raw)\nif verdict.payload:\n    pass\n")
                    .replace("Verdict", "Envelope")
                    .replace("inspect", "review")
                    .replace("payload", "score"))));
  }

  @Test
  public void teacherResponseIntoClassmethodResultIsTraceable() {
    assertTrue(
        chain(
            scan(
                SOURCE
                    + "import json\n"
                    + "class Verdict:\n"
                    + "    def __init__(self, score):\n"
                    + "        self.score=score\n"
                    + "    @classmethod\n"
                    + "    def build(cls, data):\n"
                    + "        return cls(data.get('score'))\n"
                    + "def inspect(value):\n"
                    + "    reply=client.chat.completions.create(messages=[value])\n"
                    + "    return Verdict.build(json.loads(reply.choices[0].message.content))\n"
                    + "decision=inspect(raw)\n"
                    + "if decision.score:\n"
                    + "    pass\n")));
  }

  @Test
  public void emittedThenConsumedStreamingContentIsObservationOnly() {
    AnalysisResult result =
        scan(
            SOURCE
                + CONSUMER
                + "def route():\n"
                + "    yield raw\n"
                + "    decision=inspect(raw)\n"
                + "    yield {'score':decision.payload}\n");
    assertTrue(chain(result));
    assertFalse(violation(result));
  }

  @Test
  public void literalContainerMetadataDoesNotInheritAllFieldResults() {
    assertFalse(
        chain(
            scan(
                SOURCE
                    + CONSUMER
                    + "decision=inspect(raw)\n"
                    + "bundle={'score':decision.payload,'count':1}\n"
                    + "if bundle.get('count'):\n"
                    + "    pass\n")));
    assertFalse(
        chain(
            scan(
                SOURCE
                    + "def inspect(value):\n    return len([value]) > 0\n"
                    + "decision=inspect(raw)\nif decision:\n    pass\n")));
  }

  @Test
  public void ignoredConstructorInputDoesNotFabricateReturnDependency() {
    assertFalse(
        chain(
            scan(
                SOURCE
                    + "class Fixed:\n    def __init__(self,value):\n        self.payload=True\n"
                    + "def inspect(value):\n    return Fixed(value)\n"
                    + "decision=inspect(raw)\nif decision:\n    pass\n")));
  }

  @Test
  public void unresolvedSiblingCallOnSameLineRemainsUnknown() {
    AnalysisResult result =
        scan(
            "from openai import OpenAI\n"
                + "OpenAI().chat.completions.create(); external.chat.completions.create()\n");
    boolean unresolved = false;
    for (Map<String, Object> diagnostic : result.diagnostics)
      if ("PYTHON_UNRESOLVED_MODEL_CALL".equals(diagnostic.get("code"))) unresolved = true;
    assertTrue(unresolved);
  }

  @Test
  public void missingRequiredArgumentDoesNotProveExecutableModelContent() {
    AnalysisResult result =
        scan(SOURCE + "def forward(value, unused):\n    return value\n" + "eval(forward(raw))\n");
    assertTrue(result.aiDetected);
    assertFalse(violation(result));
  }
}
