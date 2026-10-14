package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import org.junit.Test;

public class PythonAnalysisTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private AnalysisResult scan(String source) {
    return PythonAnalysis.analyze(Arrays.asList(new SourceFile("app.py", source)), NEVER);
  }

  private static final String SDK =
      "from openai import OpenAI as Provider\nimport logging as journal\nport = Provider()\n";
  private static final String RESPONSE =
      "reply = port.chat.completions.create(model='model', messages=[])\n";

  private boolean has(AnalysisResult r, String id, String disposition) {
    for (Map<String, Object> a : r.assessments)
      if (id.equals(a.get("ruleId")) && disposition.equals(a.get("disposition"))) return true;
    return false;
  }

  @Test
  public void catalogCoversSevenDistinctDomains() {
    assertEquals(7, PythonAnalysis.catalog().size());
    for (int i = 0; i < 7; i++)
      assertEquals("L" + (i + 1), PythonAnalysis.catalog().get(i).get("domain"));
  }

  @Test
  public void aliasedSdkResponseContentLoggedHasDefiniteSourceSink() {
    AnalysisResult r = scan(SDK + RESPONSE + "journal.info(reply.choices[0].message.content)\n");
    assertTrue(r.aiDetected);
    assertTrue(has(r, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void namesMayBeRenamedWithoutChangingTheFinding() {
    String source = SDK + RESPONSE + "journal.info(reply.choices[0].message.content)\n";
    AnalysisResult r =
        scan(
            source
                .replace("Provider", "Remote")
                .replaceAll("\\bport\\b", "connection")
                .replace("reply", "envelope")
                .replace("journal", "audit"));
    assertTrue(has(r, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void unusedImportsCommentsAndStringsAreNotModelCalls() {
    AnalysisResult r =
        scan(
            "from openai import OpenAI\n"
                + "# OpenAI().chat.completions.create()\n"
                + "x='client.chat.completions.create()'\n");
    assertFalse(r.aiDetected);
    assertFalse(has(r, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void lookalikeClientAndParameterShadowingAreUnknown() {
    AnalysisResult r =
        scan(
            "from openai import OpenAI\n"
                + "def f(OpenAI):\n"
                + "    p=OpenAI()\n"
                + "    return p.chat.completions.create()\n");
    assertFalse(r.aiDetected);
    assertFalse(
        scan("class OpenAI:\n    pass\np=OpenAI()\np.chat.completions.create()\n").aiDetected);
  }

  @Test
  public void metadataAndSanitizedReturnsAreNotRawContent() {
    AnalysisResult r =
        scan(
            SDK
                + RESPONSE
                + "journal.info(reply.id)\n"
                + "journal.info(scrub(reply.choices[0].message.content))\n");
    assertTrue(r.aiDetected);
    assertFalse(has(r, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void reassignmentStopsPriorRawProvenance() {
    AnalysisResult r =
        scan(
            SDK
                + RESPONSE
                + "text=reply.choices[0].message.content\ntext='fixed'\njournal.info(text)\n");
    assertFalse(has(r, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void typedLoggerInstanceAndDefiniteRawExecutionAreFound() {
    AnalysisResult r =
        scan(
            SDK
                + RESPONSE
                + "logger=journal.getLogger(__name__)\n"
                + "body=reply.choices[0].message.content\n"
                + "logger.error(body)\n"
                + "eval(body)\n");
    assertTrue(has(r, "AI-PY-003", "VIOLATED"));
    assertTrue(has(r, "AI-PY-007", "VIOLATED"));
  }

  @Test
  public void unknownLoggerOrShadowedEvalDoesNotProveSink() {
    AnalysisResult r =
        scan(
            SDK
                + RESPONSE
                + "body=reply.choices[0].message.content\n"
                + "eval=custom\n"
                + "eval(body)\n"
                + "logger.info(body)\n");
    assertFalse(has(r, "AI-PY-003", "VIOLATED"));
    assertFalse(has(r, "AI-PY-007", "VIOLATED"));
  }

  @Test
  public void factoryAndClassFieldRetainSdkIdentity() {
    AnalysisResult r =
        scan(
            "from openai import OpenAI\n"
                + "def connect() -> OpenAI | None:\n"
                + "    return OpenAI()\n"
                + "class Renamed:\n"
                + "    def __init__(self):\n"
                + "        self.port=connect()\n"
                + "    def answer(self):\n"
                + "        r=self.port.chat.completions.create(model='x',messages=[])\n"
                + "        return r.choices[0].message.content\n");
    assertTrue(r.aiDetected);
  }

  @Test
  public void injectedClientHasCandidateEvidenceAndNoDefiniteLoggingViolation() {
    AnalysisResult r =
        scan(
            "from openai import OpenAI\n"
                + "import logging\n"
                + "class Service:\n"
                + "    def __init__(self, port=None):\n"
                + "        self.port=port or OpenAI()\n"
                + "    def answer(self):\n"
                + "        r=self.port.chat.completions.create(model='x',messages=[])\n"
                + "        logging.info(r.choices[0].message.content)\n");
    assertTrue(r.aiDetected);
    assertFalse(has(r, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void crossModuleFactoryAndRenamedGeneratorChainAreObserved() {
    List<SourceFile> files =
        Arrays.asList(
            new SourceFile(
                "connection.py",
                "from openai import OpenAI\ndef connect():\n    return OpenAI()\n"),
            new SourceFile(
                "engine.py",
                "from connection import connect\n"
                    + "class Streamer:\n"
                    + "    def __init__(self):\n"
                    + "        self.remote=connect()\n"
                    + "    def tokens(self):\n"
                    + "       "
                    + " stream=self.remote.chat.completions.create(model='x',messages=[],stream=True)\n"
                    + "        for parcel in stream:\n"
                    + "            yield parcel.choices[0].delta.content\n"),
            new SourceFile(
                "flow.py",
                "from engine import Streamer\n"
                    + "class Runner:\n"
                    + "    def __init__(self):\n"
                    + "        self.producer=Streamer()\n"
                    + "    def run(self):\n"
                    + "        for piece in self.producer.tokens():\n"
                    + "            yield {'type':'token','content':piece}\n"
                    + "        check(piece)\n"));
    AnalysisResult r = PythonAnalysis.analyze(files, NEVER);
    assertTrue(r.aiDetected);
    assertTrue(has(r, "AI-PY-005", "OBSERVED"));
    boolean flow = false;
    for (Map<String, Object> a : r.assessments)
      if ("AI-PY-005".equals(a.get("ruleId")))
        for (Object e : (List<?>) a.get("evidence"))
          if ("flow.py".equals(((Map<?, ?>) e).get("path"))) flow = true;
    assertTrue("Generator origin must reach a differently named wrapper", flow);
  }

  @Test
  public void retrievalUsesTypedChromaReceiver() {
    AnalysisResult r =
        scan(
            "import chromadb as db\n"
                + "c=db.PersistentClient(path='local')\n"
                + "collection=c.get_or_create_collection(name='docs')\n"
                + "hits=collection.query(query_texts=['q'],n_results=3)\n");
    boolean found = false;
    for (Map<String, Object> a : r.assessments)
      if ("AI-PY-002".equals(a.get("ruleId"))) found = !((List<?>) a.get("evidence")).isEmpty();
    assertTrue(found);
    assertFalse(scan("collection.query(query_texts=['q'])\n").aiDetected);
  }

  @Test
  public void fstringHasExplicitUnknownBoundaryNotRawLoggingProof() {
    AnalysisResult r =
        scan(SDK + RESPONSE + "journal.info(f'{reply.choices[0].message.content}')\n");
    assertFalse(has(r, "AI-PY-003", "VIOLATED"));
    boolean found = false;
    for (Map<String, Object> d : r.diagnostics)
      if ("PYTHON_FSTRING_BOUNDARY".equals(d.get("code"))) found = true;
    assertTrue(found);
  }

  @Test
  public void malformedFileAddsDiagnosticWithoutPositiveEvidence() {
    AnalysisResult r = scan(SDK + "def broken(:\n");
    assertFalse(r.aiDetected);
    assertEquals("PYTHON_PARSE_FAILED", r.diagnostics.get(0).get("code"));
  }

  @Test(expected = CancellationException.class)
  public void cancellationIsPropagated() {
    PythonAnalysis.analyze(
        Arrays.asList(new SourceFile("app.py", SDK)),
        new Cancel() {
          public void check() {
            throw new CancellationException();
          }
        });
  }

  @Test
  public void reportsDoNotContainSourceLiterals() {
    AnalysisResult r =
        scan(
            SDK
                + "secret='DO_NOT_REPORT_PRIVATE_2026'\n"
                + RESPONSE
                + "journal.info(reply.choices[0].message.content)\n");
    assertFalse(r.assessments.toString().contains("DO_NOT_REPORT_PRIVATE_2026"));
  }

  @Test
  public void mixedHelperReturnsAreCandidateOnly() {
    AnalysisResult r =
        scan(
            SDK
                + "def get(flag):\n"
                + "    if flag:\n"
                + "        return 'fixed'\n"
                + "    reply=port.chat.completions.create(model='x',messages=[])\n"
                + "    return reply.choices[0].message.content\n"
                + "journal.info(get(True))\n");
    assertTrue(r.aiDetected);
    assertFalse(has(r, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void mutableClientFieldCannotProveRuntimeImplementation() {
    AnalysisResult r =
        scan(
            "from openai import OpenAI\n"
                + "import logging\n"
                + "class Service:\n"
                + "    def __init__(self):\n"
                + "        self.port=OpenAI()\n"
                + "    def swap(self,x):\n"
                + "        self.port=x\n"
                + "    def answer(self):\n"
                + "        r=self.port.chat.completions.create()\n"
                + "        logging.info(r.choices[0].message.content)\n");
    assertTrue(r.aiDetected);
    assertFalse(has(r, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void booleanComparisonIsNotRawContent() {
    assertFalse(
        has(
            scan(SDK + RESPONSE + "journal.info(reply.choices[0].message.content == 'yes')\n"),
            "AI-PY-003",
            "VIOLATED"));
  }

  @Test
  public void standardToolCallsRetainArgumentsOriginButDoNotCertifyAuthorization() {
    AnalysisResult r =
        scan(
            SDK
                + RESPONSE
                + "for invocation in reply.choices[0].message.tool_calls:\n"
                + "    payload=invocation.function.arguments\n"
                + "    eval(payload)\n");
    assertTrue(has(r, "AI-PY-007", "VIOLATED"));
    assertTrue(has(r, "AI-PY-007", "UNKNOWN"));
    assertTrue(has(r, "AI-PY-007", "OBSERVED"));
    assertFalse(
        has(
            scan("for call in other.tool_calls:\n    eval(call.function.arguments)\n"),
            "AI-PY-007",
            "VIOLATED"));
  }

  @Test
  public void tokenBudgetArgumentIsObservationOnly() {
    AnalysisResult r =
        scan(SDK + "r=port.chat.completions.create(model='x',messages=[],max_tokens=500)\n");
    assertTrue(has(r, "AI-PY-004", "OBSERVED"));
    assertTrue(has(r, "AI-PY-004", "UNKNOWN"));
  }

  @Test
  public void unicodeStringsNumericSeparatorsAndUnionAnnotationsParse() {
    AnalysisResult r =
        scan(
            "from openai import OpenAI\n"
                + "def connect(value:int|None=None):\n"
                + "    budget=1_000_000\n"
                + "    hexvalue=0x_FF\n"
                + "    rate=1_000.2_3e1_0\n"
                + "    text='中文内容'\n"
                + "    return OpenAI()\n"
                + "p=connect()\n"
                + "p.chat.completions.create()\n");
    assertTrue(r.aiDetected);
    for (Map<String, Object> d : r.diagnostics)
      assertNotEquals("PYTHON_PARSE_FAILED", d.get("code"));
  }

  @Test
  public void localDefinitionsAndLaterLocalAssignmentsShadowSdkImports() {
    assertFalse(
        scan("from openai import OpenAI\n"
                 + "def OpenAI():\n"
                 + "    return fake()\n"
                 + "p=OpenAI()\n"
                 + "p.chat.completions.create()\n")
            .aiDetected);
    assertFalse(
        scan("from openai import OpenAI\n"
                 + "def f():\n"
                 + "    p=OpenAI()\n"
                 + "    OpenAI=fake\n"
                 + "    p.chat.completions.create()\n")
            .aiDetected);
  }

  @Test
  public void booleanAndLiteralSelectionDoNotLeakContainerOrigin() {
    AnalysisResult r =
        scan(
            SDK
                + RESPONSE
                + "body=reply.choices[0].message.content\n"
                + "journal.info(not body)\n"
                + "journal.info(['fixed',body][0])\n");
    assertFalse(has(r, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void customDecoratorLeavesReturnSemanticsUnknown() {
    AnalysisResult r =
        scan(
            SDK
                + RESPONSE
                + "body=reply.choices[0].message.content\n"
                + "def replace(f):\n"
                + "    return lambda: 'fixed'\n"
                + "@replace\n"
                + "def get():\n"
                + "    return body\n"
                + "journal.info(get())\n");
    assertFalse(has(r, "AI-PY-003", "VIOLATED"));
  }

  @Test
  public void discardedDeepSyntaxCannotContributePartialModelEvidence() {
    StringBuilder source = new StringBuilder(SDK + RESPONSE);
    String indent = "";
    for (int i = 0; i < 210; i++) {
      source.append(indent).append("if True:\n");
      indent += " ";
    }
    source.append(indent).append("pass\n");
    AnalysisResult r = scan(source.toString());
    assertFalse(r.aiDetected);
    boolean limit = false;
    for (Map<String, Object> d : r.diagnostics)
      if (d.get("code").toString().matches("PYTHON_(ANALYSIS_LIMIT|PARSE_DEPTH)")) limit = true;
    assertTrue(limit);
  }

  @Test
  public void literalContainerDoesNotBecomeExecutableString() {
    assertFalse(
        has(
            scan(SDK + RESPONSE + "eval([reply.choices[0].message.content])\n"),
            "AI-PY-007",
            "VIOLATED"));
  }
}
