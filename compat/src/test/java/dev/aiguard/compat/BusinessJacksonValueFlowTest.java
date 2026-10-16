package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Jackson summaries depend on a default mapper and tree origin, never a JsonNode type alone. */
public class BusinessJacksonValueFlowTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };
  private static final String IMPORTS =
      "import port.Api;import com.fasterxml.jackson.databind.ObjectMapper;import"
          + " com.fasterxml.jackson.databind.JsonNode;";
  private static final String MAPPER = "private final ObjectMapper mapper=new ObjectMapper();";

  private BusinessPolicy policy() throws Exception {
    return BusinessPolicy.parse(
        "bank-common",
        "{\"version\":2,\"contracts\":[{\"symbol\":\"port.Api#make\",\"arity\":0,\"kind\":\"source\",\"label\":\"model-output\"},{\"symbol\":\"port.Api#check\",\"arity\":1,\"kind\":\"check\",\"control\":\"guard\",\"args\":[0],\"accept\":true,\"failureMode\":\"closed\"},{\"symbol\":\"port.Api#release\",\"arity\":1,\"kind\":\"sink\",\"channel\":\"release\",\"args\":[0]}]}");
  }

  private BusinessFlow.Program program(String code, SourceFile... more) throws Exception {
    List<SourceFile> files = new ArrayList<SourceFile>();
    files.add(new SourceFile("Example.java", IMPORTS + code));
    files.addAll(Arrays.asList(more));
    return BusinessJavaAnalysis.adapt(files, NONE, policy());
  }

  private String status(String body) throws Exception {
    BusinessAnalysis result =
        BusinessAnalysis.analyze(
            program("class Demo{" + MAPPER + "void run() throws Exception{" + body + "}}"),
            policy(),
            NONE);
    for (Map<String, Object> item : result.assessments)
      if (BusinessPolicy.GUARD.equals(item.get("ruleId")))
        return String.valueOf(item.get("disposition"));
    throw new AssertionError("guard assessment missing");
  }

  private List<BusinessFlow.Expr> expressions(BusinessFlow.Program program) {
    List<BusinessFlow.Expr> found = new ArrayList<BusinessFlow.Expr>();
    for (BusinessFlow.Function function : program.functions)
      for (BusinessFlow.Stmt statement : function.body) collect(statement, found);
    return found;
  }

  private void collect(BusinessFlow.Stmt statement, List<BusinessFlow.Expr> found) {
    collect(statement.expr, found);
    for (List<BusinessFlow.Stmt> list :
        Arrays.asList(statement.body, statement.otherwise, statement.finalizer))
      for (BusinessFlow.Stmt child : list) collect(child, found);
    for (List<BusinessFlow.Stmt> list : statement.handlers)
      for (BusinessFlow.Stmt child : list) collect(child, found);
  }

  private void collect(BusinessFlow.Expr expression, List<BusinessFlow.Expr> found) {
    if (expression == null) return;
    found.add(expression);
    collect(expression.receiver, found);
    for (BusinessFlow.Expr arg : expression.args) collect(arg, found);
  }

  private int count(BusinessFlow.Program program, String kind) {
    int count = 0;
    for (BusinessFlow.Expr expression : expressions(program))
      if (expression.kind.equals(kind)) count++;
    return count;
  }

  @Test
  public void defaultPrivateMapperAndTreeOriginProduceDistinctJacksonIr() throws Exception {
    BusinessFlow.Program program =
        program(
            "class Demo{"
                + MAPPER
                + "void run(String raw)throws Exception{JsonNode"
                + " n=mapper.readTree(raw);if(n.has(\"payload\")){String"
                + " a=n.path(\"payload\").asText();n.get(\"other\").asText(\"fallback\");}}}");
    assertEquals(1, count(program, "JACKSON_PARSE"));
    assertEquals(1, count(program, "JACKSON_HAS"));
    assertEquals(1, count(program, "JACKSON_PATH"));
    assertEquals(1, count(program, "JACKSON_GET"));
    assertEquals(2, count(program, "JACKSON_TEXT"));
  }

  @Test
  public void exactLocalMapperWorksButAliasesAndConfigurationDoNot() throws Exception {
    String local =
        "class Demo{void run(String raw)throws Exception{ObjectMapper mapper=new ObjectMapper();%s"
            + " JsonNode n=mapper.readTree(raw);n.path(\"payload\").asText();}}";
    assertEquals(1, count(program(String.format(local, "")), "JACKSON_PARSE"));
    for (String action :
        Arrays.asList(
            "mapper.findAndRegisterModules();",
            "ObjectMapper alias=mapper;",
            "external(mapper);",
            "mapper=external();"))
      assertEquals(0, count(program(String.format(local, action)), "JACKSON_PARSE"));
  }

  @Test
  public void mapperParametersAndMutableOrInjectedFieldsStayUnknown() throws Exception {
    for (String field :
        Arrays.asList(
            "ObjectMapper mapper;",
            "private final ObjectMapper mapper=external();",
            "private ObjectMapper mapper=new ObjectMapper();",
            "public final ObjectMapper mapper=new ObjectMapper();"))
      assertEquals(
          0,
          count(
              program(
                  "class Demo{"
                      + field
                      + "void run(String raw)throws Exception{JsonNode"
                      + " n=mapper.readTree(raw);n.path(\"payload\");}}"),
              "JACKSON_PARSE"));
    assertEquals(
        0,
        count(
            program(
                "class Demo{void run(ObjectMapper mapper,String raw)throws Exception{JsonNode"
                    + " n=mapper.readTree(raw);n.path(\"payload\");}}"),
            "JACKSON_PARSE"));
  }

  @Test
  public void declaredJsonNodeAndReassignedTreesDoNotEstablishOrigin() throws Exception {
    assertEquals(
        0,
        count(
            program(
                "class Demo{void run(JsonNode"
                    + " n){n.path(\"payload\").asText();n.has(\"payload\");}}"),
            "JACKSON_PATH"));
    assertEquals(
        0,
        count(
            program(
                "class Demo{"
                    + MAPPER
                    + "void run(String raw,JsonNode other)throws Exception{JsonNode"
                    + " n=mapper.readTree(raw);n=other;n.path(\"payload\").asText();}}"),
            "JACKSON_PATH"));
  }

  @Test
  public void checkedConvertedFieldMayBeReleased() throws Exception {
    assertEquals(
        "OBSERVED",
        status(
            "String raw=Api.make();JsonNode n=mapper.readTree(raw);String"
                + " text=n.path(\"payload\").asText();if(Api.check(text))Api.release(text);"));
  }

  @Test
  public void checkingRawOrAnotherFieldCannotApproveConvertedOutput() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "String raw=Api.make();JsonNode n=mapper.readTree(raw);String"
                + " text=n.path(\"payload\").asText();if(Api.check(raw))Api.release(text);"));
    assertNotEquals(
        "OBSERVED",
        status(
            "String raw=Api.make();JsonNode n=mapper.readTree(raw);String"
                + " a=n.path(\"payload\").asText();String"
                + " b=n.path(\"other\").asText();if(Api.check(a))Api.release(b);"));
  }

  @Test
  public void hasFieldIsPresenceEvidenceAndNeverGuardApproval() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "String raw=Api.make();JsonNode"
                + " n=mapper.readTree(raw);if(n.has(\"payload\"))Api.release(n.path(\"payload\").asText());"));
  }

  @Test
  public void parsingAndMissingGetPreserveExceptionPaths() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "String raw=Api.make();String"
                + " other=Api.make();if(Api.check(raw)){try{mapper.readTree(raw).get(\"payload\").asText();}catch(Exception"
                + " e){Api.release(other);}Api.release(raw);}"));
  }

  @Test
  public void unknownMutationCannotPreserveTreeMemberApproval() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "String raw=Api.make();JsonNode n=mapper.readTree(raw);JsonNode"
                + " part=n.path(\"payload\");if(Api.check(part)){n.mutate();Api.release(n.path(\"payload\"));}"));
  }

  @Test
  public void sourceShadowAndAnonymousMappersCannotReceiveBuiltinSemantics() throws Exception {
    String code =
        "class Demo{" + MAPPER + "void run(String raw)throws Exception{mapper.readTree(raw);}}";
    assertEquals(
        0,
        count(
            program(
                code,
                new SourceFile(
                    "ObjectMapper.java",
                    "package com.fasterxml.jackson.databind;public class ObjectMapper{}")),
            "JACKSON_PARSE"));
    assertEquals(
        0,
        count(
            program(
                "class Demo{void run(String raw)throws Exception{ObjectMapper mapper=new"
                    + " ObjectMapper(){};mapper.readTree(raw);}}"),
            "JACKSON_PARSE"));
  }

  @Test
  public void explicitReadTreeContractPrecedesLibrarySummary() throws Exception {
    BusinessPolicy explicit =
        BusinessPolicy.parse(
            "bank-common",
            "{\"version\":2,\"contracts\":[{\"symbol\":\"com.fasterxml.jackson.databind.ObjectMapper#readTree\",\"arity\":1,\"kind\":\"source\",\"label\":\"model-output\"}]}");
    BusinessFlow.Program program =
        BusinessJavaAnalysis.adapt(
            Arrays.asList(
                new SourceFile(
                    "Example.java",
                    IMPORTS
                        + "class Demo{"
                        + MAPPER
                        + "void run(String raw)throws Exception{JsonNode"
                        + " n=mapper.readTree(raw);n.path(\"payload\").asText();}}")),
            NONE,
            explicit);
    assertEquals(0, count(program, "JACKSON_PARSE"));
    assertEquals(0, count(program, "JACKSON_PATH"));
  }

  @Test
  public void numericNodeTextCannotBorrowTheScannerDecimalRepresentation() throws Exception {
    // Jackson's default DoubleNode emits "1.0" / "0.1", whereas the scanner's bounded JSON
    // parser uses BigDecimal and retains a different representation. These are distinct values.
    assertNotEquals(
        "OBSERVED",
        status(
            "JsonNode"
                + " n=mapper.readTree(\"{\\\"x\\\":1e0}\");if(Api.check(\"1\"))Api.release(n.path(\"x\").asText());"));
    assertNotEquals(
        "OBSERVED",
        status(
            "JsonNode"
                + " n=mapper.readTree(\"{\\\"x\\\":0.10}\");if(Api.check(\"0.10\"))Api.release(n.path(\"x\").asText());"));
    assertNotEquals(
        "OBSERVED",
        status(
            "JsonNode"
                + " n=mapper.readTree(\"{\\\"x\\\":-0.0}\");if(Api.check(\"0.0\"))Api.release(n.path(\"x\").asText());"));
  }

  @Test
  public void jacksonObjectShapeDoesNotMakeAnUnrelatedJavaCastSafe() throws Exception {
    assertNotEquals(
        "OBSERVED",
        status(
            "JsonNode n=mapper.readTree(\"{\\\"payload\\\":\\\"x\\\"}\");Object"
                + " raw=Api.make(),other=Api.make();if(Api.check(raw)){try{((java.util.Map)n).get(\"payload\");}catch(Exception"
                + " e){Api.release(other);}Api.release(raw);}"));
    assertNotEquals(
        "OBSERVED",
        status(
            "JsonNode n=mapper.readTree(\"{\\\"payload\\\":\\\"x\\\"}\");Object"
                + " raw=Api.make(),other=Api.make();if(Api.check(raw)){try{((java.util.Map)(Object)n).get(\"payload\");}catch(Exception"
                + " e){Api.release(other);}Api.release(raw);}"));
  }
}
