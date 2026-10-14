package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.CancellationException;
import org.junit.Test;

/** The target snippets deliberately include modern Java syntax; this test itself is Java 7. */
public class JavaAnalysisTest {
  static final Cancel RUN =
      new Cancel() {
        public void check() {}
      };
  static final String POM =
      "<project><properties><spring-ai.version>1.1.0</spring-ai.version></properties><dependencyManagement><dependencies><dependency><groupId>org.springframework.ai</groupId><artifactId>spring-ai-bom</artifactId><version>${spring-ai.version}</version></dependency></dependencies></dependencyManagement></project>";
  static final String HEADER =
      "import org.springframework.ai.chat.client.ChatClient; import"
          + " org.springframework.ai.chat.model.ChatModel; import"
          + " org.springframework.ai.tool.annotation.Tool; import"
          + " org.springframework.web.bind.annotation.PostMapping; import"
          + " org.springframework.ai.chat.client.advisor.SafeGuardAdvisor; import"
          + " org.springframework.ai.chat.client.advisor.MessageChatMemoryAdvisor; import"
          + " org.springframework.ai.chat.client.advisor.QuestionAnswerAdvisor; import"
          + " org.springframework.ai.chat.memory.ChatMemory; import"
          + " org.springframework.security.access.prepost.PreAuthorize; import org.slf4j.Logger;"
          + " import org.slf4j.MDC; import org.springframework.jdbc.core.JdbcTemplate; import"
          + " org.springframework.web.servlet.mvc.method.annotation.SseEmitter; import"
          + " org.springframework.ai.moderation.ModerationModel; import"
          + " org.springframework.ai.moderation.ModerationPrompt; import java.util.List; class App"
          + " { ChatClient chat; ChatModel model; Logger logger; JdbcTemplate jdbc; SseEmitter"
          + " emitter; ModerationModel moderation; Object memory,store; ";
  static final String HTTP =
      "import okhttp3.*; import com.fasterxml.jackson.databind.*; import java.util.*; import"
          + " org.slf4j.Logger; final class Transport { OkHttpClient wire; ObjectMapper mapper;"
          + " JsonNode exchange(String q)throws Exception { Request request=new"
          + " Request.Builder().url(\"https://example.invalid/v1/chat/completions\").post(RequestBody.create(q,MediaType.parse(\"application/json\"))).build();"
          + " try(Response response=wire.newCall(request).execute()){return"
          + " mapper.readTree(response.body().string());}} } ";

  static String web(String body) {
    return "@PostMapping String ask(String prompt)throws Exception {" + body + "}";
  }

  static AnalysisResult scan(String code) {
    return JavaAnalysis.analyze(
        Arrays.asList(new SourceFile("pom.xml", POM), new SourceFile("src/App.java", code)), RUN);
  }

  static boolean has(AnalysisResult result, String id, String disposition) {
    for (Map<String, Object> item : result.assessments)
      if (id.equals(item.get("ruleId")) && disposition.equals(item.get("disposition"))) return true;
    return false;
  }

  static void require(String id, String body) {
    AnalysisResult result = scan(HEADER + body + "}");
    assertTrue(id + " " + result.assessments, has(result, id, "VIOLATED"));
    assertFalse(result.assessments.toString().contains("secret-canary"));
  }

  static void deny(String id, String body) {
    AnalysisResult result = scan(HEADER + body + "}");
    assertFalse(id + " " + result.assessments, has(result, id, "VIOLATED"));
  }

  @Test
  public void systemInputAndImmutableAlias() {
    require(
        "AI-L1-001",
        web(
            "String value=prompt;return"
                + " chat.prompt().system(\"secret-canary\"+value).call().content();"));
  }

  @Test
  public void fixedSystemAndCustomTransformation() {
    deny("AI-L1-001", web("return chat.prompt().system(\"fixed\").user(prompt).call().content();"));
    deny("AI-L1-001", web("return chat.prompt().system(clean(prompt)).call().content();"));
  }

  @Test
  public void directToolAndParameterizedSql() {
    require(
        "AI-L2-001", "@Tool void run(String cmd)throws Exception{Runtime.getRuntime().exec(cmd);}");
    deny(
        "AI-L2-001",
        "@Tool void run(String data){jdbc.update(\"insert into t values (?)\",data);}");
  }

  @Test
  public void modelOutputExecutionAndReassignment() {
    require(
        "AI-L7-001",
        web(
            "String value=chat.prompt().call().content();Runtime.getRuntime().exec(value);return"
                + " value;"));
    deny(
        "AI-L7-001",
        web(
            "String"
                + " value=chat.prompt().call().content();value=\"fixed\";Runtime.getRuntime().exec(value);return"
                + " value;"));
  }

  @Test
  public void processExecutableShellAndData() {
    require(
        "AI-L7-001",
        web(
            "String value=chat.prompt().call().content();new"
                + " ProcessBuilder(\"/bin/sh\",\"-c\",value).start();return value;"));
    require(
        "AI-L7-001",
        web(
            "String value=chat.prompt().call().content();new"
                + " ProcessBuilder(value,\"-c\",\"fixed\").start();return value;"));
    deny(
        "AI-L7-001",
        web(
            "String value=chat.prompt().call().content();new"
                + " ProcessBuilder(\"grep\",\"-c\",value).start();return value;"));
  }

  @Test
  public void explicitRawClientFallback() {
    require(
        "AI-L1-002",
        web(
            "ChatClient local=ChatClient.builder(model).build();try{return"
                + " local.prompt().advisors(new"
                + " SafeGuardAdvisor(List.of(\"blocked\"))).user(prompt).call().content();}catch(Exception"
                + " e){return local.prompt().user(prompt).call().content();}"));
  }

  @Test
  public void injectedDefaultAdvisorsRemainUnknown() {
    deny(
        "AI-L1-002",
        web(
            "try{return chat.prompt().advisors(new"
                + " SafeGuardAdvisor(List.of(\"blocked\"))).user(prompt).call().content();}catch(Exception"
                + " e){return chat.prompt().user(prompt).call().content();}"));
  }

  @Test
  public void memoryBindingAndUnboundParameter() {
    require(
        "AI-L2-002",
        web(
            "return"
                + " chat.prompt().advisors(MessageChatMemoryAdvisor.builder(memory).build()).advisors(a->a.param(ChatMemory.CONVERSATION_ID,\"shared\")).call().content();"));
    deny(
        "AI-L2-002",
        web(
            "return"
                + " chat.prompt().advisors(a->a.param(ChatMemory.CONVERSATION_ID,\"shared\")).call().content();"));
  }

  @Test
  public void ragBindingAndUnboundParameter() {
    require(
        "AI-L2-003",
        web(
            "return chat.prompt().advisors(new"
                + " QuestionAnswerAdvisor(store)).advisors(a->a.param(QuestionAnswerAdvisor.FILTER_EXPRESSION,prompt)).call().content();"));
    deny(
        "AI-L2-003",
        web(
            "return"
                + " chat.prompt().advisors(a->a.param(QuestionAnswerAdvisor.FILTER_EXPRESSION,prompt)).call().content();"));
  }

  @Test
  public void rawModelAndPromptLogging() {
    require(
        "AI-L3-001",
        web(
            "String result=chat.prompt().user(prompt).call().content();logger.info(result);return"
                + " result;"));
    require(
        "AI-L3-001",
        web("logger.info(prompt);return chat.prompt().user(prompt).call().content();"));
    deny(
        "AI-L3-001",
        web(
            "String result=chat.prompt().call().content();logger.info(mask(result));return"
                + " result;"));
  }

  @Test
  public void retries() {
    require(
        "AI-L4-001", web("chat.prompt().stream().content().retry().subscribe();return \"ok\";"));
    deny("AI-L4-001", web("chat.prompt().stream().content().retry(3).subscribe();return \"ok\";"));
  }

  @Test
  public void auditCorrelation() {
    require(
        "AI-L6-001",
        web("MDC.put(\"traceId\",\"fixed\");return chat.prompt().user(prompt).call().content();"));
    deny(
        "AI-L6-001",
        web("MDC.put(\"traceId\",nextId());return chat.prompt().user(prompt).call().content();"));
  }

  @Test
  public void moderationOrder() {
    require(
        "AI-L5-001",
        web(
            "chat.prompt().stream().content().doOnNext(chunk->{emitter.send(chunk);moderation.call(new"
                + " ModerationPrompt(chunk));});return \"ok\";"));
    deny(
        "AI-L5-001",
        web(
            "chat.prompt().stream().content().doOnNext(chunk->{moderation.call(new"
                + " ModerationPrompt(chunk));emitter.send(chunk);});return \"ok\";"));
  }

  @Test
  public void conditionalAndDifferentPayloadModeration() {
    deny(
        "AI-L5-001",
        web(
            "String"
                + " other=chat.prompt().call().content();chat.prompt().stream().content().doOnNext(chunk->{emitter.send(chunk);moderation.call(new"
                + " ModerationPrompt(other));});return \"ok\";"));
    deny(
        "AI-L5-001",
        web(
            "chat.prompt().stream().content().doOnNext(chunk->{if(flag)emitter.send(chunk);moderation.call(new"
                + " ModerationPrompt(chunk));});return \"ok\";"));
  }

  @Test
  public void unknownVersionAndSiblingCannotBorrow() {
    List<SourceFile> input =
        Arrays.asList(
            new SourceFile("other/pom.xml", POM),
            new SourceFile(
                "src/App.java",
                HEADER + web("return chat.prompt().system(prompt).call().content();") + "}"));
    assertFalse(has(JavaAnalysis.analyze(input, RUN), "AI-L1-001", "VIOLATED"));
    assertTrue(has(JavaAnalysis.analyze(input, RUN), "AI-L1-001", "UNKNOWN"));
  }

  @Test
  public void shadowTypesCannotBorrowImport() {
    deny(
        "AI-L1-001",
        "class ChatClient {} " + web("return chat.prompt().system(prompt).call().content();"));
    deny(
        "AI-L7-001",
        "class Runtime {static Runtime getRuntime(){return null;}void exec(String s){}} "
            + web(
                "String text=chat.prompt().call().content();Runtime.getRuntime().exec(text);return"
                    + " text;"));
  }

  @Test
  public void nonAiLookalikes() {
    AnalysisResult result =
        JavaAnalysis.analyze(
            Arrays.asList(
                new SourceFile(
                    "Fake.java",
                    "class Fake { FakeClient chat; Object run(String q){return"
                        + " chat.prompt().system(q).stream().content().retry();}}")),
            RUN);
    assertFalse(result.aiDetected);
    for (Map<String, Object> a : result.assessments)
      assertEquals("NOT_APPLICABLE", a.get("disposition"));
  }

  @Test
  public void configTrueFalseAndUnknown() {
    for (String value : Arrays.asList("true", "false", "${VALUE}")) {
      AnalysisResult result =
          JavaAnalysis.analyze(
              Arrays.asList(
                  new SourceFile("pom.xml", POM),
                  new SourceFile(
                      "application.properties", "spring.ai.chat.observations.log-prompt=" + value)),
              RUN);
      assertTrue(
          has(
              result,
              "AI-L3-002",
              value.equals("true") ? "VIOLATED" : value.equals("false") ? "OBSERVED" : "UNKNOWN"));
    }
  }

  @Test
  public void yamlProfileDuplicateAliasAndTagUnknown() {
    for (String config :
        Arrays.asList(
            "spring.ai.chat.observations.log-prompt: true\n"
                + "spring.ai.chat.observations.log-prompt: false",
            "a: &a true\nspring.ai.chat.observations.log-prompt: *a",
            "spring.ai.chat.observations.log-prompt: !!bool true",
            "spring:\n"
                + "  config:\n"
                + "    activate:\n"
                + "      on-profile: prod\n"
                + "  ai:\n"
                + "    chat:\n"
                + "      observations:\n"
                + "        log-prompt: true")) {
      AnalysisResult result =
          JavaAnalysis.analyze(
              Arrays.asList(
                  new SourceFile("pom.xml", POM), new SourceFile("application.yaml", config)),
              RUN);
      assertFalse(has(result, "AI-L3-002", "VIOLATED"));
      assertTrue(has(result, "AI-L3-002", "UNKNOWN"));
    }
  }

  @Test
  public void configYamlLiteral() {
    AnalysisResult result =
        JavaAnalysis.analyze(
            Arrays.asList(
                new SourceFile("pom.xml", POM),
                new SourceFile(
                    "application.yaml",
                    "spring:\n  ai:\n    chat:\n      observations:\n        log-prompt: true")),
            RUN);
    assertTrue(result.assessments.toString(), has(result, "AI-L3-002", "VIOLATED"));
  }

  @Test
  public void parserFailureRemainsUnknown() {
    AnalysisResult result = scan("class Broken { String x = ; }");
    assertFalse(result.diagnostics.isEmpty());
    assertTrue(has(result, "AI-L1-001", "UNKNOWN"));
  }

  @Test(expected = CancellationException.class)
  public void cancellation() {
    JavaAnalysis.analyze(
        Arrays.asList(new SourceFile("App.java", "class App{}")),
        new Cancel() {
          public void check() {
            throw new CancellationException();
          }
        });
  }

  @Test
  public void functionCallingDispatchAndDirectExecution() {
    String code =
        HTTP
            + "final class Service { Transport t; String run()throws Exception { JsonNode"
            + " result=t.exchange(\"q\"); return"
            + " invoke(result.path(\"name\").asText(),result.path(\"arguments\")); } String"
            + " invoke(String operation,JsonNode data)throws Exception { switch(operation){case"
            + " \"fixed\":return \"ok\";default:return null;} } }";
    AnalysisResult result = scan(code);
    assertTrue(result.assessments.toString(), has(result, "AI-FC-001", "OBSERVED"));
    assertTrue(has(result, "AI-FC-002", "UNKNOWN"));
    assertFalse(has(result, "AI-FC-001", "VIOLATED"));
    result =
        scan(
            code.replace(
                "switch(operation){case \"fixed\":return \"ok\";default:return null;}",
                "Runtime.getRuntime().exec(operation);return null;"));
    assertTrue(result.assessments.toString(), has(result, "AI-FC-001", "VIOLATED"));
  }

  @Test
  public void ordinaryJsonPairIsNotFunctionCalling() {
    AnalysisResult result =
        scan(
            "import com.fasterxml.jackson.databind.*; class Service {String run(JsonNode"
                + " value){return invoke(value.path(\"name\").asText(),value.path(\"arguments\"));}"
                + " String invoke(String n,JsonNode a){return n;} }");
    assertFalse(has(result, "AI-FC-001", "OBSERVED"));
    assertFalse(has(result, "AI-FC-001", "VIOLATED"));
  }

  @Test
  public void customGatewayLoggingAndGuard() {
    String code =
        HTTP
            + "final class Service{Transport t;Logger log;boolean check(String v){return"
            + " v.isEmpty();}String run()throws Exception{String"
            + " text=t.exchange(\"q\").asText();log.info(text);if(check(text))return null;return"
            + " text;}}";
    AnalysisResult result = scan(code);
    assertTrue(result.assessments.toString(), has(result, "AI-GW-001", "OBSERVED"));
    assertTrue(has(result, "AI-GW-002", "VIOLATED"));
    assertTrue(has(result, "AI-GUARD-002", "OBSERVED"));
    assertTrue(has(result, "AI-GUARD-002", "UNKNOWN"));
  }

  static final String DECISIONS =
      "final class DecisionLogic { record Result(boolean permitted){} static final class"
          + " Outcome{boolean value; Outcome(boolean value){this.value=value;}boolean"
          + " accepted(){return this.value;}void replace(boolean next){value=next;}} Result"
          + " check(String value){return new Result(!value.isEmpty());} Outcome checkPojo(String"
          + " value){return new Outcome(!value.isEmpty());} boolean accept(String value){return"
          + " !value.isEmpty();} boolean unrelated(){return true;} } ";

  static AnalysisResult custom(String body) {
    return scan(
        HTTP
            + DECISIONS
            + "final class Service {Transport"
            + " t;org.springframework.web.servlet.mvc.method.annotation.SseEmitter emitter;boolean"
            + " flag;boolean overwrite(DecisionLogic.Outcome value){value.replace(true);return"
            + " true;}void run(String input)throws Exception{String"
            + " answer=t.exchange(input).asText();"
            + body
            + "}}");
  }

  @Test
  public void customRecordAndPojoDecisions() {
    for (String snippet :
        Arrays.asList(
            "DecisionLogic.Result verdict=new"
                + " DecisionLogic().check(answer);if(!verdict.permitted())return;emitter.send(answer);",
            "DecisionLogic.Outcome verdict=new"
                + " DecisionLogic().checkPojo(answer);if(!verdict.accepted())return;emitter.send(answer);")) {
      AnalysisResult result = custom(snippet);
      assertTrue(result.assessments.toString(), has(result, "AI-GUARD-002", "OBSERVED"));
      assertTrue(has(result, "AI-GUARD-003", "OBSERVED"));
      assertFalse(has(result, "AI-GUARD-003", "VIOLATED"));
    }
  }

  @Test
  public void customDecisionReassignmentAndObjectMutationUnknown() {
    for (String snippet :
        Arrays.asList(
            "DecisionLogic.Outcome verdict=new"
                + " DecisionLogic().checkPojo(answer);verdict.replace(true);if(!verdict.accepted())return;emitter.send(answer);",
            "DecisionLogic.Outcome verdict=new"
                + " DecisionLogic().checkPojo(answer);if(overwrite(verdict)&&!verdict.accepted())return;emitter.send(answer);",
            "boolean verdict=new"
                + " DecisionLogic().accept(answer);if(verdict=true)return;emitter.send(answer);")) {
      AnalysisResult result = custom(snippet);
      assertFalse(result.assessments.toString(), has(result, "AI-GUARD-002", "OBSERVED"));
      assertTrue(has(result, "AI-GUARD-002", "UNKNOWN"));
      assertFalse(has(result, "AI-GUARD-003", "OBSERVED"));
    }
  }

  @Test
  public void lateCustomCheckRemainsObservationAndNoBraceDoesNotOrder() {
    AnalysisResult result =
        custom("emitter.send(answer);if(!new DecisionLogic().accept(answer))return;");
    assertTrue(has(result, "AI-GUARD-003", "OBSERVED"));
    assertFalse(has(result, "AI-GUARD-003", "VIOLATED"));
    result = custom("if(flag)emitter.send(answer);if(!new DecisionLogic().accept(answer))return;");
    assertFalse(result.assessments.toString(), has(result, "AI-GUARD-003", "OBSERVED"));
  }

  @Test
  public void customInputCorrelationIsRequired() {
    String header =
        HTTP
            + DECISIONS
            + "final class Service{Transport t;void run(String input,String unrelated)throws"
            + " Exception{";
    AnalysisResult yes =
        scan(header + "if(!new DecisionLogic().accept(input))return;t.exchange(input);}}");
    assertTrue(yes.assessments.toString(), has(yes, "AI-GUARD-001", "OBSERVED"));
    AnalysisResult no =
        scan(header + "if(!new DecisionLogic().accept(unrelated))return;t.exchange(input);}}");
    assertFalse(has(no, "AI-GUARD-001", "OBSERVED"));
  }

  @Test
  public void functionCallingRecordAdapter() {
    String code =
        HTTP
            + "final class Service{Transport t;ObjectMapper mapper;record Choice(String"
            + " option,JsonNode data){}Choice parse(String payload)throws Exception{JsonNode"
            + " root=mapper.readTree(payload);return new"
            + " Choice(root.path(\"tool\").asText(),root.path(\"args\"));}String run(String"
            + " input)throws Exception{Choice selected=parse(t.exchange(input).asText());return"
            + " dispatch(selected.option(),selected.data(),input);}String dispatch(String"
            + " name,JsonNode args,String context){return name;}}";
    AnalysisResult result = scan(code);
    assertTrue(result.assessments.toString(), has(result, "AI-FC-001", "OBSERVED"));
    assertTrue(has(result, "AI-FC-003", "OBSERVED"));
  }

  @Test
  public void functionCallingMapSchemaAndShellData() {
    String code =
        HTTP
            + "final class Service{Transport t;Map<String,Object> registry;ObjectMapper"
            + " mapper;javax.validation.Validator validator;String run(String input)throws"
            + " Exception{JsonNode root=t.exchange(input);return"
            + " dispatch(root.path(\"name\").asText(),root.path(\"arguments\"));}String"
            + " dispatch(String name,JsonNode args)throws"
            + " Exception{if(!registry.containsKey(name))return null;Object"
            + " selected=registry.get(name);Object"
            + " parsed=mapper.readTree(args.asText());validator.validate(parsed);new"
            + " ProcessBuilder(\"grep\",\"-c\",args.asText()).start();return null;}}";
    AnalysisResult result = scan(code);
    assertTrue(result.assessments.toString(), has(result, "AI-FC-001", "OBSERVED"));
    assertTrue(has(result, "AI-FC-002", "OBSERVED"));
    assertFalse(has(result, "AI-FC-001", "VIOLATED"));
  }

  @Test
  public void candidateFunctionDispatchCannotUpgrade() {
    String code =
        HTTP
            + "interface Handler{String apply(String n,JsonNode a)throws Exception;}final class"
            + " Implementation implements Handler{public String apply(String n,JsonNode a)throws"
            + " Exception{Runtime.getRuntime().exec(n);return null;}}final class Service{Transport"
            + " t;Handler target;String run(String input)throws Exception{JsonNode"
            + " root=t.exchange(input);return"
            + " target.apply(root.path(\"name\").asText(),root.path(\"arguments\"));}}";
    AnalysisResult result = scan(code);
    assertTrue(result.assessments.toString(), has(result, "AI-FC-001", "OBSERVED"));
    assertFalse(has(result, "AI-FC-001", "VIOLATED"));
  }

  @Test
  public void versionBomAndGradleScope() {
    String unmanaged =
        "<project><dependencies><dependency><groupId>org.springframework.ai</groupId><artifactId>spring-ai-a</artifactId><version>1.1.0</version></dependency><dependency><groupId>org.springframework.ai</groupId><artifactId>spring-ai-b</artifactId></dependency></dependencies></project>";
    LegacyConfiguration no =
        new LegacyConfiguration(Arrays.asList(new SourceFile("pom.xml", unmanaged)), RUN);
    assertFalse(no.supported("src/App.java"));
    String gradle =
        "val aiVersion = \"1.1.0\"\n"
            + "dependencies {"
            + " implementation(platform(\"org.springframework.ai:spring-ai-bom:$aiVersion\"));implementation(\"org.springframework.ai:spring-ai-a\")"
            + " }";
    LegacyConfiguration yes =
        new LegacyConfiguration(Arrays.asList(new SourceFile("build.gradle.kts", gradle)), RUN);
    assertTrue(yes.version + " " + yes.status, yes.supported("src/App.java"));
  }

  @Test
  public void parentPomCoordinatesAndProperties() {
    String parent =
        "<project><groupId>x</groupId><artifactId>parent</artifactId><version>1</version><properties><aiVersion>1.1.0</aiVersion></properties><dependencyManagement><dependencies><dependency><groupId>org.springframework.ai</groupId><artifactId>spring-ai-bom</artifactId><version>${aiVersion}</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></project>";
    String child =
        "<project><parent><groupId>x</groupId><artifactId>parent</artifactId><version>1</version></parent><dependencies><dependency><groupId>org.springframework.ai</groupId><artifactId>spring-ai-a</artifactId></dependency></dependencies></project>";
    LegacyConfiguration yes =
        new LegacyConfiguration(
            Arrays.asList(new SourceFile("pom.xml", parent), new SourceFile("app/pom.xml", child)),
            RUN);
    assertTrue(yes.supported("app/src/App.java"));
    LegacyConfiguration no =
        new LegacyConfiguration(
            Arrays.asList(
                new SourceFile("pom.xml", parent),
                new SourceFile(
                    "app/pom.xml",
                    child.replace("<groupId>x</groupId>", "<groupId>elsewhere</groupId>"))),
            RUN);
    assertFalse(no.supported("app/src/App.java"));
  }

  @Test
  public void mappedStreamAndOpaqueLambdaPayloadUnknown() {
    AnalysisResult result =
        scan(
            HEADER
                + web(
                    "chat.prompt().stream().content().map(v->mask(v)).doOnNext(chunk->{emitter.send(chunk);moderation.call(new"
                        + " ModerationPrompt(chunk));});return \"ok\";")
                + "}");
    assertFalse(has(result, "AI-L5-001", "VIOLATED"));
    assertTrue(has(result, "AI-L5-001", "UNKNOWN"));
  }

  @Test
  public void lambdaAndCatchParametersAreNotWebOrToolInputs() {
    AnalysisResult result =
        scan(
            HEADER
                + "@Tool void run(String input)throws"
                + " Exception{List.of(\"fixed\").forEach(item->Runtime.getRuntime().exec(item));}"
                + web(
                    "List.of(\"fixed\").forEach(item->chat.prompt().system(item).call().content());try{return"
                        + " prompt;}catch(Exception error){return"
                        + " chat.prompt().system(error.toString()).call().content();}")
                + "}");
    assertFalse(result.assessments.toString(), has(result, "AI-L2-001", "VIOLATED"));
    assertFalse(has(result, "AI-L1-001", "VIOLATED"));
  }

  @Test
  public void defaultAdvisorFallbackDoesNotProveBypass() {
    AnalysisResult result =
        scan(
            HEADER
                + web(
                    "ChatClient local=ChatClient.builder(model).defaultAdvisors(new"
                        + " SafeGuardAdvisor(List.of(\"blocked\"))).build();try{return"
                        + " local.prompt().advisors(new"
                        + " SafeGuardAdvisor(List.of(\"blocked\"))).call().content();}catch(Exception"
                        + " e){return local.prompt().call().content();}")
                + "}");
    assertFalse(result.assessments.toString(), has(result, "AI-L1-002", "VIOLATED"));
    assertTrue(has(result, "AI-L1-002", "UNKNOWN"));
  }

  @Test
  public void unrelatedAdvisorAndNonWebMemoryKeyRemainUnknown() {
    AnalysisResult result =
        scan(
            HEADER
                + web(
                    "chat.prompt().advisors(new QuestionAnswerAdvisor(store)).call();return"
                        + " chat.prompt().advisors(a->a.param(QuestionAnswerAdvisor.FILTER_EXPRESSION,prompt)).call().content();")
                + "String offline(){return"
                + " chat.prompt().advisors(MessageChatMemoryAdvisor.builder(memory).build()).advisors(a->a.param(ChatMemory.CONVERSATION_ID,\"fixed\")).call().content();}}"
                + " ");
    assertFalse(has(result, "AI-L2-003", "VIOLATED"));
    assertTrue(has(result, "AI-L2-003", "UNKNOWN"));
    assertFalse(has(result, "AI-L2-002", "VIOLATED"));
    assertTrue(has(result, "AI-L2-002", "UNKNOWN"));
  }

  @Test
  public void loggerProcessAndRuntimeShadowing() {
    AnalysisResult result =
        scan(
            HEADER
                + "class Logger{void info(Object text){}}class ProcessBuilder{ProcessBuilder(String"
                + " text){}void start(){}}class Runtime{static Runtime getRuntime(){return"
                + " null;}void exec(String text){}}"
                + web(
                    "String text=chat.prompt().call().content();logger.info(text);new"
                        + " ProcessBuilder(text).start();Runtime.getRuntime().exec(text);return"
                        + " text;")
                + "}");
    assertFalse(result.assessments.toString(), has(result, "AI-L3-001", "VIOLATED"));
    assertFalse(has(result, "AI-L7-001", "VIOLATED"));
  }

  @Test
  public void lombokLoggerRecognizedButLocalShadowNotBorrowed() {
    String header =
        "import org.springframework.ai.chat.client.ChatClient;import"
            + " lombok.extern.slf4j.Slf4j;@Slf4j class App{ChatClient chat;";
    AnalysisResult result =
        scan(header + "void run(){String text=chat.prompt().call().content();log.info(text);}} ");
    assertTrue(result.assessments.toString(), has(result, "AI-L3-001", "VIOLATED"));
    result =
        scan(
            header
                + "void run(Fake log){String"
                + " text=chat.prompt().call().content();log.info(text);}} ");
    assertFalse(has(result, "AI-L3-001", "VIOLATED"));
  }

  @Test
  public void memberBooleanIndependentOfPayloadIsNotGuard() {
    AnalysisResult result =
        scan(
            HTTP
                + "final class Check{boolean accept(String ignored){return true;}}final class"
                + " Service{Transport t;void run(String input)throws Exception{String"
                + " text=t.exchange(input).asText();if(new Check().accept(text))return;}}");
    assertFalse(has(result, "AI-GUARD-002", "OBSERVED"));
    assertTrue(has(result, "AI-GUARD-002", "UNKNOWN"));
  }

  @Test
  public void arbitraryWrapperDoesNotConsumeDecision() {
    AnalysisResult result =
        scan(
            HTTP
                + DECISIONS
                + "final class Service{Transport t;boolean always(boolean ignored){return"
                + " true;}void run(String input)throws Exception{String"
                + " text=t.exchange(input).asText();if(always(new"
                + " DecisionLogic().accept(text)))return;}}");
    assertFalse(result.assessments.toString(), has(result, "AI-GUARD-002", "OBSERVED"));
    assertTrue(has(result, "AI-GUARD-002", "UNKNOWN"));
  }

  @Test
  public void modelMetadataCannotReenterFunctionCallingSource() {
    AnalysisResult result =
        scan(
            HTTP
                + "final class Service{Transport t;void use(Object value){}void run()throws"
                + " Exception{JsonNode"
                + " usage=t.exchange(\"q\").path(\"usage\");Runtime.getRuntime().exec(usage.path(\"name\").asText());use(usage.path(\"arguments\"));}}");
    assertFalse(result.assessments.toString(), has(result, "AI-FC-001", "VIOLATED"));
    assertFalse(has(result, "AI-FC-001", "OBSERVED"));
  }
}
