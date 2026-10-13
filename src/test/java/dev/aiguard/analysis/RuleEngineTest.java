package dev.aiguard.analysis;

import com.github.javaparser.StaticJavaParser;
import dev.aiguard.model.ScanModel.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class RuleEngineTest {
    private static final String HEADER = """
        import org.springframework.ai.chat.client.ChatClient;
        import org.springframework.ai.chat.client.advisor.SafeGuardAdvisor;
        import org.springframework.ai.chat.client.advisor.QuestionAnswerAdvisor;
        import org.springframework.ai.chat.client.advisor.MessageChatMemoryAdvisor;
        import org.springframework.ai.chat.memory.ChatMemory;
        import org.springframework.ai.tool.annotation.Tool;
        import org.springframework.web.bind.annotation.PostMapping;
        import org.springframework.web.bind.annotation.RequestBody;
        import org.springframework.security.access.prepost.PreAuthorize;
        import org.springframework.jdbc.core.JdbcTemplate;
        import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
        import org.springframework.ai.moderation.ModerationModel;
        import org.springframework.ai.moderation.ModerationPrompt;
        import org.slf4j.Logger;
        import org.slf4j.MDC;
        import java.util.List;
        class App {
          ChatClient chat; JdbcTemplate jdbc; Logger logger;
          SseEmitter emitter; ModerationModel moderation; ChatMemory memory; int retries;
        """;
    private static String web(String body) { return "@PostMapping String ask(@RequestBody String prompt) throws Exception { " + body + " }"; }
    private static String stream(String body) { return web("chat.prompt().user(prompt).stream().content().doOnNext(chunk -> { " + body + " }); return \"done\";"); }
    private static SourceProject project(String code, String version, boolean ai) {
        return new SourceProject(Path.of("/fixture"), List.of(new SourceProject.JavaSource("src/App.java", StaticJavaParser.parse(code))), Map.of(),
            new ProjectMetadata(version.equals("SUPPORTED") ? "1.1.6" : "", version, 1, 0, ai), "digest", List.of());
    }
    private static Assessment assess(String id, String members) {
        return new RuleEngine().assess(project(HEADER + members + "}", "SUPPORTED", true), () -> false).stream()
            .filter(a -> a.ruleId().equals(id)).findFirst().orElseThrow();
    }
    static Stream<Arguments> violations() {
        return Stream.of(
            Arguments.of("AI-L1-001", web("String alias = prompt; return chat.prompt().system(\"instruction: \" + alias).call().content();")),
            Arguments.of("AI-L1-002", web("ChatClient client=ChatClient.builder(model).build(); try { return client.prompt().advisors(new SafeGuardAdvisor(List.of(\"blocked\"))).user(prompt).call().content(); } catch (Exception e) { return client.prompt().user(prompt).call().content(); }")),
            Arguments.of("AI-L2-001", "@Tool String run(String command) throws Exception { Runtime.getRuntime().exec(command); return \"ok\"; }"),
            Arguments.of("AI-L2-002", web("return chat.prompt().user(prompt).advisors(MessageChatMemoryAdvisor.builder(memory).build()).advisors(a -> a.param(ChatMemory.CONVERSATION_ID, \"shared\")).call().content();")),
            Arguments.of("AI-L3-001", web("String answer = chat.prompt().user(prompt).call().content(); logger.info(\"answer={}\", answer); return answer;")),
            Arguments.of("AI-L4-001", web("chat.prompt().user(prompt).stream().content().retry().subscribe(); return \"ok\";")),
            Arguments.of("AI-L5-001", stream("emitter.send(chunk); moderation.call(new ModerationPrompt(chunk));")),
            Arguments.of("AI-L6-001", web("MDC.put(\"requestId\", \"shared\"); return chat.prompt().user(prompt).call().content();")),
            Arguments.of("AI-L7-001", web("String answer = chat.prompt().user(prompt).call().content(); String command = answer; Runtime.getRuntime().exec(command); return \"ok\";")),
            Arguments.of("AI-L2-003", web("return chat.prompt().user(\"question\").advisors(new QuestionAnswerAdvisor(store)).advisors(a -> a.param(QuestionAnswerAdvisor.FILTER_EXPRESSION, prompt)).call().content();"))
        );
    }
    @ParameterizedTest @MethodSource("violations")
    void provenViolationHasOnlyFixedEvidence(String id, String members) {
        Assessment result = assess(id, members);
        assertEquals(Disposition.VIOLATED, result.disposition(), id);
        assertFalse(result.evidence().isEmpty());
        assertTrue(result.evidence().stream().allMatch(e -> e.path().equals("src/App.java") && e.line() >= 1));
        assertFalse(result.toString().contains("instruction: "));
        assertFalse(result.toString().contains("answer={}"));
    }
    static Stream<Arguments> nonViolations() {
        return Stream.of(
            Arguments.of("AI-L1-001", web("return chat.prompt().system(\"fixed instructions\").user(prompt).call().content();")),
            Arguments.of("AI-L1-002", web("try { return chat.prompt().advisors(new SafeGuardAdvisor(List.of(\"blocked\"))).user(prompt).call().content(); } catch (Exception e) { throw e; }")),
            Arguments.of("AI-L2-001", "@Tool @PreAuthorize(\"hasRole('OPERATOR')\") void update(String value) { jdbc.update(\"update table_a set name=?\", value); }"),
            Arguments.of("AI-L2-002", web("return chat.prompt().user(prompt).advisors(a -> a.param(ChatMemory.CONVERSATION_ID, authorizedConversation())).call().content();")),
            Arguments.of("AI-L3-001", web("String answer=chat.prompt().user(prompt).call().content(); logger.info(\"completed\"); return answer;")),
            Arguments.of("AI-L4-001", web("chat.prompt().user(prompt).stream().content().retry(3).subscribe(); return \"ok\";")),
            Arguments.of("AI-L5-001", stream("moderation.call(new ModerationPrompt(chunk)); emitter.send(chunk);")),
            Arguments.of("AI-L6-001", web("MDC.put(\"requestId\", generateId()); return chat.prompt().user(prompt).call().content();")),
            Arguments.of("AI-L7-001", web("String answer=chat.prompt().user(prompt).call().content(); jdbc.update(\"insert into replies values (?)\", answer); return answer;")),
            Arguments.of("AI-L2-003", web("return chat.prompt().user(prompt).advisors(a -> a.param(QuestionAnswerAdvisor.FILTER_EXPRESSION, \"tenant == 'server-owned'\")).call().content();"))
        );
    }
    @ParameterizedTest @MethodSource("nonViolations")
    void correctOrUnprovenAlternativeIsNotViolation(String id, String members) {
        assertNotEquals(Disposition.VIOLATED, assess(id, members).disposition(), id);
    }
    static Stream<Arguments> unknowns() {
        return Stream.of(
            Arguments.of("AI-L1-001", web("return chat.prompt().system(customGuard(prompt)).call().content();")),
            Arguments.of("AI-L1-002", web("SafeGuardAdvisor guard = new SafeGuardAdvisor(List.of(\"blocked\")); return chat.prompt().user(prompt).call().content();")),
            Arguments.of("AI-L2-001", "@Tool void remove(String id) { repository.deleteById(id); }"),
            Arguments.of("AI-L2-002", "String singleUser() { return chat.prompt().advisors(a -> a.param(ChatMemory.CONVERSATION_ID, \"single-user\")).call().content(); }"),
            Arguments.of("AI-L3-001", web("String answer=chat.prompt().user(prompt).call().content(); logger.info(mask(answer)); return answer;")),
            Arguments.of("AI-L4-001", web("chat.prompt().user(prompt).stream().content().retry(retries).subscribe(); return \"ok\";")),
            Arguments.of("AI-L5-001", stream("review(chunk); emitter.send(chunk);")),
            Arguments.of("AI-L6-001", web("return chat.prompt().user(prompt).call().content();")),
            Arguments.of("AI-L7-001", web("String answer=chat.prompt().user(prompt).call().content(); Runtime.getRuntime().exec(check(answer)); return answer;")),
            Arguments.of("AI-L2-003", web("return chat.prompt().user(prompt).advisors(a -> a.param(QuestionAnswerAdvisor.FILTER_EXPRESSION, filterService.build(prompt))).call().content();"))
        );
    }
    @ParameterizedTest @MethodSource("unknowns")
    void unresolvedControlsRemainUnknown(String id, String members) { assertEquals(Disposition.UNKNOWN, assess(id, members).disposition(), id); }

    @ParameterizedTest @MethodSource("violations")
    void unknownVersionDowngradesAllFrameworkConclusions(String id, String members) {
        var assessments = new RuleEngine().assess(project(HEADER + members + "}", "UNKNOWN", true), () -> false);
        var result = assessments.stream().filter(a -> a.ruleId().equals(id)).findFirst().orElseThrow();
        assertEquals(Disposition.UNKNOWN, result.disposition());
        assertFalse(result.evidence().isEmpty());
    }
    @Test void nonAiLookalikesDoNotTrigger() {
        String code = "class App { FakeClient chat; FakeLog logger; Object ask(String prompt) { return chat.prompt().system(prompt).stream().content().retry(); } }";
        var results = new RuleEngine().assess(project(code, "UNKNOWN", false), () -> false);
        assertTrue(results.stream().allMatch(a -> a.disposition() == Disposition.NOT_APPLICABLE));
        assertEquals(Set.of(Domain.values()), results.stream().map(Assessment::domain).collect(java.util.stream.Collectors.toSet()));
    }
    @Test void sameNameTypeDoesNotBorrowSpringImport() {
        String code = HEADER + "class ChatClient {} " + web("return chat.prompt().system(prompt).call().content();") + "}";
        assertTrue(new RuleEngine().assess(project(code, "SUPPORTED", true), () -> false).stream().noneMatch(a -> a.disposition() == Disposition.VIOLATED));
    }
    @Test void localParameterShadowsFieldAndSiblingMethodDeclarations() {
        var members = "void other() { String text=chat.prompt().call().content(); } " + web("String text=\"fixed\"; Runtime.getRuntime().exec(text); return text;");
        assertNotEquals(Disposition.VIOLATED, assess("AI-L7-001", members).disposition());
    }
    @Test void reassignedLocalIsNotAssumedToKeepOriginalTaint() {
        assertEquals(Disposition.UNKNOWN, assess("AI-L7-001", web("String text=chat.prompt().call().content(); if (true) text=review(text); Runtime.getRuntime().exec(text); return text;")).disposition());
    }
    @Test void standaloneDataArgumentDoesNotBecomeProcessCommand() {
        assertNotEquals(Disposition.VIOLATED, assess("AI-L7-001", web("String text=chat.prompt().call().content(); new ProcessBuilder(\"echo\", text).start(); return text;")).disposition());
        assertEquals(Disposition.VIOLATED, assess("AI-L7-001", web("String text=chat.prompt().call().content(); new ProcessBuilder(\"sh\", \"-c\", text).start(); return text;")).disposition());
    }
    @Test void differentPayloadModerationDoesNotProveLateCheck() {
        String body = web("String other=chat.prompt().call().content(); chat.prompt().stream().content().doOnNext(chunk -> { emitter.send(chunk); moderation.call(new ModerationPrompt(other)); }); return \"done\";");
        assertEquals(Disposition.UNKNOWN, assess("AI-L5-001", body).disposition());
    }
    @Test void cancellationIsPropagated() {
        assertThrows(CancellationException.class, () -> new RuleEngine().assess(project(HEADER + "}", "SUPPORTED", true), () -> true));
    }
    @Test void malformedOrSkippedNonAiFilesCannotAppearNotApplicable() {
        SourceProject base = project("class App {}", "UNKNOWN", false);
        var incomplete = new SourceProject(base.root(), base.sources(), Map.of(), base.metadata(), base.digest(), List.of(new Diagnostic("PARSE_ERROR", "bad.java", "parse failed")));
        assertTrue(new RuleEngine().assess(incomplete, () -> false).stream().allMatch(a -> a.disposition() == Disposition.UNKNOWN));
    }
    @Test void requestAndModelSecretsAreNotPrintedInEvidence() {
        String secret="THIS_IS_A_PRIVATE_VALUE_987";
        String body=web("String answer=chat.prompt().system(prompt + \"" + secret + "\").call().content(); logger.info(answer); return answer;");
        var report = new RuleEngine().assess(project(HEADER + body + "}", "SUPPORTED", true), () -> false).toString();
        assertFalse(report.contains(secret));
    }
    @Test void missingMemoryOrRagBindingCannotProveUseOfParameter() {
        assertEquals(Disposition.UNKNOWN, assess("AI-L2-002", web("return chat.prompt().advisors(a -> a.param(ChatMemory.CONVERSATION_ID, \"shared\")).call().content();")).disposition());
        assertEquals(Disposition.UNKNOWN, assess("AI-L2-003", web("return chat.prompt().advisors(a -> a.param(QuestionAnswerAdvisor.FILTER_EXPRESSION, prompt)).call().content();")).disposition());
    }
    @Test void unknownDefaultAdvisorsDoNotProveBypass() {
        var body=web("try { return chat.prompt().advisors(new SafeGuardAdvisor(List.of(\"blocked\"))).user(prompt).call().content(); } catch (Exception e) { return chat.prompt().user(prompt).call().content(); }");
        assertEquals(Disposition.UNKNOWN, assess("AI-L1-002", body).disposition());
    }
    @Test void importedCustomRuntimeIsNotAnExecutionSink() {
        String code=HEADER.replace("import java.util.List;", "import java.util.List; import custom.Runtime;") +
            web("String response=chat.prompt().call().content(); Runtime runtime=service.getRuntime(); runtime.exec(response); Runtime.getRuntime().exec(response); return response;") + "}";
        assertTrue(new RuleEngine().assess(project(code,"SUPPORTED",true),()->false).stream()
            .filter(a -> a.ruleId().equals("AI-L7-001")).noneMatch(a -> a.disposition()==Disposition.VIOLATED));
    }
    @Test void customStreamTransformationBreaksProofOfRawOutput() {
        assertNotEquals(Disposition.VIOLATED, assess("AI-L5-001", web("chat.prompt().stream().content().map(this::sanitize).doOnNext(chunk -> { emitter.send(chunk); moderation.call(new ModerationPrompt(chunk)); }); return \"ok\";")).disposition());
    }
    @Test void violationDoesNotHideAnotherUnknownPath() {
        var members=web("chat.prompt().system(prompt).call().content(); return chat.prompt().system(customGuard(prompt)).call().content();");
        var results=new RuleEngine().assess(project(HEADER+members+"}","SUPPORTED",true),()->false).stream().filter(a -> a.ruleId().equals("AI-L1-001")).toList();
        assertTrue(results.stream().anyMatch(a -> a.disposition()==Disposition.VIOLATED));
        assertTrue(results.stream().anyMatch(a -> a.disposition()==Disposition.UNKNOWN));
    }
    @Test void parameterReassignmentBreaksRawInputProof() {
        assertEquals(Disposition.UNKNOWN, assess("AI-L1-001", web("prompt=customGuard(prompt); return chat.prompt().system(prompt).call().content();")).disposition());
        assertNotEquals(Disposition.VIOLATED, assess("AI-L5-001", stream("chunk=customGuard(chunk); emitter.send(chunk); moderation.call(new ModerationPrompt(chunk));")).disposition());
    }
    @Test void unrelatedParamMethodInsideAdvisorLambdaIsNotFrameworkConfiguration() {
        String members=web("return chat.prompt().advisors(new QuestionAnswerAdvisor(store)).advisors(a -> unrelated.param(QuestionAnswerAdvisor.FILTER_EXPRESSION, prompt)).call().content();");
        assertEquals(Disposition.UNKNOWN, assess("AI-L2-003",members).disposition());
    }
    @Test void requestAdvisorMayBeBoundAfterItsParameters() {
        String members=web("return chat.prompt().advisors(a -> a.param(QuestionAnswerAdvisor.FILTER_EXPRESSION, prompt)).advisors(new QuestionAnswerAdvisor(store)).call().content();");
        assertEquals(Disposition.VIOLATED, assess("AI-L2-003",members).disposition());
    }
    @Test void localLogDoesNotBorrowLombokLoggerAnnotation() {
        String code=HEADER.replace("class App {", "@lombok.extern.slf4j.Slf4j class App {") +
            web("Other log=otherService(); String answer=chat.prompt().call().content(); log.info(answer); return answer;") + "}";
        assertTrue(new RuleEngine().assess(project(code,"SUPPORTED",true),()->false).stream()
            .filter(a -> a.ruleId().equals("AI-L3-001")).noneMatch(a -> a.disposition()==Disposition.VIOLATED));
    }
}
