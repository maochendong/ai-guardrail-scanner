package dev.aiguard.analysis;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import dev.aiguard.model.ScanModel.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CancellationException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CustomGuardRulesTest {
    private static final String ADAPTER = """
        import okhttp3.*;
        import com.fasterxml.jackson.databind.*;
        final class Transport {
          OkHttpClient wire; ObjectMapper mapper;
          JsonNode exchange(String requestText) throws Exception {
            Request request = new Request.Builder().url("https://example.invalid/v1/chat/completions")
              .post(RequestBody.create(requestText, MediaType.parse("application/json"))).build();
            try (Response response = wire.newCall(request).execute()) {
              return mapper.readTree(response.body().string());
            }
          }
        }
        """;
    private static final String CHECKER = """
        final class DecisionLogic {
          record Result(boolean permitted) {}
          Result inspect(String value) { return new Result(!value.isBlank()); }
          static class Outcome {
            boolean value;
            Outcome(boolean value) { this.value=value; }
            boolean accepted() { return this.value; }
            void replace(boolean next) { value=next; }
          }
          Outcome examine(String value) { return new Outcome(!value.isBlank()); }
          boolean accept(String value) { return !value.isBlank(); }
          void pretend(String value) {}
        }
        """;
    private record Fixture(SourceProject project, LocalCallGraph graph, GatewayModel model) {
        List<Assessment> assess() { return CustomGuardRules.assess(project,graph,model,()->false); }
    }
    private static Fixture fixture(String body) {
        var parser=new JavaParser(new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));
        List<SourceProject.JavaSource> sources=new ArrayList<>();
        List<String> codes=List.of(ADAPTER,CHECKER,"""
            import org.slf4j.Logger;
            import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
            class Feature {
              Logger logger; SseEmitter emitter;
              boolean overwrite(DecisionLogic.Outcome value) { value.replace(true); return true; }
              void execute(String input) throws Exception {
                String answer=new Transport().exchange(input).path("choices").get(0).path("message").path("content").asText();
            """+body+"\n}\n}");
        for(int i=0;i<codes.size();i++) sources.add(new SourceProject.JavaSource("src/Part"+i+".java",parser.parse(codes.get(i)).getResult().orElseThrow()));
        var p=new SourceProject(Path.of("/fixture"),sources,Map.of(),new ProjectMetadata("","UNKNOWN",3,0,false),"digest",List.of());
        var g=LocalCallGraph.build(p,()->false);
        return new Fixture(p,g,GatewayModel.build(p,g,()->false));
    }
    private static boolean has(List<Assessment> a,String rule,Disposition d) { return a.stream().anyMatch(x->x.ruleId().equals(rule)&&x.disposition()==d); }
    @Test void discoversProtocolWithoutSpringAiVersion() {
        assertTrue(has(fixture("").assess(),"AI-GW-001",Disposition.OBSERVED));
    }
    @Test void rawGatewayValueInSlf4jIsReportedWithOrigin() {
        var a=fixture("logger.warn(\"value={}\",answer);").assess();
        assertTrue(has(a,"AI-GW-002",Disposition.VIOLATED));
        assertTrue(a.stream().filter(x->x.ruleId().equals("AI-GW-002")&&x.disposition()==Disposition.VIOLATED).allMatch(x->x.evidence().size()>1));
    }
    @Test void unrelatedLogValueIsNotGatewayLeak() {
        assertFalse(has(fixture("logger.warn(\"fixed\");").assess(),"AI-GW-002",Disposition.VIOLATED));
    }
    @Test void booleanDecisionAndEarlyReturnAreOnlyObserved() {
        var a=fixture("if (!new DecisionLogic().accept(answer)) return; emitter.send(answer);").assess();
        assertTrue(has(a,"AI-GUARD-002",Disposition.OBSERVED));
        assertTrue(has(a,"AI-GUARD-002",Disposition.UNKNOWN));
        assertFalse(has(a,"AI-GUARD-003",Disposition.VIOLATED));
    }
    @Test void resultRecordBooleanAccessorIsConsumed() {
        var a=fixture("var result=new DecisionLogic().inspect(answer); if(!result.permitted()) return; emitter.send(answer);").assess();
        assertTrue(has(a,"AI-GUARD-002",Disposition.OBSERVED));
    }
    @Test void ignoredPredicateDoesNotBecomeGuardCoverage() {
        var a=fixture("new DecisionLogic().accept(answer); emitter.send(answer);").assess();
        assertFalse(has(a,"AI-GUARD-002",Disposition.OBSERVED));
        assertTrue(has(a,"AI-GUARD-002",Disposition.UNKNOWN));
    }
    @Test void javaEightBooleanResultObjectAccessorIsConsumed() {
        var a=fixture("var result=new DecisionLogic().examine(answer); if(!result.accepted()) return; emitter.send(answer);").assess();
        assertTrue(has(a,"AI-GUARD-002",Disposition.OBSERVED));
        assertTrue(has(a,"AI-GUARD-002",Disposition.UNKNOWN));
    }
    @Test void mutableResultSetterBreaksConsumptionProof() {
        var a=fixture("var result=new DecisionLogic().examine(answer); result.replace(true); if(!result.accepted()) return; emitter.send(answer);").assess();
        assertFalse(has(a,"AI-GUARD-002",Disposition.OBSERVED));
    }
    @Test void mutableResultFieldWriteBreaksConsumptionProof() {
        var a=fixture("var result=new DecisionLogic().examine(answer); result.value=true; if(!result.accepted()) return; emitter.send(answer);").assess();
        assertFalse(has(a,"AI-GUARD-002",Disposition.OBSERVED));
    }
    @Test void mutationWithinConditionDoesNotConsumeOriginalDecision() {
        var a=fixture("var result=new DecisionLogic().examine(answer); if(overwrite(result)&&!result.accepted()) return; emitter.send(answer);").assess();
        assertFalse(has(a,"AI-GUARD-002",Disposition.OBSERVED));
    }
    @Test void checkingDifferentValueDoesNotProtectModelResponse() {
        var a=fixture("if(!new DecisionLogic().accept(input)) return; emitter.send(answer);").assess();
        assertFalse(has(a,"AI-GUARD-002",Disposition.OBSERVED));
    }
    @Test void sameNamedVoidGuardIsNotAResponseDecision() {
        var a=fixture("new DecisionLogic().pretend(answer); emitter.send(answer);").assess();
        assertFalse(has(a,"AI-GUARD-002",Disposition.OBSERVED));
    }
    @Test void mutatedDecisionDoesNotProveTheOriginalCheckWasConsumed() {
        var a=fixture("var result=new DecisionLogic().inspect(answer); result=new DecisionLogic.Result(true); if(!result.permitted()) return; emitter.send(answer);").assess();
        assertFalse(has(a,"AI-GUARD-002",Disposition.OBSERVED));
    }
    @Test void customPostEmissionDecisionIsAnObservationWithoutSecuritySemantics() {
        var a=fixture("emitter.send(answer); if(!new DecisionLogic().accept(answer)) return;").assess();
        assertTrue(has(a,"AI-GUARD-003",Disposition.OBSERVED));
        assertTrue(has(a,"AI-GUARD-003",Disposition.UNKNOWN));
        assertFalse(has(a,"AI-GUARD-003",Disposition.VIOLATED));
    }
    @Test void callOrderAcrossDifferentBranchesIsNotAnExecutionProof() {
        var a=fixture("if(input.isEmpty()) { emitter.send(answer); } else { if(!new DecisionLogic().accept(answer)) return; }").assess();
        assertFalse(has(a,"AI-GUARD-003",Disposition.VIOLATED));
    }
    @Test void sseEventBuilderCarriesModelPayload() {
        var a=fixture("emitter.send(SseEmitter.event().name(\"content\").data(answer)); if(!new DecisionLogic().accept(answer)) return;").assess();
        assertTrue(has(a,"AI-GUARD-003",Disposition.OBSERVED));
        assertFalse(has(a,"AI-GUARD-003",Disposition.VIOLATED));
    }
    @Test void singleStatementConditionalSendDoesNotBecomeStraightLineOrder() {
        var a=fixture("if(input.isEmpty()) emitter.send(answer); if(!new DecisionLogic().accept(answer)) return;").assess();
        assertFalse(has(a,"AI-GUARD-003",Disposition.OBSERVED));
    }
    @Test void overwrittenDecisionInsideConditionIsNotConsumed() {
        var a=fixture("boolean result=new DecisionLogic().accept(answer); if(result=true) return; emitter.send(answer);").assess();
        assertFalse(has(a,"AI-GUARD-002",Disposition.OBSERVED));
    }
    @Test void sourceConstantsAreNotExported() {
        var a=fixture("logger.warn(\"SECRET_MESSAGE_345\",answer);").assess();
        assertFalse(a.toString().contains("SECRET_MESSAGE_345"));
        assertFalse(a.toString().contains("example.invalid"));
    }
    @Test void cancellationStopsRules() {
        var f=fixture("");
        assertThrows(CancellationException.class,()->CustomGuardRules.assess(f.project,f.graph,f.model,()->true));
    }
}
