package dev.aiguard.analysis;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import dev.aiguard.analysis.rules.FunctionCallingRules;
import dev.aiguard.model.ScanModel.*;
import org.junit.jupiter.api.Test;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CancellationException;
import static org.junit.jupiter.api.Assertions.*;

class FunctionCallingRulesTest {
    private static final String IMPORTS = """
        import com.fasterxml.jackson.databind.JsonNode;
        import com.fasterxml.jackson.databind.ObjectMapper;
        import okhttp3.*;
        import java.util.Map;
        """;
    private static final String GATEWAY = """
        final class Transport {
            OkHttpClient http; ObjectMapper mapper;
            JsonNode request(String question) throws Exception {
                Request outbound = new Request.Builder().url("https://example.invalid/v1/chat/completions")
                    .post(RequestBody.create(question, MediaType.parse("application/json"))).build();
                try (Response response = http.newCall(outbound).execute()) {
                    return mapper.readTree(response.body().string());
                }
            }
        }
        """;
    private static final String CALLER = """
        final class Entry {
            Transport transport; Dispatcher dispatcher;
            Object handle(String subject) throws Exception {
                JsonNode function = transport.request("PRIVATE_FIXTURE_874").path("choices").get(0)
                    .path("message").path("tool_calls").get(0).path("function");
                String name = function.path("name").asText();
                JsonNode args = function.path("arguments");
                return dispatcher.route(name, args, subject);
            }
        }
        """;
    private static SourceProject project(String code, boolean ai) {
        var parser = new JavaParser(new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));
        var unit = parser.parse(code).getResult().orElseThrow();
        return new SourceProject(Path.of("/fixture"), List.of(new SourceProject.JavaSource("src/Neutral.java", unit)), Map.of(),
            new ProjectMetadata("", "UNKNOWN", 1, 0, ai), "digest", List.of());
    }
    private static List<Assessment> assessCode(String code, boolean ai) {
        var project = project(code, ai);
        var graph = LocalCallGraph.build(project, () -> false);
        var gateways = GatewayModel.build(project, graph, () -> false);
        return FunctionCallingRules.assess(project, graph, gateways, () -> false);
    }
    private static List<Assessment> assess(String route) {
        return assessCode(IMPORTS + GATEWAY + CALLER + "final class Dispatcher { ObjectMapper mapper; " + route + " }", true);
    }
    private static boolean has(List<Assessment> results, String id, Disposition disposition) {
        return results.stream().anyMatch(a -> a.ruleId().equals(id) && a.disposition() == disposition);
    }
    private static String details(List<Assessment> results) {
        return results.stream().flatMap(a -> a.evidence().stream()).map(Evidence::detail).reduce("", (a,b) -> a + b);
    }
    private static String route(String body) {
        return "Object route(String selected, JsonNode payload, String context) throws Exception { " + body + " }";
    }

    @Test void fixedSwitchIsObservedButNotAuthorizationProof() {
        var results = assess(route("switch(selected) { case \"read\": return 1; default: return null; }"));
        assertTrue(has(results, "AI-FC-001", Disposition.OBSERVED), results.toString());
        assertTrue(details(results).contains("固定字符串 switch"));
        assertTrue(has(results, "AI-FC-001", Disposition.UNKNOWN));
        assertFalse(has(results, "AI-FC-001", Disposition.VIOLATED));
    }
    @Test void modelFieldToCommandAcrossDispatcherIsViolation() {
        var results = assess(route("Runtime.getRuntime().exec(payload.asText()); return null;"));
        assertTrue(has(results, "AI-FC-001", Disposition.VIOLATED), results.toString());
        assertFalse(results.toString().contains("PRIVATE_FIXTURE_874"));
    }
    @Test void functionNameMustNotSelectReflectionTargetDirectly() {
        assertTrue(has(assess(route("return Class.forName(selected);")), "AI-FC-001", Disposition.VIOLATED));
    }
    @Test void ordinaryProcessArgumentIsNotShellText() {
        assertFalse(has(assess(route("new ProcessBuilder(\"echo\", payload.asText()).start(); return null;")), "AI-FC-001", Disposition.VIOLATED));
        assertTrue(has(assess(route("new ProcessBuilder(\"sh\", \"-c\", payload.asText()).start(); return null;")), "AI-FC-001", Disposition.VIOLATED));
    }
    @Test void nonShellFlagDoesNotTurnDataIntoCommandText() {
        assertFalse(has(assess(route("new ProcessBuilder(\"grep\", \"-c\", payload.asText()).start(); return null;")), "AI-FC-001", Disposition.VIOLATED));
    }
    @Test void dynamicExecutableIsCheckedEvenWhenAnotherArgumentLooksLikeShellFlag() {
        assertTrue(has(assess(route("new ProcessBuilder(selected, \"-c\", \"fixed\").start(); return null;")), "AI-FC-001", Disposition.VIOLATED));
    }
    @Test void dispatcherHelperCarriesArgumentsByPosition() {
        var results = assess(route("return helper(payload);") + " Object helper(JsonNode data) throws Exception { Runtime.getRuntime().exec(data.asText()); return null; }");
        assertTrue(has(results, "AI-FC-001", Disposition.VIOLATED), results.toString());
    }
    @Test void reassignmentStopsOriginalNameSource() {
        var results = assessCode(IMPORTS + GATEWAY + CALLER.replace("return dispatcher.route", "name = \"fixed\"; return dispatcher.route") +
            "final class Dispatcher { " + route("return Class.forName(selected);") + "}", true);
        assertFalse(has(results, "AI-FC-001", Disposition.VIOLATED));
    }
    @Test void reassignedDispatchParameterDoesNotKeepTaint() {
        assertFalse(has(assess(route("selected = \"fixed\"; return Class.forName(selected);")), "AI-FC-001", Disposition.VIOLATED));
    }
    @Test void jsonDecodingIsObservedWithValidationStillUnknown() {
        var results = assess(route("JsonNode decoded = mapper.readTree(payload.asText()); return decoded;"));
        assertTrue(details(results).contains("Jackson JSON 解码"), results.toString());
        assertTrue(has(results, "AI-FC-002", Disposition.UNKNOWN));
    }
    @Test void ignoredValidatorResultDoesNotProveParametersWereRejected() {
        var results = assess("jakarta.validation.Validator validator; " + route("validator.validate(payload); return payload;"));
        assertTrue(details(results).contains("validate 调用"), results.toString());
        assertTrue(has(results, "AI-FC-002", Disposition.UNKNOWN));
    }
    @Test void separateContextArgumentDoesNotProveTrustedIdentity() {
        var results = assess(route("return context;"));
        assertTrue(has(results, "AI-FC-003", Disposition.OBSERVED));
        assertTrue(has(results, "AI-FC-003", Disposition.UNKNOWN));
    }
    @Test void finiteMapLookupIsStructuralEvidenceOnly() {
        var results = assess("Map<String, java.util.function.Function<JsonNode,Object>> handlers; " +
            route("if (!handlers.containsKey(selected)) return null; return handlers.get(selected).apply(payload);"));
        assertTrue(details(results).contains("Map 查找"), results.toString());
        assertTrue(has(results, "AI-FC-001", Disposition.UNKNOWN));
    }
    @Test void genericBusinessJsonDoesNotCreateFunctionCallingFinding() {
        var results = assessCode(IMPORTS + CALLER.replace("transport.request(\"PRIVATE_FIXTURE_874\")", "mapper.readTree(\"{}\")")
            .replace("Transport transport;", "ObjectMapper mapper;") +
            "final class Dispatcher { " + route("return Class.forName(selected);") + "}", false);
        assertTrue(results.stream().allMatch(a -> a.disposition() == Disposition.NOT_APPLICABLE), results.toString());
    }
    @Test void renamedClassesAndParametersProduceSameEvidence() {
        String original = IMPORTS + GATEWAY + CALLER + "final class Dispatcher { " + route("return Class.forName(selected);") + "}";
        var renamed = assessCode(original.replace("Transport", "Channel17").replace("Dispatcher", "ActionTable")
            .replace("Entry", "Orchestrator").replace("selected", "operation"), true);
        assertTrue(has(renamed, "AI-FC-001", Disposition.VIOLATED), renamed.toString());
    }
    @Test void customRecordProtocolRetainsSourceBinding() {
        String code = IMPORTS + GATEWAY + """
            final class Entry {
                Transport transport; Dispatcher dispatcher; ObjectMapper mapper;
                record Decision(String operation, JsonNode payload) {}
                Object handle(String context) throws Exception {
                    Decision decision = decode(transport.request("question").path("choices").get(0).path("message").path("content").asText());
                    return dispatcher.route(decision.operation(), decision.payload(), context);
                }
                Decision decode(String content) throws Exception {
                    JsonNode data = mapper.readTree(content);
                    return new Decision(data.path("tool").asText(), data.path("args"));
                }
            }
            """ + "final class Dispatcher { " + route("switch(selected) { case \"read\": return 1; default: return null; }") + "}";
        var results = assessCode(code, true);
        assertTrue(details(results).contains("固定字符串 switch"), results.toString());
        assertTrue(has(results, "AI-FC-002", Disposition.UNKNOWN));
    }
    @Test void userDefinedRuntimeLookalikeIsNotDangerous() {
        var results = assessCode(IMPORTS + GATEWAY + CALLER + "class Runtime { static Runtime getRuntime(){return null;} void exec(String x){} }" +
            "final class Dispatcher { " + route("Runtime.getRuntime().exec(payload.asText()); return null;") + "}", true);
        assertFalse(has(results, "AI-FC-001", Disposition.VIOLATED));
    }
    @Test void tryAssignedModelTextReachesRecordDispatchAsCandidate() {
        String code = IMPORTS + GATEWAY + """
            final class Entry {
                Transport transport; Dispatcher dispatcher; ObjectMapper mapper;
                record Decision(String operation, JsonNode payload) {}
                Object handle(String context) throws Exception {
                    String content;
                    try {
                        content = transport.request("question").path("choices").get(0).path("message").path("content").asText();
                    } catch (Exception failure) {
                        return null;
                    }
                    Decision decision = decode(content);
                    return dispatcher.route(decision.operation(), decision.payload(), context);
                }
                Decision decode(String content) throws Exception {
                    JsonNode data = mapper.readTree(content);
                    return new Decision(data.path("tool").asText(), data.path("args"));
                }
            }
            """ + "final class Dispatcher { " + route("return Class.forName(selected);") + "}";
        var results = assessCode(code, true);
        assertTrue(has(results, "AI-FC-001", Disposition.OBSERVED), results.toString());
        assertFalse(has(results, "AI-FC-001", Disposition.VIOLATED));
    }
    @Test void overridableGatewayDoesNotProveConcreteDangerousPath() {
        String code = IMPORTS + GATEWAY.replace("final class Transport", "class Transport") + CALLER +
            "final class Dispatcher { " + route("return Class.forName(selected);") + "}";
        var results = assessCode(code, true);
        assertFalse(has(results, "AI-FC-001", Disposition.VIOLATED));
        assertTrue(has(results, "AI-FC-001", Disposition.UNKNOWN));
    }
    @Test void directReflectionFromFunctionFieldsDoesNotRequireDispatcherWrapper() {
        String code = IMPORTS + GATEWAY + CALLER.replace("return dispatcher.route(name, args, subject);", "return Class.forName(name);") +
            "final class Dispatcher { " + route("return null;") + "}";
        assertTrue(has(assessCode(code, true), "AI-FC-001", Disposition.VIOLATED));
    }
    @Test void cancellationIsHonored() {
        var project = project("class Empty {}", false);
        var graph = LocalCallGraph.build(project, () -> false);
        var gateways = GatewayModel.build(project, graph, () -> false);
        assertThrows(CancellationException.class, () -> FunctionCallingRules.assess(project, graph, gateways, () -> true));
    }
}
