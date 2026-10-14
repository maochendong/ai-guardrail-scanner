package dev.aiguard.analysis;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import dev.aiguard.model.ScanModel.ProjectMetadata;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CancellationException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GatewayModelTest {
    private static final String HTTP = """
        import okhttp3.*;
        import com.fasterxml.jackson.databind.*;
        class Transport {
          OkHttpClient wire; ObjectMapper mapper;
          JsonNode exchange(String question) throws Exception {
            Request request = new Request.Builder().url("https://example.invalid/v1/chat/completions")
              .post(RequestBody.create(question, MediaType.parse("application/json"))).build();
            try (Response response = wire.newCall(request).execute()) {
              return mapper.readTree(response.body().string());
            }
          }
        }
        """;
    private record Fixture(SourceProject project, GatewayModel model) {
        MethodCallExpr call(String name) {
            return project.sources().stream().flatMap(s -> s.unit().findAll(MethodCallExpr.class).stream())
                .filter(c -> c.getNameAsString().equals(name)).findFirst().orElseThrow();
        }
    }
    private static Fixture fixture(String... codes) {
        List<SourceProject.JavaSource> sources = new ArrayList<>();
        var parser=new JavaParser(new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_21));
        for (int i=0;i<codes.length;i++) sources.add(new SourceProject.JavaSource("src/Unit"+i+".java", parser.parse(codes[i]).getResult().orElseThrow()));
        var project = new SourceProject(Path.of("/fixture"), sources, Map.of(),
            new ProjectMetadata("", "UNKNOWN", codes.length, 0, false), "digest", List.of());
        return new Fixture(project, GatewayModel.build(project, LocalCallGraph.build(project, () -> false), () -> false));
    }
    @Test void typedHttpProtocolProducesReturnOriginThroughAliasesAndJson() {
        var f=fixture(HTTP, "class Consumer { Transport channel; void use() throws Exception { var raw=channel.exchange(\"input\"); var text=raw.path(\"choices\").get(0).path(\"message\").path(\"content\").asText(); log(text); } void log(Object value) {} }");
        assertEquals(1, f.model.gateways().size());
        assertTrue(f.model.isInvocation(f.call("exchange")));
        assertTrue(f.model.origin(f.call("log").getArgument(0)).isPresent());
    }
    @Test void packageClassAndMethodRenamingDoesNotChangeDetection() {
        var renamed=HTTP.replace("Transport", "ArbitraryAdapter").replace("exchange", "performAction");
        assertEquals(1, fixture(renamed).model.gateways().size());
    }
    @Test void ordinaryHttpAndCommentKeywordsAreNotModels() {
        assertTrue(fixture(HTTP.replace("/v1/chat/completions", "/catalog")+"// model messages choices chat/completions").model.gateways().isEmpty());
    }
    @Test void unexecutedRequestIsNotGateway() {
        assertTrue(fixture(HTTP.replace("try (Response response = wire.newCall(request).execute()) {\n      return mapper.readTree(response.body().string());\n    }", "return null;")).model.gateways().isEmpty());
    }
    @Test void sameNamedUnrelatedHttpTypesDoNotBorrowImports() {
        assertTrue(fixture(HTTP.replace("class Transport", "class OkHttpClient {} class Transport")).model.gateways().isEmpty());
    }
    @Test void ignoredHttpResponseDoesNotTaintUnrelatedReturn() {
        var f=fixture(HTTP.replace("return mapper.readTree(response.body().string());", "return mapper.readTree(\"{}\");"),
            "class Consumer { Transport channel; Object use() throws Exception { return channel.exchange(\"input\"); } }");
        assertEquals(1,f.model.gateways().size());
        assertTrue(f.model.origin(f.call("exchange")).isEmpty());
    }
    @Test void overwrittenAliasAndUnrelatedHelperDoNotKeepRawOrigin() {
        var f=fixture(HTTP, "class Consumer { Transport channel; void use() throws Exception { var raw=channel.exchange(\"input\"); raw=null; log(raw); } void log(Object value) {} }");
        assertTrue(f.model.origin(f.call("log").getArgument(0)).isEmpty());
        var g=fixture(HTTP, "class Consumer { Transport channel; Object transform(Object x) { return \"fixed\"; } void use() throws Exception { log(transform(channel.exchange(\"input\"))); } void log(Object value) {} }");
        assertTrue(g.model.origin(g.call("log").getArgument(0)).isEmpty());
    }
    @Test void wrapperReturningModelValuePreservesOrigin() {
        var f=fixture(HTTP, "class Wrapper { Transport channel; Object wrap() throws Exception { var value=channel.exchange(\"input\"); return value; } Object use() throws Exception { return wrap(); } }");
        assertTrue(f.model.origin(f.call("wrap")).isPresent());
    }
    @Test void identityHelperDoesNotTaintItsUnrelatedInvocation() {
        var f=fixture(HTTP,"class Wrapper { Transport channel; Object identity(Object x) { return x; } void use() throws Exception { identity(channel.exchange(\"input\")); log(identity(\"fixed\")); } void log(Object x) {} }");
        assertTrue(f.model.origin(f.call("log").getArgument(0)).isEmpty());
    }
    @Test void responseUsageAndProviderMetadataAreNotRawModelContent() {
        var f=fixture(HTTP,"class Wrapper { Transport channel; void use() throws Exception { var response=channel.exchange(\"input\"); log(response.path(\"usage\").path(\"total_tokens\").asInt()); } void log(Object value) {} }");
        assertTrue(f.model.origin(f.call("log").getArgument(0)).isEmpty());
    }
    @Test void responseEnvelopeToStringIsMetadataAndNotRawContent() {
        var f=fixture(HTTP.replace("JsonNode exchange", "String exchange").replace("return mapper.readTree(response.body().string());", "return response.toString();"),
            "class Caller { Transport wire; Object use() throws Exception { return wire.exchange(\"input\"); } }");
        assertEquals(1,f.model.gateways().size());
        assertTrue(f.model.origin(f.call("exchange")).isEmpty());
    }
    @Test void onlyExecutedRequestBuilderChainDeterminesProtocol() {
        String nested="new Request.Builder().url(\"https://example.invalid/chat/completions\").post(RequestBody.create(\"x\",MediaType.parse(\"application/json\"))).build().toString()";
        var f=fixture(HTTP.replace(".url(\"https://example.invalid/v1/chat/completions\")", ".url(\"https://example.invalid/catalog\").header(\"meta\","+nested+")"));
        assertTrue(f.model.gateways().isEmpty());
    }
    @Test void singleTryAssignmentWithTerminatingCatchPreservesOnlyCandidateSource() {
        var f=fixture(HTTP,"class Caller { Transport wire; void use() throws Exception { Object result; try { result=wire.exchange(\"input\"); } catch(Exception failure) { return; } log(result); } void log(Object value) {} }");
        assertTrue(f.model.origin(f.call("log").getArgument(0)).orElseThrow().candidateDispatch());
        var g=fixture(HTTP,"class Caller { Transport wire; void use() throws Exception { Object result=null; try { result=wire.exchange(\"input\"); } catch(Exception failure) { log(failure); } log(result); } void log(Object value) {} }");
        var uses=g.project.sources().get(1).unit().findAll(MethodCallExpr.class).stream().filter(c -> c.getNameAsString().equals("log")).toList();
        assertTrue(g.model.origin(uses.getLast().getArgument(0)).isEmpty());
    }
    @Test void mixedInterfaceDispatchIsOnlyCandidateOrigin() {
        var f=fixture(HTTP.replace("class Transport", "class Transport implements Port"),
            "interface Port { com.fasterxml.jackson.databind.JsonNode exchange(String x) throws Exception; } class StaticPort implements Port { public com.fasterxml.jackson.databind.JsonNode exchange(String x) { return null; } } class Consumer { Port channel; Object use() throws Exception { return channel.exchange(\"input\"); } }");
        var origin=f.model.origin(f.call("exchange")).orElseThrow();
        assertTrue(origin.candidateDispatch());
    }
    @Test void configuredRestClientUsesAssociatedRecordWireShape() {
        var f=fixture("""
            import org.springframework.web.client.RestClient;
            import java.util.List;
            class Provider {
              RestClient wire; String endpoint;
              record Message(String role,String content) {}
              record Request(String model,List<Message> messages) {}
              record Choice(Message message) {}
              record Reply(List<Choice> choices) {}
              String fetch(String q) {
                Reply reply=wire.post().uri(endpoint).body(new Request("model",List.of(new Message("user",q)))).retrieve().body(Reply.class);
                return reply.choices().get(0).message().content();
              }
            }
            class Caller { Provider provider; String use() { return provider.fetch("input"); } }
            """);
        assertEquals(1,f.model.gateways().size());
        assertTrue(f.model.origin(f.call("fetch")).isPresent());
    }
    @Test void unrelatedRecordShapesDoNotTurnOrdinaryHttpIntoModel() {
        var f=fixture("""
            import org.springframework.web.client.RestClient;
            import java.util.List;
            class Provider {
              RestClient wire;
              record Message(String role,String content) {}
              record Request(String model,List<Message> messages) {}
              record Reply(List<String> choices) {}
              String fetch() { return wire.post().uri("https://example.invalid/catalog").body("ordinary").retrieve().body(String.class); }
            }
            """);
        assertTrue(f.model.gateways().isEmpty());
    }
    @Test void callbackResponseCanBeTracedIntoCallerLambda() {
        var f=fixture("""
            import okhttp3.*;
            import okhttp3.sse.*;
            import java.util.function.Consumer;
            import com.fasterxml.jackson.databind.*;
            class Adapter {
              OkHttpClient wire; ObjectMapper mapper;
              EventSource stream(Consumer<String> consumer) {
                Request request=new Request.Builder().url("https://example.invalid/chat/completions").post(RequestBody.create("body",MediaType.parse("application/json"))).build();
                EventSourceListener listener=new EventSourceListener() {
                  public void onEvent(EventSource source,String id,String type,String data) {
                    JsonNode chunk=mapper.readTree(data);
                    String text=chunk.path("choices").get(0).path("delta").path("content").asText();
                    consumer.accept(text);
                  }
                };
                return EventSources.createFactory(wire).newEventSource(request,listener);
              }
            }
            class Caller { Adapter adapter; void use() { java.util.function.Consumer<String> callback=value -> send(value); adapter.stream(callback); } void send(String text) {} }
            """);
        assertEquals(Set.of(0),f.model.gateways().get(0).callbackArguments());
        assertTrue(f.model.origin(f.call("send").getArgument(0)).isPresent());
        assertTrue(f.model.origin(f.call("stream")).isEmpty(), "EventSource handle is not model output");
        var fixed=fixture(f.project.sources().stream().map(s -> s.unit().toString().replace("consumer.accept(text)","consumer.accept(\"fixed\")")).toArray(String[]::new));
        assertTrue(fixed.model.gateways().get(0).callbackArguments().isEmpty());
        assertTrue(fixed.model.origin(fixed.call("send").getArgument(0)).isEmpty(), "A callback carrying a fixed value is not model output");
    }
    @Test void diagnosticsAndEvidenceNeverContainSourceValues() {
        var f=fixture(HTTP.replace("https://example.invalid", "https://private-value.example"));
        assertFalse(f.model.gateways().toString().contains("private-value"));
        assertFalse(f.model.diagnostics().toString().contains("private-value"));
    }
    @Test void cancellationStopsConstruction() {
        var p=fixture(HTTP).project;
        assertThrows(CancellationException.class, () -> GatewayModel.build(p,LocalCallGraph.build(p,()->false),()->true));
    }
}
