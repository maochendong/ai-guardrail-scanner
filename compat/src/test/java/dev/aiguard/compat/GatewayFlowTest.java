package dev.aiguard.compat;

import static org.junit.Assert.*;

import dev.aiguard.compat.JavaSyntax.*;
import java.util.*;
import org.junit.Test;

public class GatewayFlowTest {
  private static final String HTTP =
      "import okhttp3.*;import com.fasterxml.jackson.databind.*;class Transport {OkHttpClient"
          + " wire;ObjectMapper mapper;JsonNode exchange(String question){Request request=new"
          + " Request.Builder().url(\"https://example.invalid/chat/completions\").post(RequestBody.create(question,null)).build();try(Response"
          + " response=wire.newCall(request).execute()){return"
          + " mapper.readTree(response.body().string());}}}";

  private static GatewayFlow flow(JavaGraph graph) {
    return GatewayFlow.build(graph, JavaSyntaxGraphTest.NONE);
  }

  private static Node call(JavaGraph g, String name) {
    return JavaSyntaxGraphTest.call(g, name);
  }

  private static JavaGraph graph(String... source) {
    return JavaSyntaxGraphTest.graph(source);
  }

  @Test
  public void responseAliasesAndJsonKeepOrigin() {
    JavaGraph g =
        graph(
            HTTP,
            "class User {Transport t;void use(){var"
                + " raw=t.exchange(\"x\");log(raw.path(\"choices\").get(0).path(\"message\").path(\"content\").asText());}void"
                + " log(Object x){}}");
    GatewayFlow f = flow(g);
    assertEquals(1, f.gateways().size());
    assertNotNull(f.origin(call(g, "log").args.get(0)));
    assertTrue(f.isInvocation(call(g, "exchange")));
  }

  @Test
  public void renameIsIndependentAndOrdinaryHttpIsNotModel() {
    assertEquals(
        1,
        flow(graph(HTTP.replace("Transport", "Different").replace("exchange", "operation")))
            .gateways()
            .size());
    assertTrue(
        flow(graph(
                HTTP.replace("/chat/completions", "/catalog")
                    + "// chat/completions model choices"))
            .gateways()
            .isEmpty());
  }

  @Test
  public void ignoredResponseAndEnvelopeDoNotTaintReturn() {
    for (String replacement : Arrays.asList("mapper.readTree(\"{}\")", "response.toString()")) {
      JavaGraph g =
          graph(
              HTTP.replace(
                  "return mapper.readTree(response.body().string());",
                  "return " + replacement + ";"),
              "class U{Transport t;Object use(){return t.exchange(\"x\");}}");
      GatewayFlow f = flow(g);
      assertEquals(1, f.gateways().size());
      assertNull(f.origin(call(g, "exchange")));
    }
  }

  @Test
  public void sameNamedHttpTypeDoesNotBorrowImport() {
    assertTrue(flow(graph(HTTP + "class OkHttpClient {} ")).gateways().isEmpty());
  }

  @Test
  public void overwrittenAndUnrelatedHelperLoseOrigin() {
    JavaGraph g =
        graph(
            HTTP,
            "class U{Transport t;void run(){var x=t.exchange(\"x\");x=null;log(x);}void log(Object"
                + " x){}}");
    assertNull(flow(g).origin(call(g, "log").args.get(0)));
    JavaGraph h =
        graph(
            HTTP,
            "class U{Transport t;Object identity(Object x){return x;}void"
                + " run(){identity(t.exchange(\"x\"));log(identity(\"fixed\"));}void log(Object"
                + " x){}}");
    assertNull(flow(h).origin(call(h, "log").args.get(0)));
  }

  @Test
  public void responseMetadataIsNotRawOutput() {
    JavaGraph g =
        graph(
            HTTP,
            "class U{Transport t;void"
                + " run(){log(t.exchange(\"x\").path(\"usage\").path(\"total_tokens\").asInt());}void"
                + " log(Object x){}}");
    assertNull(flow(g).origin(call(g, "log").args.get(0)));
  }

  @Test
  public void requestDetectionFollowsActualReceiverChain() {
    String nested =
        "new Request.Builder().url(\"https://x/chat/completions\").post(null).build().toString()";
    assertTrue(
        flow(graph(
                HTTP.replace(
                    ".url(\"https://example.invalid/chat/completions\")",
                    ".url(\"https://x/catalog\").header(\"x\"," + nested + ")")))
            .gateways()
            .isEmpty());
  }

  @Test
  public void configuredRestClientRequiresAssociatedWireShapes() {
    String source =
        "import org.springframework.web.client.RestClient;import java.util.List;class P{RestClient"
            + " wire;String endpoint;record Message(String role,String content){}record"
            + " Request(String model,List<Message> messages){}record Choice(Message"
            + " message){}record Reply(List<Choice> choices){}String fetch(String q){Reply"
            + " reply=wire.post().uri(endpoint).body(new Request(\"m\",List.of(new"
            + " Message(\"user\",q)))).retrieve().body(Reply.class);return"
            + " reply.choices().get(0).message().content();}}class U{P p;String run(){return"
            + " p.fetch(\"x\");}}";
    JavaGraph g = graph(source);
    GatewayFlow f = flow(g);
    assertEquals(1, f.gateways().size());
    assertNotNull(f.origin(call(g, "fetch")));
    assertTrue(
        flow(graph(
                source.replace(
                    "new Request(\"m\",List.of(new Message(\"user\",q)))", "\"ordinary\"")))
            .gateways()
            .isEmpty());
  }

  @Test
  public void tryAssignmentOnlyTerminatingCatchPreservesCandidate() {
    JavaGraph g =
        graph(
            HTTP,
            "class U{Transport t;void run(){Object"
                + " result;try{result=t.exchange(\"x\");}catch(Exception"
                + " e){return;}log(result);}void log(Object x){}}");
    GatewayFlow.Origin origin = flow(g).origin(call(g, "log").args.get(0));
    assertNotNull(origin);
    assertTrue(origin.candidate);
    JavaGraph h =
        graph(
            HTTP,
            "class U{Transport t;void run(){Object"
                + " result=null;try{result=t.exchange(\"x\");}catch(Exception e){}log(result);}void"
                + " log(Object x){}}");
    assertNull(flow(h).origin(call(h, "log").args.get(0)));
  }

  @Test
  public void callbacksSupplyOnlyModelContent() {
    String source =
        "import okhttp3.*;import okhttp3.sse.*;import java.util.function.Consumer;class"
            + " A{OkHttpClient wire;EventSource stream(Consumer<String> sink){Request r=new"
            + " Request.Builder().url(\"https://x/chat/completions\").post(null).build();EventSourceListener"
            + " listener=new EventSourceListener(){public void onEvent(EventSource s,String"
            + " id,String type,String data){sink.accept(data);}};return"
            + " EventSources.createFactory(wire).newEventSource(r,listener);}}class U{A a;void"
            + " run(){a.stream(value->send(value));}void send(String x){}}";
    JavaGraph g = graph(source);
    GatewayFlow f = flow(g);
    assertEquals(1, f.gateways().size());
    assertNotNull(f.origin(call(g, "send").args.get(0)));
    assertNull(f.origin(call(g, "stream")));
    JavaGraph h = graph(source.replace("sink.accept(data)", "sink.accept(\"fixed\")"));
    assertNull(flow(h).origin(call(h, "send").args.get(0)));
  }

  @Test
  public void noSourceValuesInEvidence() {
    JavaGraph g = graph(HTTP.replace("example.invalid", "private-host-secret.invalid"));
    GatewayFlow f = flow(g);
    Node raw = call(g, "readTree");
    assertFalse(f.origin(raw).evidence.toString().contains("private-host-secret"));
    assertFalse(f.diagnostics().toString().contains("private-host-secret"));
  }

  @Test
  public void requestBuiltInTryWithTerminatingCatchIsAssociated() {
    String adapted =
        HTTP.replace(
                "Request request=new Request.Builder()",
                "Request request;try{request=new Request.Builder()")
            .replace(
                ".build();try(Response",
                ".build();}catch(Exception failure){return null;}try(Response");
    assertEquals(1, flow(graph(adapted)).gateways().size());
    assertTrue(
        flow(graph(
                adapted.replace(
                    "catch(Exception failure){return null;}", "catch(Exception failure){}")))
            .gateways()
            .isEmpty());
  }

  @Test
  public void modelCollectionCopyAndForeachRemainCandidate() {
    JavaGraph g =
        graph(
            HTTP,
            "import java.util.*;import com.fasterxml.jackson.databind.*;class U{Transport"
                + " t;List<JsonNode> copy(JsonNode values){List<JsonNode> result=new"
                + " ArrayList<>();values.forEach(result::add);return result;}void"
                + " run(){for(JsonNode"
                + " item:copy(t.exchange(\"x\").path(\"tool_calls\"))){log(item.path(\"function\").path(\"name\").asText());}}void"
                + " log(Object x){}}");
    GatewayFlow.Origin origin = flow(g).origin(call(g, "log").args.get(0));
    assertNotNull(origin);
    assertTrue(origin.candidate);
  }

  @Test
  public void modernJdkHttpSourceDoesNotRequireModernRuntime() {
    JavaGraph g =
        graph(
            "import java.net.http.HttpClient;import java.net.http.HttpRequest;import"
                + " java.net.http.HttpResponse;import java.net.URI;final class X{HttpClient"
                + " client;String run(){HttpRequest"
                + " req=HttpRequest.newBuilder(URI.create(\"https://x/chat/completions\")).POST(HttpRequest.BodyPublishers.ofString(\"{}\")).build();HttpResponse<String>"
                + " response=client.send(req,HttpResponse.BodyHandlers.ofString());return"
                + " response.body();}}class Y{X x;String use(){return x.run();}}");
    GatewayFlow f = flow(g);
    assertEquals(1, f.gateways().size());
    assertNotNull(f.origin(call(g, "run")));
  }

  @Test(expected = java.util.concurrent.CancellationException.class)
  public void cancellationStopsFlow() {
    GatewayFlow.build(
        graph(HTTP),
        new Cancel() {
          public void check() {
            throw new java.util.concurrent.CancellationException();
          }
        });
  }

  @Test
  public void eventFieldAccumulationIsCandidateBiConsumerContent() {
    String source =
        "import okhttp3.*;import okhttp3.sse.*;import java.util.function.BiConsumer;import"
            + " java.util.*;import com.fasterxml.jackson.databind.*;class A{OkHttpClient"
            + " wire;ObjectMapper mapper;EventSource stream(BiConsumer<JsonNode,String>"
            + " sink){Request r=new"
            + " Request.Builder().url(\"https://x/chat/completions\").post(null).build();return"
            + " EventSources.createFactory(wire).newEventSource(r,new"
            + " EventSourceListener(){StringBuilder buffer=new StringBuilder();List<Object>"
            + " frames=new ArrayList<>();public void onEvent(EventSource source,String id,String"
            + " type,String data){if(data.equals(\"done\")){Map<String,Object> frame=new"
            + " HashMap<>();frame.put(\"name\",buffer.toString());frames.add(frame);sink.accept(mapper.valueToTree(frames),\"fixed\");return;}buffer.append(mapper.readTree(data).path(\"choices\").get(0).path(\"delta\").path(\"tool_calls\").get(0).path(\"function\").path(\"name\").asText());}});}}class"
            + " U{A a;void run(){a.stream((value,fixed)->send(value,fixed));}void send(Object"
            + " value,String fixed){}}";
    JavaGraph g = graph(source);
    GatewayFlow f = flow(g);
    Node send = call(g, "send");
    assertNotNull(f.origin(send.args.get(0)));
    assertTrue(f.origin(send.args.get(0)).candidate);
    assertNull(f.origin(send.args.get(1)));
  }
}
