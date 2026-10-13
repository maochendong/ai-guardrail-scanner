package dev.aiguard.mcp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class McpProtocolTest {
    @TempDir Path temporary;
    private final ObjectMapper json = new ObjectMapper();

    @Test void realProcessHandshakeScanResultInvalidArgumentsAndEof() throws Exception {
        Path repository = Files.createDirectories(temporary.resolve("repo")).toRealPath();
        Files.writeString(repository.resolve("Demo.java"), "class Demo { String hello() { return \"hello\"; } }");
        Path reports = temporary.resolve("reports");
        try (Client client = new Client(repository, reports)) {
            var initialized = client.call("initialize", Map.of("protocolVersion", "2025-11-25", "capabilities", Map.of(),
                    "clientInfo", Map.of("name", "integration-test", "version", "1.0")));
            assertEquals("ai-guardrail-scanner", initialized.path("result").path("serverInfo").path("name").asText());
            client.notify("notifications/initialized", Map.of());
            var listing = client.call("tools/list", Map.of());
            assertEquals(5, listing.path("result").path("tools").size());
            assertFalse(client.tool("guardrail_rules", Map.of()).path("isError").asBoolean());
            assertTrue(client.tool("guardrail_scan_start", Map.of("repository", repository.toString(), "output", "/tmp/escape")).path("isError").asBoolean());
            assertTrue(client.tool("guardrail_scan_start", Map.of("repository", 42)).path("isError").asBoolean());
            assertTrue(client.tool("guardrail_scan_start", Map.of("repository", temporary.toString())).path("isError").asBoolean());
            JsonNode start = body(client.tool("guardrail_scan_start", Map.of("repository", repository.toString())));
            String id = start.path("scanId").asText(); assertFalse(id.isEmpty());
            JsonNode status = null;
            long until = System.nanoTime() + Duration.ofSeconds(15).toNanos();
            do {
                status = body(client.tool("guardrail_scan_status", Map.of("scanId", id)));
                if (!status.path("state").asText().equals("RUNNING")) break;
                Thread.sleep(30);
            } while (System.nanoTime() < until);
            assertEquals("COMPLETED", status.path("state").asText(), status.toString());
            var result = body(client.tool("guardrail_scan_result", Map.of("scanId", id)));
            assertEquals(id, json.readTree(result.path("content").asText()).path("scanId").asText());
            assertTrue(Files.isRegularFile(reports.resolve(id).resolve("results.sarif")));
            assertTrue(client.tool("guardrail_scan_result", Map.of("scanId", id, "format", "raw")).path("isError").asBoolean());
            assertEquals("COMPLETED", body(client.tool("guardrail_scan_cancel", Map.of("scanId", id))).path("state").asText());
            client.writer.close();
            assertTrue(client.process.waitFor(10, TimeUnit.SECONDS), "stdio EOF must terminate process");
            assertEquals(0, client.process.exitValue());
        }
    }

    @Test void oversizedProtocolFrameEndsSession() throws Exception {
        Path root = Files.createDirectories(temporary.resolve("repo")).toRealPath();
        try (Client c = new Client(root, temporary.resolve("reports"))) {
            try { c.writer.write("x".repeat(1024 * 1024 + 1)); c.writer.flush(); }
            catch (IOException ignored) { /* Server may close its pipe as soon as it detects the bound. */ }
            assertTrue(c.process.waitFor(10, TimeUnit.SECONDS));
        }
    }

    @Test void malformedProtocolFrameTerminatesSessionEvenWithoutAnotherRead() throws Exception {
        Path root = Files.createDirectories(temporary.resolve("repo")).toRealPath();
        try (Client c = new Client(root, temporary.resolve("reports"))) {
            c.writer.write("{malformed-frame}\n"); c.writer.flush();
            assertTrue(c.process.waitFor(10, TimeUnit.SECONDS), "SDK parse failure must unblock host lifecycle");
        }
    }

    @Test void activeCancellationAndEofDoNotPublishACompletedReport() throws Exception {
        Path root = Files.createDirectories(temporary.resolve("repo")).toRealPath();
        // A real bounded analysis workload makes cancellation observable without mocking the protocol.
        String methods = "";
        for (int j = 0; j < 100; j++) methods += "int f" + j + "(){return " + j + ";}";
        for (int i = 0; i < 500; i++) Files.writeString(root.resolve("C" + i + ".java"), "class C" + i + "{" + methods + "}");
        Path reports = temporary.resolve("reports");
        try (Client c = new Client(root, reports)) {
            c.call("initialize", Map.of("protocolVersion", "2025-11-25", "capabilities", Map.of(),
                    "clientInfo", Map.of("name", "cancel-test", "version", "1")));
            c.notify("notifications/initialized", Map.of());
            String id = body(c.tool("guardrail_scan_start", Map.of("repository", root.toString()))).path("scanId").asText();
            assertEquals("CANCELLED", body(c.tool("guardrail_scan_cancel", Map.of("scanId", id))).path("state").asText());
            assertTrue(c.tool("guardrail_scan_result", Map.of("scanId", id)).path("isError").asBoolean());
            c.writer.close(); assertTrue(c.process.waitFor(10, TimeUnit.SECONDS));
            assertFalse(Files.exists(reports.resolve(id)), "cancelled work must not publish a report");
        }
        try (Client c = new Client(root, temporary.resolve("eof-reports"))) {
            c.call("initialize", Map.of("protocolVersion", "2025-11-25", "capabilities", Map.of(),
                    "clientInfo", Map.of("name", "eof-test", "version", "1")));
            c.notify("notifications/initialized", Map.of());
            String id = body(c.tool("guardrail_scan_start", Map.of("repository", root.toString()))).path("scanId").asText();
            c.writer.close(); assertTrue(c.process.waitFor(10, TimeUnit.SECONDS));
            assertFalse(Files.exists(temporary.resolve("eof-reports").resolve(id)));
        }
    }

    private JsonNode body(JsonNode result) throws Exception {
        assertFalse(result.path("isError").asBoolean(), result.toString());
        return json.readTree(result.path("content").get(0).path("text").asText());
    }

    private final class Client implements AutoCloseable {
        final Process process;
        final BufferedWriter writer;
        final BufferedReader reader;
        final ExecutorService reads = Executors.newSingleThreadExecutor();
        int nextId;
        Client(Path root, Path out) throws Exception {
            var command = new java.util.ArrayList<String>();
            command.add(Path.of(System.getProperty("java.home"), "bin/java").toString());
            String packaged = System.getProperty("scanner.jar");
            if (packaged == null) command.addAll(List.of("-cp", System.getProperty("java.class.path"), "dev.aiguard.Main"));
            else command.addAll(List.of("-jar", Path.of(packaged).toAbsolutePath().toString()));
            command.addAll(List.of("mcp", "--allow-root", root.toString(), "--output", out.toString()));
            process = new ProcessBuilder(command).redirectError(temporary.resolve("stderr.log").toFile()).start();
            writer = process.outputWriter(); reader = process.inputReader();
        }
        void notify(String method, Object params) throws Exception {
            writer.write(json.writeValueAsString(Map.of("jsonrpc", "2.0", "method", method, "params", params))); writer.newLine(); writer.flush();
        }
        JsonNode call(String method, Object params) throws Exception {
            int id = ++nextId;
            writer.write(json.writeValueAsString(Map.of("jsonrpc", "2.0", "id", id, "method", method, "params", params))); writer.newLine(); writer.flush();
            return reads.submit(() -> {
                String line;
                while ((line = reader.readLine()) != null) {
                    JsonNode message = json.readTree(line); // Non-protocol stdout is a hard failure.
                    if (message.path("id").asInt(-1) == id) return message;
                }
                throw new EOFException("Protocol ended before response");
            }).get(15, TimeUnit.SECONDS);
        }
        JsonNode tool(String name, Object args) throws Exception { return call("tools/call", Map.of("name", name, "arguments", args)).path("result"); }
        public void close() throws Exception {
            try { writer.close(); } finally {
                if (!process.waitFor(3, TimeUnit.SECONDS)) process.destroyForcibly();
                reads.shutdownNow(); reader.close();
            }
        }
    }
}
