package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CancellationException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class InfrastructureTest {
  @Rule public TemporaryFolder temporary = new TemporaryFolder();
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private Path folder(String name) throws IOException {
    return temporary.newFolder(name).toPath().toRealPath();
  }

  @Test
  public void strictJsonRejectsDuplicateKeysAndTrailingData() throws Exception {
    for (String invalid :
        Arrays.asList("{\"x\":1,\"x\":2}", "{\"x\":1,}", "{} {}", "{x:1}", "/* x */ {}", "[NaN]")) {
      try {
        Json.parse(invalid);
        fail("Invalid JSON accepted");
      } catch (IOException expected) {
      } catch (IllegalStateException expected) {
      }
    }
    assertEquals("中文", Json.parse("{\"x\":\"中文\"}").getAsJsonObject().get("x").getAsString());
  }

  @Test
  public void strictJsonHasANestingLimit() throws Exception {
    String text = "0";
    for (int i = 0; i < 70; i++) text = "[" + text + "]";
    try {
      Json.parse(text);
      fail();
    } catch (IOException expected) {
    }
  }

  @Test
  public void pathPolicyRejectsEscapeSymlinkAndOutputOverlap() throws Exception {
    Path root = folder("repo"), outside = folder("outside"), output = folder("reports");
    PathPolicy policy = new PathPolicy(Arrays.asList(root), output);
    assertEquals(root, policy.repository(root));
    try {
      policy.repository(outside);
      fail();
    } catch (IllegalArgumentException expected) {
    }
    Files.createSymbolicLink(root.resolve("redirect"), outside);
    try {
      policy.repository(root.resolve("redirect"));
      fail();
    } catch (IllegalArgumentException expected) {
    }
    try {
      new PathPolicy(Arrays.asList(root), root.resolve("reports")).repository(root);
      fail();
    } catch (IllegalArgumentException expected) {
    }
    Files.createSymbolicLink(output.resolve("link"), outside);
    try {
      new PathPolicy(Arrays.asList(root), output.resolve("link/reports"));
      fail();
    } catch (IOException expected) {
    }
  }

  @Test
  public void inventoryReadsOnlyProductionCodeAndSelectedConfiguration() throws Exception {
    Path root = folder("source");
    Files.createDirectories(root.resolve("src/main/java"));
    Files.createDirectories(root.resolve("src/test/java"));
    Files.createDirectories(root.resolve(".venv/lib"));
    Files.createDirectories(root.resolve("data"));
    Files.write(
        root.resolve("src/main/java/A.java"), "class A {}".getBytes(StandardCharsets.UTF_8));
    Files.write(
        root.resolve("src/test/java/Test.java"), "not parsed".getBytes(StandardCharsets.UTF_8));
    Files.write(
        root.resolve("app.py"), "from openai import OpenAI\n".getBytes(StandardCharsets.UTF_8));
    Files.write(
        root.resolve(".venv/lib/dependency.py"), "not parsed".getBytes(StandardCharsets.UTF_8));
    Files.write(root.resolve("application.yml"), "spring: {}".getBytes(StandardCharsets.UTF_8));
    Files.write(root.resolve("data/private.db"), new byte[] {0, 1, 2});
    Inventory inventory = Inventory.load(root, NEVER);
    assertEquals(1, inventory.javaFiles);
    assertEquals(1, inventory.python.size());
    assertEquals(1, inventory.configurationFiles);
    assertEquals(64, inventory.digest.length());
    assertTrue(hasDiagnostic(inventory.diagnostics, "EXCLUDED_SCOPE"));
  }

  @Test
  public void inventorySkipsSymlinksOversizeAndInvalidEncoding() throws Exception {
    Path root = folder("source2");
    Files.write(root.resolve("Huge.java"), new byte[2 * 1024 * 1024 + 1]);
    Files.write(root.resolve("Bad.java"), new byte[] {(byte) 0xff});
    Path other = temporary.newFile("external.java").toPath();
    Files.write(other, "class Secret {}".getBytes(StandardCharsets.UTF_8));
    Files.createSymbolicLink(root.resolve("Link.java"), other);
    Inventory inventory = Inventory.load(root, NEVER);
    assertEquals(0, inventory.javaFiles);
    assertTrue(hasDiagnostic(inventory.diagnostics, "SOURCE_BYTE_LIMIT"));
    assertTrue(hasDiagnostic(inventory.diagnostics, "ENCODING_ERROR"));
    assertTrue(hasDiagnostic(inventory.diagnostics, "SYMLINK_SKIPPED"));
  }

  @Test
  public void inventoryRecognizesVirtualEnvironmentByMarkerInsteadOfDirectoryName()
      throws Exception {
    Path root = folder("python-env");
    Files.createDirectories(root.resolve("arbitrary-runtime/lib"));
    Files.write(root.resolve("arbitrary-runtime/pyvenv.cfg"), new byte[0]);
    Files.write(
        root.resolve("arbitrary-runtime/lib/dependency.py"),
        "excluded".getBytes(StandardCharsets.UTF_8));
    Files.createDirectories(root.resolve("legacy/lib/site-packages"));
    Files.write(
        root.resolve("legacy/lib/site-packages/dependency.py"),
        "excluded".getBytes(StandardCharsets.UTF_8));
    Files.write(root.resolve("production.py"), "value = 1\n".getBytes(StandardCharsets.UTF_8));
    Inventory inventory = Inventory.load(root, NEVER);
    assertEquals(1, inventory.python.size());
    assertEquals("production.py", inventory.python.get(0).path);
    assertTrue(hasDiagnostic(inventory.diagnostics, "EXCLUDED_SCOPE"));
  }

  @Test
  public void inventoryCancellationPropagates() throws Exception {
    try {
      Inventory.load(
          folder("cancel"),
          new Cancel() {
            public void check() {
              throw new CancellationException();
            }
          });
      fail();
    } catch (CancellationException expected) {
    }
  }

  @Test
  public void reportsReopenAllFormatsAndNeverOverwriteOrCopySourceValues() throws Exception {
    Path output = folder("output");
    Map<String, Object> report = report("fixture");
    Map<String, String> docs = Reports.write(report, output);
    for (String format : Arrays.asList("json", "markdown", "sarif")) {
      assertEquals(
          docs.get(format),
          new String(
              Files.readAllBytes(output.resolve(Reports.fileName(format))),
              StandardCharsets.UTF_8));
      assertFalse(docs.get(format).contains("DO_NOT_EXPORT_SOURCE_SECRET"));
    }
    assertEquals(
        1,
        Json.parse(docs.get("sarif"))
            .getAsJsonObject()
            .getAsJsonArray("runs")
            .get(0)
            .getAsJsonObject()
            .getAsJsonArray("results")
            .size());
    assertTrue(docs.get("markdown").contains("UNKNOWN"));
    assertFalse(docs.get("markdown").contains("<script>"));
    try {
      Reports.write(report, output);
      fail();
    } catch (IOException expected) {
    }
  }

  @Test
  public void serviceCompletesAndTerminalCancellationIsImmutable() throws Exception {
    Path root = folder("jobs"), output = folder("jobs-out");
    ScanService service =
        new ScanService(
            Arrays.asList(root),
            output,
            new ScanService.Task() {
              public Map<String, Object> scan(Path path, String id, Cancel cancel) {
                return report(id);
              }
            },
            3000,
            1);
    try {
      String id = (String) service.start(root).get("scanId");
      Map<String, Object> state = waitFor(service, id);
      assertEquals("COMPLETED", state.get("state"));
      assertEquals(state, service.cancel(id));
      assertEquals(false, service.result(id, "json").get("contentOmitted"));
      try {
        service.start(root);
        fail();
      } catch (IllegalStateException expected) {
        assertEquals("SESSION_SCAN_LIMIT", expected.getMessage());
      }
    } finally {
      service.close();
    }
  }

  @Test
  public void serviceCancellationAndTimeoutAreDistinct() throws Exception {
    Path root = folder("slow"), output = folder("slow-out");
    ScanService.Task task =
        new ScanService.Task() {
          public Map<String, Object> scan(Path path, String id, Cancel cancel) throws Exception {
            while (true) {
              cancel.check();
              Thread.sleep(2);
            }
          }
        };
    ScanService service = new ScanService(Arrays.asList(root), output, task, 3000, 32);
    try {
      String id = (String) service.start(root).get("scanId");
      assertEquals("CANCELLED", service.cancel(id).get("state"));
      assertEquals("CANCELLED", waitFor(service, id).get("state"));
      try {
        service.result(id, "json");
        fail();
      } catch (IllegalStateException expected) {
      }
    } finally {
      service.close();
    }
    ScanService timed = new ScanService(Arrays.asList(root), output, task, 10, 32);
    try {
      String id = (String) timed.start(root).get("scanId");
      Map<String, Object> state = waitFor(timed, id);
      assertEquals("FAILED", state.get("state"));
      assertEquals("SCAN_TIMEOUT", state.get("error"));
    } finally {
      timed.close();
    }
  }

  @Test
  public void workerErrorCannotLeaveAnOrphanedRunningJob() throws Exception {
    Path root = folder("worker-error"), output = folder("worker-error-out");
    ScanService service =
        new ScanService(
            Arrays.asList(root),
            output,
            new ScanService.Task() {
              public Map<String, Object> scan(Path path, String id, Cancel cancel) {
                throw new AssertionError("fixture worker failure");
              }
            },
            100,
            32);
    try {
      String id = (String) service.start(root).get("scanId");
      Map<String, Object> state = waitFor(service, id);
      assertEquals("FAILED", state.get("state"));
      assertEquals("SCAN_FAILED", state.get("error"));
      assertEquals(state, service.cancel(id));
    } finally {
      service.close();
    }
  }

  @Test
  public void mcpHandshakeDiscoveryInvalidToolInputAndEof() throws Exception {
    Path root = folder("mcp"), output = folder("mcp-out");
    String input =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}\n"
            + "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n"
            + "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"
            + "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"guardrail_scan_start\",\"arguments\":{\"repository\":42}}}\n";
    ByteArrayOutputStream result = new ByteArrayOutputStream();
    new McpHost(new ScanService(Arrays.asList(root), output))
        .run(new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)), result);
    String[] lines = new String(result.toByteArray(), StandardCharsets.UTF_8).trim().split("\n");
    assertEquals(3, lines.length);
    assertEquals(
        "0.7.0",
        Json.parse(lines[0])
            .getAsJsonObject()
            .getAsJsonObject("result")
            .getAsJsonObject("serverInfo")
            .get("version")
            .getAsString());
    assertEquals(
        5,
        Json.parse(lines[1])
            .getAsJsonObject()
            .getAsJsonObject("result")
            .getAsJsonArray("tools")
            .size());
    assertTrue(
        Json.parse(lines[2])
            .getAsJsonObject()
            .getAsJsonObject("result")
            .get("isError")
            .getAsBoolean());
  }

  @Test
  public void mcpRejectsOversizedFrames() throws Exception {
    Path root = folder("bad-mcp"), output = folder("bad-mcp-out");
    try {
      new McpHost(new ScanService(Arrays.asList(root), output))
          .run(new ByteArrayInputStream(new byte[1024 * 1024 + 1]), new ByteArrayOutputStream());
      fail();
    } catch (IOException expected) {
      assertEquals("MCP_FRAME_LIMIT", expected.getMessage());
    }
  }

  @Test
  public void mcpRecoversFromParseAndEnvelopeErrorsWithoutLosingInitialization() throws Exception {
    Path root = folder("recover-mcp"), output = folder("recover-mcp-out");
    String initialize =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}\n";
    String[] invalid = {
      "{bad}",
      "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":42}",
      "{\"jsonrpc\":\"1.0\",\"id\":2,\"method\":\"ping\"}",
      "{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"ping\"}",
      "{\"jsonrpc\":\"2.0\",\"id\":2}",
      "[]"
    };
    ByteArrayOutputStream input = new ByteArrayOutputStream();
    input.write(initialize.getBytes(StandardCharsets.UTF_8));
    for (String frame : invalid) input.write((frame + "\n").getBytes(StandardCharsets.UTF_8));
    input.write(new byte[] {(byte) 0xff, '\n'});
    input.write(
        ("{\"jsonrpc\":\"2.0\",\"method\":\"unknown-notification\"}\n"
                + "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}\n")
            .getBytes(StandardCharsets.UTF_8));
    ByteArrayOutputStream outputBytes = new ByteArrayOutputStream();
    new McpHost(new ScanService(Arrays.asList(root), output))
        .run(new ByteArrayInputStream(input.toByteArray()), outputBytes);
    String[] responses =
        new String(outputBytes.toByteArray(), StandardCharsets.UTF_8).trim().split("\n");
    assertEquals(9, responses.length);
    for (int i = 1; i <= 7; i++) {
      com.google.gson.JsonObject error = Json.parse(responses[i]).getAsJsonObject();
      assertTrue(error.has("id"));
      assertTrue(error.get("id").isJsonNull());
      assertEquals(
          i == 1 || i == 7 ? -32700 : -32600,
          error.getAsJsonObject("error").get("code").getAsInt());
    }
    com.google.gson.JsonObject recovered = Json.parse(responses[8]).getAsJsonObject();
    assertEquals(3, recovered.get("id").getAsInt());
    assertEquals(5, recovered.getAsJsonObject("result").getAsJsonArray("tools").size());
  }

  private static Map<String, Object> waitFor(ScanService service, String id) throws Exception {
    long deadline = System.nanoTime() + 3000000000L;
    while (System.nanoTime() < deadline) {
      Map<String, Object> state = service.status(id);
      if (!"RUNNING".equals(state.get("state"))) return state;
      Thread.sleep(5);
    }
    fail("Scan did not reach a terminal state");
    return null;
  }

  private static boolean hasDiagnostic(List<Map<String, Object>> diagnostics, String code) {
    for (Map<String, Object> item : diagnostics) if (code.equals(item.get("code"))) return true;
    return false;
  }

  static Map<String, Object> report(String id) {
    List<Map<String, Object>> findings = new ArrayList<Map<String, Object>>();
    findings.add(
        Findings.assessment(
            "X",
            "L3",
            "VIOLATED",
            "MEDIUM",
            "<script>",
            "固定描述",
            "固定建议",
            Arrays.asList(Findings.evidence("src/A #1.java", 4, "固定证据")),
            "仅静态证据"));
    findings.add(
        Findings.assessment(
            "Y",
            "L2",
            "UNKNOWN",
            "INFO",
            "未知",
            "未知",
            "补充证据",
            Collections.<Map<String, Object>>emptyList()));
    return Findings.map(
        "schemaVersion",
        "1.2",
        "ruleSetVersion",
        "test",
        "scanId",
        id,
        "createdAt",
        "fixture",
        "sourceDigest",
        "digest",
        "project",
        Findings.map(
            "languages",
            Arrays.asList("java"),
            "aiProtocols",
            Arrays.asList("test"),
            "customGatewayMethods",
            1),
        "runtime",
        Findings.map("javaVersion", System.getProperty("java.version")),
        "complete",
        false,
        "securityVerified",
        false,
        "assessments",
        findings,
        "diagnostics",
        Collections.emptyList());
  }
}
