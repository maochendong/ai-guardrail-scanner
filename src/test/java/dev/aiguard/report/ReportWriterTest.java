package dev.aiguard.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aiguard.model.ScanModel.*;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class ReportWriterTest {
    @TempDir Path temp;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ReportWriter writer = new ReportWriter();

    @Test void reopensAllFormatsAndKeepsUnknownSeparateFromViolations() throws Exception {
        Path output = temp.toRealPath().resolve("scan");
        Report report = report(false, List.of(
                assessment("AI-L1-001", Domain.L1, Disposition.VIOLATED, "应用/src/A #100%.java", 0),
                assessment("AI-L1-001", Domain.L1, Disposition.VIOLATED, "src/B.java", 14),
                assessment("AI-L2-001", Domain.L2, Disposition.UNKNOWN, "src/Tool.java", 3),
                assessment("AI-L6-001", Domain.L6, Disposition.OBSERVED, "src/Audit.java", 2),
                assessment("AI-L7-001", Domain.L7, Disposition.NOT_APPLICABLE, "", 1)));
        writer.write(report, output);

        JsonNode json = mapper.readTree(output.resolve("report.json").toFile());
        assertEquals(5, json.path("assessments").size());
        assertFalse(json.path("complete").asBoolean());
        assertEquals("UNKNOWN", json.path("assessments").get(2).path("disposition").asText());
        String markdown = Files.readString(output.resolve("report.md"));
        assertTrue(markdown.contains("**不完整"));
        assertTrue(markdown.contains("证据不足 / 未评估：1"));
        assertTrue(markdown.contains("| L1 提示注入 | 2 | 0 | 0 | 0 |"));
        for (Domain domain : Domain.values()) assertTrue(markdown.contains("| " + domain + " "));

        JsonNode run = mapper.readTree(output.resolve("results.sarif").toFile()).path("runs").get(0);
        assertEquals(2, run.path("results").size());
        assertEquals(4, run.path("tool").path("driver").path("rules").size());
        assertEquals(0, run.path("results").get(1).path("ruleIndex").asInt());
        assertFalse(run.path("invocations").get(0).path("executionSuccessful").asBoolean());
        assertFalse(run.path("properties").path("controlEvaluationComplete").asBoolean());
        assertFalse(run.path("properties").path("securityVerified").asBoolean());
        assertEquals(1, run.path("properties").path("unknownAssessments").asInt());
        assertEquals(7, run.path("properties").path("coverage").size());
        JsonNode location = run.path("results").get(0).path("locations").get(0).path("physicalLocation");
        URI uri = URI.create(location.path("artifactLocation").path("uri").asText());
        assertFalse(uri.isAbsolute());
        assertEquals("应用/src/A #100%.java", uri.getPath());
        assertNull(uri.getFragment());
        assertEquals(1, location.path("region").path("startLine").asInt());
        try (var files = Files.list(output)) { assertEquals(3, files.count()); }
    }

    @Test void completeExecutionCanStillHaveUnknownCoverageAndNoSarifFindings() throws Exception {
        Path output = temp.toRealPath().resolve("unknown");
        writer.write(report(true, List.of(assessment("AI-L2-001", Domain.L2,
                Disposition.UNKNOWN, "src/Tool.java", 1))), output);
        JsonNode run = mapper.readTree(output.resolve("results.sarif").toFile()).path("runs").get(0);
        assertTrue(run.path("invocations").get(0).path("executionSuccessful").asBoolean());
        assertEquals(0, run.path("results").size());
        assertFalse(run.path("properties").path("controlEvaluationComplete").asBoolean());
    }

    @Test void escapesMarkdownAndNeverReadsSourceOrExportsItsSecrets() throws Exception {
        Path root = temp.toRealPath();
        String secret = "fixture-secret-never-read-818a74";
        Path source = root.resolve("Sensitive.java");
        Files.writeString(source, "String token = \"" + secret + "\";");
        String untrusted = "[open](https://example.invalid) <script>bad()</script> `x` |\n# heading www.example.invalid a@example.invalid";
        Assessment a = new Assessment("AI-L1-001", Domain.L1, Disposition.VIOLATED, Severity.HIGH,
                untrusted, untrusted, untrusted, List.of(new Evidence("Sensitive.java", 1, "受控证据描述")), List.of(untrusted));
        Path output = root.resolve("escaped");
        writer.write(report(true, List.of(a)), output);
        String markdown = Files.readString(output.resolve("report.md"));
        assertFalse(markdown.contains("[open]"));
        assertFalse(markdown.contains("<script>"));
        assertFalse(markdown.contains("https://"));
        assertFalse(markdown.contains("www.example.invalid"));
        assertFalse(markdown.contains("a@example.invalid"));
        assertFalse(markdown.contains("\n# heading"));
        assertTrue(markdown.contains("&#60;script&#62;"));
        for (String name : List.of("report.json", "report.md", "results.sarif")) {
            String artifact = Files.readString(output.resolve(name));
            assertFalse(artifact.contains(secret));
            assertFalse(artifact.contains("String token"));
        }
        JsonNode sarif = mapper.readTree(output.resolve("results.sarif").toFile());
        assertFalse(sarif.toString().contains("\"snippet\""));
    }

    @Test void omitsUnsafeSarifLocationsInsteadOfEmittingAbsoluteOrEscapingUris() throws Exception {
        Path output = temp.toRealPath().resolve("paths");
        Assessment a = new Assessment("AI-L1-001", Domain.L1, Disposition.VIOLATED, Severity.HIGH,
                "位置", "说明", "建议", List.of(new Evidence("/private/secret.java", 1, "说明"),
                new Evidence("../outside.java", 1, "说明"), new Evidence("C:\\repo\\A.java", 1, "说明"),
                new Evidence("name:part.java", 4, "说明")), List.of());
        writer.write(report(true, List.of(a)), output);
        JsonNode result = mapper.readTree(output.resolve("results.sarif").toFile()).path("runs").get(0).path("results").get(0);
        assertEquals(3, result.path("properties").path("omittedLocations").asInt());
        assertEquals(1, result.path("locations").size());
        URI uri = URI.create(result.path("locations").get(0).path("physicalLocation").path("artifactLocation").path("uri").asText());
        assertFalse(uri.isAbsolute());
        assertEquals("./name:part.java", uri.getPath());
    }

    @Test void allowsAnExistingEmptyDirectoryButNeverOverwritesAnyExistingData() throws Exception {
        Path output = Files.createDirectory(temp.toRealPath().resolve("empty"));
        Report report = report(true, List.of());
        writer.write(report, output);
        byte[] original = Files.readAllBytes(output.resolve("report.json"));
        JsonNode run = mapper.readTree(output.resolve("results.sarif").toFile()).path("runs").get(0);
        assertFalse(run.path("properties").path("controlEvaluationComplete").asBoolean());
        assertEquals(7, run.path("properties").path("unassessedDomains").size());
        assertThrows(IOException.class, () -> writer.write(report, output));
        assertArrayEquals(original, Files.readAllBytes(output.resolve("report.json")));
        Path other = Files.createDirectory(temp.toRealPath().resolve("nonempty"));
        Files.writeString(other.resolve("keep.txt"), "keep");
        assertThrows(IOException.class, () -> writer.write(report, other));
        assertFalse(Files.exists(other.resolve("report.json")));
        assertEquals("keep", Files.readString(other.resolve("keep.txt")));
    }

    @Test void rejectsSymbolicLinkDestinationAncestorAndPreexistingArtifactLink() throws Exception {
        Path root = temp.toRealPath();
        Path real = Files.createDirectory(root.resolve("real"));
        Path link = Files.createSymbolicLink(root.resolve("link"), real);
        Report report = report(true, List.of());
        assertThrows(IOException.class, () -> writer.write(report, link));
        assertThrows(IOException.class, () -> writer.write(report, link.resolve("scan")));
        Path outside = root.resolve("outside.txt");
        Files.writeString(outside, "untouched");
        Files.createSymbolicLink(real.resolve("report.json"), outside);
        assertThrows(IOException.class, () -> writer.write(report, real));
        assertEquals("untouched", Files.readString(outside));
        assertFalse(Files.exists(real.resolve("results.sarif")));
    }

    private static Assessment assessment(String id, Domain domain, Disposition disposition, String path, int line) {
        return new Assessment(id, domain, disposition, Severity.HIGH, "控制检查", "固定说明", "固定建议",
                List.of(new Evidence(path, line, "固定证据")), List.of("仅静态证据，外部控制待确认"));
    }

    private static Report report(boolean complete, List<Assessment> assessments) {
        return new Report("1.0", "0.1.0", "scan-test", "2026-10-13T12:00:00Z", "digest",
                new ProjectMetadata("1.1.6", "SUPPORTED", 4, 1, true), complete, assessments,
                complete ? List.of() : List.of(new Diagnostic("PARSE_ERROR", "src/Broken.java", "解析未完成")));
    }
}
