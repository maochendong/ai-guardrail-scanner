package dev.aiguard.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aiguard.model.ScanModel.Disposition;
import dev.aiguard.report.ReportWriter;
import dev.aiguard.scan.Scanner;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class ScannerIntegrationTest {
    @TempDir Path temp;

    @Test void customProtocolRunsWithoutSpringAiAndSurvivesAllReportFormats() throws Exception {
        Path root=Files.createDirectory(temp.toRealPath().resolve("application"));
        Path source=Files.createDirectories(root.resolve("src/main/java")).resolve("Adapter.java");
        String code="""
            import okhttp3.*;
            import com.fasterxml.jackson.databind.*;
            final class Adapter {
              OkHttpClient wire; ObjectMapper mapper;
              JsonNode request(String input) throws Exception {
                Request request=new Request.Builder().url("https://example.invalid/v1/chat/completions")
                    .post(RequestBody.create(input, MediaType.parse("application/json"))).build();
                try(Response reply=wire.newCall(request).execute()) {
                  return mapper.readTree(reply.body().string());
                }
              }
            }
            """;
        Files.writeString(source,code);
        var report=new Scanner().scan(root,"integration",()->false);
        assertTrue(report.project().aiDetected());
        assertEquals(1,report.project().customGatewayMethods());
        assertEquals(java.util.List.of("openai-chat-compatible"),report.project().aiProtocols());
        assertNotEquals("SUPPORTED",report.project().versionStatus());
        assertEquals(19,report.assessments().stream().map(a->a.ruleId()).distinct().count());
        assertTrue(report.assessments().stream().anyMatch(a->a.ruleId().equals("AI-GW-001")&&a.disposition()==Disposition.OBSERVED));
        assertTrue(report.assessments().stream().anyMatch(a->a.ruleId().equals("AI-FC-001")&&a.disposition()==Disposition.UNKNOWN));
        assertFalse(report.complete());
        assertFalse(report.securityVerified());
        Path output=temp.toRealPath().resolve("report");
        new ReportWriter().write(report,output);
        var mapper=new ObjectMapper();
        var json=mapper.readTree(output.resolve("report.json").toFile());
        var sarif=mapper.readTree(output.resolve("results.sarif").toFile());
        assertEquals(json.path("project"),sarif.path("runs").get(0).path("properties").path("project"));
        assertTrue(Files.readString(output.resolve("report.md")).replace("&#45;","-").contains("openai-chat-compatible"));
        for(String name:java.util.List.of("report.json","report.md","results.sarif"))
            assertFalse(Files.readString(output.resolve(name)).contains("example.invalid"));
        assertEquals(code,Files.readString(source));
    }
}
