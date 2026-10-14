package dev.aiguard.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aiguard.model.ScanModel;
import dev.aiguard.model.ScanModel.Assessment;
import dev.aiguard.model.ScanModel.Disposition;
import dev.aiguard.model.ScanModel.Domain;
import dev.aiguard.model.ScanModel.Evidence;
import dev.aiguard.model.ScanModel.Report;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Exports controlled evidence records. This class never opens a source file. */
public final class ReportWriter {
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * The destination must be new or empty, beneath an operator-owned directory.
     * Each file is published atomically without replacing an existing file.
     * A failed export may leave already-published files; it is never a completed scan.
     */
    public void write(Report report, Path directory) throws IOException {
        Path target = directory.toAbsolutePath().normalize();
        prepareDirectory(target);
        byte[] json = mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report);
        byte[] markdown = markdown(report).getBytes(StandardCharsets.UTF_8);
        byte[] sarif = mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(sarif(report));
        publish(target, "report.json", json);
        publish(target, "report.md", markdown);
        publish(target, "results.sarif", sarif);
    }

    private static void prepareDirectory(Path directory) throws IOException {
        Path current = directory.getRoot();
        for (Path component : directory) {
            current = current.resolve(component);
            if (Files.isSymbolicLink(current)) {
                throw new IOException("Report directory must not contain symbolic links");
            }
            if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectory(current);
            }
            if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Report destination is not a directory");
            }
        }
        try (var entries = Files.list(directory)) {
            if (entries.findAny().isPresent()) {
                throw new IOException("Report directory must be empty; existing data will not be overwritten");
            }
        }
    }

    private static void publish(Path directory, String name, byte[] content) throws IOException {
        if (Files.isSymbolicLink(directory)) {
            throw new IOException("Report directory must not be a symbolic link");
        }
        Path temporary = Files.createTempFile(directory, ".guardrail-", ".tmp");
        try {
            Files.write(temporary, content);
            // Hard-link publication fails if the destination exists, unlike ATOMIC_MOVE,
            // whose replacement semantics are provider dependent. Both files share a filesystem.
            Files.createLink(directory.resolve(name), temporary);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static String markdown(Report report) {
        StringBuilder out = new StringBuilder("# AI 安全围栏静态审计\n\n");
        out.append("本报告提供静态证据，不构成安全认证。OBSERVED 仅表示观察到控制或构造，不能解释为安全通过。\n\n");
        out.append("- 扫描 ID：").append(escape(report.scanId())).append('\n');
        out.append("- 创建时间：").append(escape(report.createdAt())).append('\n');
        out.append("- 规则版本：").append(escape(report.ruleSetVersion())).append('\n');
        out.append("- 源文件摘要：").append(escape(report.sourceDigest())).append('\n');
        out.append("- Spring AI 版本：").append(escape(report.project().springAiVersion()))
                .append("（").append(escape(report.project().versionStatus())).append("）\n");
        out.append("- AI 协议证据：").append(escape(String.join("、", report.project().aiProtocols())))
                .append("；自定义网关边界方法：").append(report.project().customGatewayMethods()).append('\n');
        out.append("- 分析完整性：").append(report.complete() ? "完整" : "**不完整，必须检查诊断与未评估项**").append('\n');
        out.append("- 发现违反：").append(report.violations()).append("；证据不足 / 未评估：")
                .append(report.unknowns()).append("。\n\n");
        out.append("## 控制域覆盖\n\n");
        out.append("| 控制域 | VIOLATED 违反 | OBSERVED 已观察 | UNKNOWN 证据不足 | NOT_APPLICABLE 不适用 |\n");
        out.append("| --- | ---: | ---: | ---: | ---: |\n");
        for (Domain domain : Domain.values()) {
            out.append("| ").append(domain).append(' ').append(domainName(domain));
            for (Disposition disposition : Disposition.values()) {
                out.append(" | ").append(count(report, domain, disposition));
            }
            out.append(" |\n");
        }
        out.append("\n## 未评估与分析限制\n\n");
        out.append("以下限制会影响结论；零条违规不表示应用安全。外部网关、动态注册、反射、AOP、依赖源码与生产策略的效果可能无法从当前输入确定。\n\n");
        List<String> unassessed = unassessedDomains(report);
        if (!unassessed.isEmpty()) out.append("- **未产生评估的控制域**：").append(String.join("、", unassessed)).append("。\n");
        for (Assessment assessment : report.assessments()) {
            if (assessment.disposition() == Disposition.UNKNOWN) {
                out.append("- **UNKNOWN** ").append(escape(assessment.ruleId())).append("：")
                        .append(escape(assessment.explanation())).append('\n');
            }
            for (String limitation : assessment.limitations()) {
                out.append("- ").append(escape(assessment.ruleId())).append("：")
                        .append(escape(limitation)).append('\n');
            }
        }
        if (report.unknowns() == 0 && report.assessments().stream().allMatch(a -> a.limitations().isEmpty())) {
            out.append("- 规则未记录额外限制；静态扫描的通用边界仍然适用。\n");
        }
        out.append("\n## 分析诊断\n\n");
        if (report.diagnostics().isEmpty()) out.append("无记录。\n");
        for (ScanModel.Diagnostic diagnostic : report.diagnostics()) {
            out.append("- ").append(escape(diagnostic.code())).append("：")
                    .append(escape(diagnostic.path())).append(" ")
                    .append(escape(diagnostic.message())).append('\n');
        }
        out.append("\n## 规则证据\n\n");
        for (Assessment assessment : report.assessments()) {
            out.append("### ").append(escape(assessment.ruleId())).append(" · ")
                    .append(escape(assessment.title())).append("\n\n");
            out.append("状态：").append(assessment.disposition()).append("；严重度：")
                    .append(assessment.severity()).append("；控制域：").append(assessment.domain()).append("。\n\n");
            out.append(escape(assessment.explanation())).append("\n\n");
            out.append("建议：").append(escape(assessment.recommendation())).append("\n\n");
            for (Evidence evidence : assessment.evidence()) {
                out.append("- ").append(escape(evidence.path())).append(" 第 ")
                        .append(Math.max(1, evidence.line())).append(" 行：")
                        .append(escape(evidence.detail())).append('\n');
            }
            out.append('\n');
        }
        return out.toString();
    }

    private static Map<String, Object> sarif(Report report) {
        Map<String, Integer> indexes = new LinkedHashMap<>();
        List<Map<String, Object>> rules = new ArrayList<>();
        List<Map<String, Object>> results = new ArrayList<>();
        for (Assessment assessment : report.assessments()) {
            if (!indexes.containsKey(assessment.ruleId())) {
                indexes.put(assessment.ruleId(), rules.size());
                rules.add(Map.of("id", assessment.ruleId(),
                        "shortDescription", Map.of("text", assessment.title()),
                        "fullDescription", Map.of("text", assessment.explanation()),
                        "help", Map.of("text", assessment.recommendation()),
                        "properties", Map.of("domain", assessment.domain().name())));
            }
            if (assessment.disposition() != Disposition.VIOLATED) continue;
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("ruleId", assessment.ruleId());
            result.put("ruleIndex", indexes.get(assessment.ruleId()));
            result.put("level", switch (assessment.severity()) {
                case HIGH -> "error";
                case MEDIUM, LOW -> "warning";
                case INFO -> "note";
            });
            result.put("message", Map.of("text", assessment.explanation()));
            List<Map<String, Object>> locations = new ArrayList<>();
            for (Evidence evidence : assessment.evidence()) {
                String uri = relativeUri(evidence.path());
                if (uri != null) {
                    locations.add(Map.of("physicalLocation", Map.of(
                            "artifactLocation", Map.of("uri", uri),
                            "region", Map.of("startLine", Math.max(1, evidence.line()))),
                            "message", Map.of("text", evidence.detail())));
                }
            }
            if (!locations.isEmpty()) result.put("locations", locations);
            result.put("properties", Map.of("domain", assessment.domain().name(),
                    "disposition", assessment.disposition().name(), "limitations", assessment.limitations(),
                    "omittedLocations", assessment.evidence().size() - locations.size()));
            results.add(result);
        }
        List<Map<String, Object>> notifications = report.diagnostics().stream().map(d -> Map.<String, Object>of(
                "descriptor", Map.of("id", d.code()), "level", "warning",
                "message", Map.of("text", d.message()), "properties", Map.of("path", d.path()))).toList();
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("scanId", report.scanId());
        properties.put("sourceDigest", report.sourceDigest());
        properties.put("project", report.project());
        properties.put("analysisComplete", report.complete());
        properties.put("unknownAssessments", report.unknowns());
        properties.put("controlEvaluationComplete", report.complete() && report.unknowns() == 0 && unassessedDomains(report).isEmpty());
        properties.put("unassessedDomains", unassessedDomains(report));
        properties.put("securityVerified", false);
        properties.put("coverage", coverage(report));
        properties.put("assessmentStates", report.assessments().stream().map(a -> Map.of(
                "ruleId", a.ruleId(), "disposition", a.disposition().name(), "limitations", a.limitations())).toList());
        Map<String, Object> run = Map.of(
                "tool", Map.of("driver", Map.of("name", "AI Guardrail Scanner", "version", report.ruleSetVersion(), "rules", rules)),
                "invocations", List.of(Map.of("executionSuccessful", report.complete(), "toolExecutionNotifications", notifications)),
                "results", results, "properties", properties);
        return Map.of("$schema", "https://json.schemastore.org/sarif-2.1.0.json", "version", "2.1.0", "runs", List.of(run));
    }

    private static Map<String, Object> coverage(Report report) {
        Map<String, Object> domains = new LinkedHashMap<>();
        for (Domain domain : Domain.values()) {
            Map<String, Long> counts = new LinkedHashMap<>();
            for (Disposition disposition : Disposition.values()) counts.put(disposition.name(), count(report, domain, disposition));
            domains.put(domain.name(), counts);
        }
        return domains;
    }

    private static long count(Report report, Domain domain, Disposition disposition) {
        return report.assessments().stream().filter(a -> a.domain() == domain && a.disposition() == disposition).count();
    }

    private static List<String> unassessedDomains(Report report) {
        List<String> missing = new ArrayList<>();
        for (Domain domain : Domain.values()) {
            if (report.assessments().stream().noneMatch(a -> a.domain() == domain)) missing.add(domain.name());
        }
        return missing;
    }

    private static String relativeUri(String path) {
        if (path == null || path.isBlank() || path.startsWith("/") || path.startsWith("\\") || path.matches("^[a-zA-Z]:.*")) return null;
        for (String part : path.replace('\\', '/').split("/")) if (part.equals("..")) return null;
        try {
            // Prefix avoids a colon in a filename being interpreted as a URI scheme.
            String value = path.indexOf(':') >= 0 ? "./" + path : path;
            return new URI(null, null, value, null).toASCIIString();
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private static String escape(String value) {
        if (value == null) return "未确定";
        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isISOControl(c) || (c >= '\u202a' && c <= '\u202e') || (c >= '\u2066' && c <= '\u2069')) {
                escaped.append(' ');
            } else if ((c >= '!' && c <= '/') || (c >= ':' && c <= '@')
                    || (c >= '[' && c <= '`') || (c >= '{' && c <= '~')) {
                escaped.append("&#").append((int) c).append(';');
            } else {
                escaped.append(c);
            }
        }
        return escaped.toString();
    }

    private static String domainName(Domain domain) {
        return switch (domain) {
            case L1 -> "提示注入";
            case L2 -> "授权与隔离";
            case L3 -> "数据泄露";
            case L4 -> "资源限制";
            case L5 -> "内容审核";
            case L6 -> "审计追踪";
            case L7 -> "输出与执行安全";
        };
    }
}
