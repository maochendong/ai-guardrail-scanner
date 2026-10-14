package dev.aiguard.model;

import java.util.List;

/** Evidence, not security certification. Never put raw source or secrets in these records. */
public final class ScanModel {
    private ScanModel() {}
    public enum Domain { L1, L2, L3, L4, L5, L6, L7 }
    public enum Disposition { VIOLATED, OBSERVED, UNKNOWN, NOT_APPLICABLE }
    public enum Severity { HIGH, MEDIUM, LOW, INFO }
    public record Evidence(String path, int line, String detail) {}
    public record Diagnostic(String code, String path, String message) {}
    public record Rule(String id, Domain domain, String title, String description,
                       String recommendation, List<String> references) {}
    public record Assessment(String ruleId, Domain domain, Disposition disposition, Severity severity,
                             String title, String explanation, String recommendation,
                             List<Evidence> evidence, List<String> limitations) {
        public Assessment { evidence = List.copyOf(evidence); limitations = List.copyOf(limitations); }
    }
    public record ProjectMetadata(String springAiVersion, String versionStatus,
                                  int javaFiles, int configurationFiles, boolean aiDetected,
                                  List<String> aiProtocols, int customGatewayMethods) {
        public ProjectMetadata { aiProtocols = List.copyOf(aiProtocols); }
        public ProjectMetadata(String springAiVersion, String versionStatus, int javaFiles, int configurationFiles, boolean aiDetected) {
            this(springAiVersion,versionStatus,javaFiles,configurationFiles,aiDetected,
                    aiDetected ? List.of("spring-ai") : List.of(),0);
        }
    }
    public record Report(String schemaVersion, String ruleSetVersion, String scanId, String createdAt,
                         String sourceDigest, ProjectMetadata project, boolean complete,
                         List<Assessment> assessments, List<Diagnostic> diagnostics) {
        public Report { assessments = List.copyOf(assessments); diagnostics = List.copyOf(diagnostics); }
        @com.fasterxml.jackson.annotation.JsonProperty("securityVerified")
        public boolean securityVerified() { return false; }
        @com.fasterxml.jackson.annotation.JsonProperty("analysisScope")
        public String analysisScope() { return "bounded static source/configuration and local inter-method evidence; no runtime or model effectiveness verification"; }
        public long violations() { return assessments.stream().filter(a -> a.disposition() == Disposition.VIOLATED).count(); }
        public long unknowns() { return assessments.stream().filter(a -> a.disposition() == Disposition.UNKNOWN).count(); }
    }
}
