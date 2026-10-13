package dev.aiguard.scan;

import dev.aiguard.analysis.ProjectLoader;
import dev.aiguard.analysis.RuleEngine;
import dev.aiguard.model.ScanModel.*;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

public final class Scanner {
    public Report scan(Path root, String scanId, BooleanSupplier cancelled) throws IOException {
        var project = new ProjectLoader().load(root, cancelled);
        if (cancelled.getAsBoolean()) throw new CancellationException();
        var assessments = new RuleEngine().assess(project, cancelled);
        var diagnostics = new ArrayList<>(project.diagnostics().subList(0, Math.min(2048, project.diagnostics().size())));
        if (project.diagnostics().size() > 2048)
            diagnostics.add(new Diagnostic("DIAGNOSTIC_LIMIT", "", "Only the first 2048 inventory diagnostics are retained; coverage is incomplete."));
        var bounded = new ArrayList<Assessment>();
        boolean truncated = assessments.size() > 1000;
        for (var a : assessments.subList(0, Math.min(1000, assessments.size()))) {
            truncated |= a.evidence().size() > 16;
            bounded.add(new Assessment(a.ruleId(), a.domain(), a.disposition(), a.severity(), a.title(),
                    a.explanation(), a.recommendation(), a.evidence().subList(0, Math.min(16, a.evidence().size())),
                    a.limitations()));
        }
        if (truncated) diagnostics.add(new Diagnostic("RESULT_LIMIT", "", "Evidence was bounded to 1000 assessments and 16 locations per assessment."));
        if (project.sources().isEmpty()) diagnostics.add(new Diagnostic("NO_JAVA_SOURCE", "", "No supported production Java source was analyzed."));
        boolean complete = diagnostics.stream().allMatch(d -> d.code().equals("EXCLUDED_SCOPE"))
                && bounded.stream().noneMatch(a -> a.disposition() == Disposition.UNKNOWN);
        return new Report("1.0", "java-spring-v1", scanId, Instant.now().toString(), project.digest(),
                project.metadata(), complete, bounded, diagnostics);
    }
}
