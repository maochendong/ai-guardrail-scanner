package dev.aiguard.scan;

import dev.aiguard.analysis.ProjectLoader;
import dev.aiguard.analysis.RuleEngine;
import dev.aiguard.analysis.LocalCallGraph;
import dev.aiguard.analysis.GatewayModel;
import dev.aiguard.analysis.CustomGuardRules;
import dev.aiguard.analysis.rules.FunctionCallingRules;
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
        var graph = LocalCallGraph.build(project, cancelled);
        var model = GatewayModel.build(project, graph, cancelled);
        var assessments = new ArrayList<>(new RuleEngine().assess(project, cancelled));
        assessments.addAll(CustomGuardRules.assess(project, graph, model, cancelled));
        assessments.addAll(FunctionCallingRules.assess(project, graph, model, cancelled));
        var allDiagnostics = new ArrayList<>(project.diagnostics());
        allDiagnostics.addAll(graph.diagnostics());
        allDiagnostics.addAll(model.diagnostics());
        var diagnostics = new ArrayList<>(allDiagnostics.subList(0, Math.min(2048, allDiagnostics.size())));
        if (allDiagnostics.size() > 2048)
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
        var original = project.metadata();
        var protocols = new java.util.TreeSet<>(original.aiProtocols());
        model.gateways().forEach(g -> protocols.add(g.protocol()));
        var metadata = new ProjectMetadata(original.springAiVersion(), original.versionStatus(), original.javaFiles(),
                original.configurationFiles(), original.aiDetected() || !model.gateways().isEmpty(),
                new ArrayList<>(protocols), model.gateways().size());
        return new Report("1.1", "java-guardrail-v2", scanId, Instant.now().toString(), project.digest(),
                metadata, complete, bounded, diagnostics);
    }
}
