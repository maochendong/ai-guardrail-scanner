package dev.aiguard.analysis;

import com.github.javaparser.ast.CompilationUnit;
import dev.aiguard.model.ScanModel.Diagnostic;
import dev.aiguard.model.ScanModel.ProjectMetadata;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record SourceProject(Path root, List<JavaSource> sources, Map<String, String> configurations,
                            ProjectMetadata metadata, String digest, List<Diagnostic> diagnostics) {
    public SourceProject {
        sources = List.copyOf(sources); configurations = Map.copyOf(configurations);
        diagnostics = List.copyOf(diagnostics);
    }
    public record JavaSource(String path, CompilationUnit unit) {}
    public boolean supportedVersion() { return "SUPPORTED".equals(metadata.versionStatus()); }
}
