package dev.aiguard;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.aiguard.analysis.RuleEngine;
import dev.aiguard.mcp.McpHost;
import dev.aiguard.mcp.ScanService;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class Main {
    private Main() {}
    public static void main(String[] args) { System.exit(run(args)); }
    static int run(String[] args) {
        try {
            if (args.length == 0 || args[0].equals("--help") || args[0].equals("help")) {
                System.out.println("""
                        AI Guardrail Scanner 0.1.0 (Java 21)
                        scan /absolute/repository --output /absolute/report-root
                        mcp --allow-root /absolute/projects [--allow-root /another/root] --output /absolute/report-root
                        rules
                        Exit: 0 complete assessment, 1 violations, 2 incomplete/failed, 130 cancelled.
                        OBSERVED is an observation, never a certification. No target code is executed.
                        """);
                return 0;
            }
            if (args[0].equals("rules")) {
                if (args.length != 1) throw new IllegalArgumentException("rules accepts no options.");
                System.out.println(new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(new RuleEngine().catalog()));
                return 0;
            }
            boolean mcp = args[0].equals("mcp");
            if (!mcp && !args[0].equals("scan")) throw new IllegalArgumentException("Unknown command; use --help.");
            Path repository = null, output = null;
            var roots = new ArrayList<Path>();
            int position = 1;
            if (!mcp) {
                if (args.length < 2 || args[1].startsWith("--")) throw new IllegalArgumentException("scan requires a repository.");
                repository = Path.of(args[1]).toAbsolutePath().normalize(); roots.add(repository); position = 2;
            }
            for (int i = position; i < args.length; i += 2) {
                if (i + 1 >= args.length) throw new IllegalArgumentException("Option requires a value.");
                if (args[i].equals("--output") && output == null) output = Path.of(args[i + 1]).toAbsolutePath().normalize();
                else if (mcp && args[i].equals("--allow-root")) roots.add(Path.of(args[i + 1]));
                else throw new IllegalArgumentException("Unknown or duplicate option.");
            }
            if (output == null || roots.isEmpty()) throw new IllegalArgumentException("Explicit output and allowed roots are required.");
            try (var service = new ScanService(roots, output)) {
                if (mcp) { new McpHost(service).run(); return 0; }
                var status = service.start(repository);
                System.out.println("scanId=" + status.scanId());
                while (status.state() == ScanService.State.RUNNING) {
                    Thread.sleep(50); status = service.status(status.scanId());
                }
                if (status.state() == ScanService.State.CANCELLED) return 130;
                if (status.state() == ScanService.State.FAILED) { System.err.println(status.error()); return 2; }
                System.out.println(new ObjectMapper().writeValueAsString(service.result(status.scanId(), "json").get("artifacts")));
                System.out.printf("violations=%d unknown=%d complete=%s%n", status.violations(), status.unknowns(), status.coverageComplete());
                return status.violations() > 0 ? 1 : status.coverageComplete() ? 0 : 2;
            }
        } catch (InterruptedException e) { Thread.currentThread().interrupt(); return 130; }
        catch (Exception e) { System.err.println("Unable to run: check arguments, Java version, repository and output access. Use --help."); return 2; }
    }
}
