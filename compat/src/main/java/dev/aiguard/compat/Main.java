package dev.aiguard.compat;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public final class Main {
  private Main() {}

  public static void main(String[] args) {
    try {
      System.exit(run(args));
    } catch (Exception error) {
      System.err.println(
          "SCANNER_FAILED: input, protocol, scope or output unavailable; no source values are"
              + " included.");
      System.exit(2);
    }
  }

  private static int run(String[] args) throws Exception {
    if (args.length == 0 || "--help".equals(args[0])) {
      System.out.println(
          "AI Guardrail Scanner 0.7.0 (native Java 7+)\n"
              + "  rules\n"
              + "  scan /absolute/repository --output /absolute/reports\n"
              + "  mcp --allow-root /absolute/root [--allow-root /another] --output"
              + " /absolute/reports\n"
              + "  scan/mcp options: --profile"
              + " generic|bank-common|bank-customer|bank-internal|bank-all [--bank-policy"
              + " /absolute/operator-contracts.json]");
      return 0;
    }
    if ("rules".equals(args[0]) && args.length == 1) {
      System.out.println(Json.PRETTY.toJson(Catalog.all()));
      return 0;
    }
    if ("mcp".equals(args[0])) {
      List<Path> roots = new ArrayList<Path>();
      Path output = null;
      String profile = "generic";
      Path bankPolicy = null;
      Set<String> seen = new HashSet<String>();
      for (int i = 1; i < args.length; i += 2) {
        if (i + 1 == args.length) throw new IllegalArgumentException("INVALID_ARGUMENTS");
        if (!"--allow-root".equals(args[i]) && !seen.add(args[i]))
          throw new IllegalArgumentException("INVALID_ARGUMENTS");
        if ("--allow-root".equals(args[i])) roots.add(Paths.get(args[i + 1]));
        else if ("--output".equals(args[i]) && output == null) output = Paths.get(args[i + 1]);
        else if ("--profile".equals(args[i])) profile = args[i + 1];
        else if ("--bank-policy".equals(args[i])) bankPolicy = Paths.get(args[i + 1]);
        else throw new IllegalArgumentException("INVALID_ARGUMENTS");
      }
      if (output == null) throw new IllegalArgumentException("OUTPUT_REQUIRED");
      BusinessPolicy loaded = BusinessPolicy.load(profile, bankPolicy);
      for (Path root : roots) loaded.checkRepository(root);
      final ScanService service = new ScanService(roots, output, loaded);
      Thread hook =
          new Thread(
              new Runnable() {
                public void run() {
                  service.close();
                }
              },
              "guardrail-shutdown");
      Runtime.getRuntime().addShutdownHook(hook);
      try {
        new McpHost(service).run(System.in, System.out);
      } finally {
        service.close();
        try {
          Runtime.getRuntime().removeShutdownHook(hook);
        } catch (IllegalStateException ignored) {
        }
      }
      return 0;
    }
    if ("scan".equals(args[0]) && args.length >= 4) {
      Path root = Paths.get(args[1]), output = null, bankPolicy = null;
      String profile = "generic";
      Set<String> seen = new HashSet<String>();
      for (int i = 2; i < args.length; i += 2) {
        if (i + 1 == args.length || !seen.add(args[i]))
          throw new IllegalArgumentException("INVALID_ARGUMENTS");
        if ("--output".equals(args[i])) output = Paths.get(args[i + 1]);
        else if ("--profile".equals(args[i])) profile = args[i + 1];
        else if ("--bank-policy".equals(args[i])) bankPolicy = Paths.get(args[i + 1]);
        else throw new IllegalArgumentException("INVALID_ARGUMENTS");
      }
      if (output == null) throw new IllegalArgumentException("OUTPUT_REQUIRED");
      BusinessPolicy loaded = BusinessPolicy.load(profile, bankPolicy);
      loaded.checkRepository(root);
      try (ScanService service = new ScanService(Arrays.asList(root), output, loaded)) {
        Map<String, Object> status = service.start(root);
        String id = (String) status.get("scanId");
        while ("RUNNING".equals(status.get("state"))) {
          Thread.sleep(25);
          status = service.status(id);
        }
        System.out.println(
            Json.PRETTY.toJson(
                Findings.map("status", status, "reportDirectory", output.resolve(id).toString())));
        if (!"COMPLETED".equals(status.get("state")))
          return "CANCELLED".equals(status.get("state")) ? 130 : 2;
        return ((Number) status.get("violations")).intValue() > 0 ? 1 : 2;
      }
    }
    throw new IllegalArgumentException("INVALID_ARGUMENTS");
  }
}
