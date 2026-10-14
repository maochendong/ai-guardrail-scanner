# Java 7 / 8 native runtime migration

The user explicitly requires the scanner itself to run on Java 7 and Java 8. A launcher which starts Java 21 does not meet that requirement. Preserve the completed custom gateway, Guard and function-calling work and repeat real project validation.

## Verified constraints and approach

- The current MCP SDK has class major 61; JavaParser and Jackson have major 52. The application also uses Java 21 language/API features. Changing Maven target alone is insufficient.
- Native JDK 7u79 and JDK 8u40 are installed and successfully start locally.
- ANTLR 4.9.3 has Java 7 bytecode. BSD-licensed Java grammar, pinned to its upstream commit, can generate and run a parser under JDK 7, including the modern source constructs used by the two Java targets.
- Create `compat/` as a Java 7 native runtime distribution, retaining the modern implementation and regression fixtures as a reference until compatibility is verified. No external model, target build, target dependency or newer JVM is invoked by the runtime.
- Use a small bounded stdio JSON-RPC host, Gson JSON trees, Java 7 NIO/executors, ANTLR source IR and the same controlled evidence/report contract. Keep source-derived strings out of exported descriptions.
- Third target: `/Users/Darkknight/Documents/蒸馏小可乐` is Python/RAG. The user also explicitly approved Python/RAG rule expansion in this same delivery; implement a native Java 7 Python source adapter, do not execute target Python, and do not present a Java-only scan as a completed Python audit.

## Work and acceptance

- [x] Implement pinned grammar and Java 7 IR, source binding, candidate dispatch and origin summaries.
- [x] Migrate all 19 rule contracts with actual supported positive/negative evidence; preserve UNKNOWN and ambiguity rather than substituting names or all-unknown placeholders.
- [x] Implement safe inventory, path/output isolation, budgets, cancellation, reports and the five stdio tools using Java 7 APIs.
- [x] Add Java 7 syntax fixtures and Java 8 lambdas/method references/default methods/modern target-source fixtures. Check every shipped class major <= 51.
- [x] Build and run the same final JAR in real JDK 7 and JDK 8 processes; exercise handshake, discovery, bounded errors, scan lifecycle, cancellation/EOF and three report formats.
- [x] Compare rule states and evidence locations across both runtimes on codebuddy and wm-sales; retain generative-name and ordinary-data false-positive regressions.
- [x] Verify the third project's agreed scope without executing or changing its application/data.
- [x] Install versioned 0.3 JAR; update only this Codex server's runtime/JAR fields and allowed roots needed for the explicitly requested third target; preserve unrelated settings and rollback files.
- [x] Save exact JDK versions, class/API checks, test counts, scan IDs, diagnostics, target hashes and limitations. Confirm the actual new Codex process rather than claiming an old live process hot-reloaded.

Final acceptance: 2026-10-14, 114 native tests on each real JDK 7/8 runtime, 6 native project scans plus 3 Codex scans, 26 rules. Evidence and remaining limitations: `docs/java7-python-verification.md`.
