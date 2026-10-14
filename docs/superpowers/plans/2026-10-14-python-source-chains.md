# Python Source Chains Implementation Plan

> **For agentic workers:** Implement the independent grammar and provenance tasks with isolated file ownership, then integrate and review. The optional superpowers execution sub-skills are not installed; use the available collaboration tools in this task.

**Goal:** Close the requested Python syntax and client/result-source gaps with reusable rules and repeat three-project acceptance.

**Architecture:** Keep the native Java 7 parser and bounded source analysis. Add `case` as a normal name where grammar permits; carry instance constructor contexts and source-visible consumer-result relations without promoting custom semantics to safety.

**Tech Stack:** Java 7 APIs, ANTLR 4.9.3, JUnit 4.13.2, existing JSON/Markdown/SARIF and MCP host.

**Spec:** `docs/superpowers/specs/2026-10-14-python-source-chains-design.md`

## Global constraints

- Scanner must itself run on real Java 7 and Java 8, with no Python sidecar.
- Treat UNKNOWN and OBSERVED as non-certifying evidence; preserve 26 existing rule IDs.
- Read only target source/configuration. Do not run or modify target applications or data.
- Source scope, types and relations drive rules; never match target project/application names.
- Keep Java 21 reference implementation unchanged. Release native module as 0.3.1, schema 1.2, rule set `java-python-guardrail-v3.1`.

### Task 1: Soft-keyword syntax

Files: modify `compat/src/main/antlr4/dev/aiguard/compat/pygrammar/Python3Parser.g4`; add `compat/src/test/java/dev/aiguard/compat/PythonSyntaxTest.java`; update grammar modification notice after integration.

- [x] Add a failing parse fixture: `for case in items:\n    result = case.get('name')\n`, plus renamed parameters/attributes and an actual `match subject: case ...` block.
- [x] Reproduce failure under the shipped grammar, then add `'case'` to the existing `name` alternatives. Do not turn keywords into names globally.
- [x] Run syntax and existing Python tests; invalid standalone/malformed case statements must remain rejected. Parse both actual helper files read-only.

### Task 2: Client and consumer-result contexts

Files: modify `compat/src/main/java/dev/aiguard/compat/PythonAnalysis.java`; add `compat/src/test/java/dev/aiguard/compat/PythonProvenanceTest.java`.

Consumes/produces: existing `PythonAnalysis.analyze(List<SourceFile>, Cancel)` -> `AnalysisResult`; the interface and rule IDs remain stable. Contexts stay private implementation details.

- [x] Reproduce missing injected provenance with `class Remote: ... self.port = port` and `Remote(port=OpenAI()).run()`. Include cross-file aliases, nested factories and both positional/keyword arguments.
- [x] Store instance constructor argument snapshots; bind supported local method arguments and self during evaluation. Do not share memoized AST values across incompatible contexts. Keep unknown unpacking, alternative injection and mutation conservative.
- [x] Reproduce missing result-use evidence with `verdict = inspector.consume(answer); if inspector.decide(verdict): return fallback`. Rename inspector, methods, variables and modules in variants; method names must not select rules.
- [x] Track the returned value of a source-visible model-content consumer separately from raw content. Emit controlled result-use/source-order observations with source locations; retain UNKNOWN for behavior and full path coverage.
- [x] Verify two instances/calls with different clients do not contaminate one another; ignored/reassigned results, unrelated predicates/fields, unknown consumers, mixed returns and decorators do not prove a guard or raw execution violation. Exercise bounded recursion and cancellation.

### Task 3: Integration and runtime acceptance

Files: native `pom.xml`, version/report entry points and `InfrastructureTest.java`; existing `scripts/verify-runtime-matrix.py`, `scripts/verify-codex-integration.py`; README, rules and new verification record.

- [x] Set 0.3.1 package/server/report versions and v3.1 rule-set identity; retain schema 1.2 and 26 rules.
- [x] Add generic verification options for no parse failures and consumer-result evidence. Requirements apply by language/option, never repository name.
- [x] Run `./scripts/build-compatible.sh -q clean verify`; run all compiled native tests with actual JDK 7u79 and JDK 8u40. Check all shipped class versions <= 51.
- [x] Use `scripts/verify-runtime-matrix.py` with both JVM paths and all three project roots; compare source digests, assessments and diagnostics between JVMs. Verify no Python parse failures and relevant RAG provenance/result-use evidence.
- [x] Install the versioned final JAR and surgically update only this server's JAR path in Codex configuration, preserving a backup and 0.3.0 artifact. Run `scripts/verify-codex-integration.py` for the three projects using the actual configured server.
- [x] Independently review evidence/negative cases; compare target HEAD/status digests with the saved baseline. Save exact test counts, JAR hash, scan IDs, evidence deltas and limitations in `docs/python-source-chains-verification.md`; commit the scoped implementation.
