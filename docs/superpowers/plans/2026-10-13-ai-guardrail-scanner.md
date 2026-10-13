# AI Guardrail Scanner Implementation Plan

> **For agentic workers:** Use the available collaboration tools for independent modules and review each task against the approved spec. The referenced superpowers execution skills are not installed; this plan is executed in the current session under the user's implementation confirmation.

**Goal:** Deliver a runnable local Java source/configuration audit MCP with evidence, honest coverage, and reproducible validation.

**Architecture:** JavaParser inventory feeds a deterministic rule engine. A bounded job service exposes the same engine through CLI and the official MCP SDK; reports share one canonical result model.

**Tech Stack:** Java 21, Maven, MCP Java SDK 2.0.1, JavaParser 3.28.2, Jackson, JUnit 5.

**Spec:** `docs/superpowers/specs/2026-10-13-ai-guardrail-scanner-design.md`

## Global Constraints

- Only source/configuration static analysis; no target code/build execution or network dependency resolution.
- No raw source, prompt, response or credentials in exported evidence.
- Unknown evidence never counts as security success; all seven domains appear in reports.
- MCP allowed roots and output location are operator-owned; one active scan and bounded history.
- The user authorized the design, implementation plan, implementation and verification; no additional execution-choice approval is needed.

## File structure and contracts

`model/ScanModel.java`: immutable records/enums shared by all modules.
`analysis/SourceProject.java`: parsed units, configurations, dependency version, digest and diagnostics.
`analysis/ProjectLoader.java`: safe inventory; `load(Path, BooleanSupplier)`.
`analysis/RuleEngine.java`: `catalog()` and `assess(SourceProject, BooleanSupplier)`.
`scan/Scanner.java`: `scan(Path, String, BooleanSupplier)` composes inventory and assessment.
`report/ReportWriter.java`: exports canonical JSON, Markdown, SARIF into operator-owned output.
`mcp/ScanService.java`: bounded lifecycle; `start/status/cancel/result`.
`mcp/McpHost.java`: official SDK transport and validated tool arguments.
`Main.java`: strict CLI; `scan` and `mcp` entrypoints.

### Task 1: Safe inventory and dependency profile

- [ ] Add JUnit temp-project cases for a Java parse error, XML external entity, unresolved BOM property, external symlink and file limit.
- [ ] Implement read-only bounded inventory with `Files.walkFileTree` without FOLLOW_LINKS, SHA-256 snapshot and JavaParser.
- [ ] Parse known version literals/properties without executing builds. Return UNKNOWN for conflicts or unresolved versions.
- [ ] Run `mvn -Dtest=ProjectLoaderTest test`; inspect diagnostics as well as file counts.

### Task 2: Versioned evidence rules

- [ ] Establish a catalog with stable IDs, seven control domains, descriptions and evidence limits.
- [ ] Write fixture-driven JUnit cases: unsafe data reaching sinks, constant/sanitized alternatives, non-AI lookalikes, unknown external enforcement.
- [ ] Implement AST-based rules and limited expression/method relationships; names alone cannot prove security guarantees.
- [ ] Emit UNKNOWN for unsupported version semantics and unresolvable paths, retaining exact source locations for proven observations.
- [ ] Run `mvn -Dtest=RuleEngineTest test` and inspect the three evidence classes for each rule.

### Task 3: Jobs and reports

- [ ] Add tests for allowlist escape, symlinks, output overlap, single active job, cancellation race, unknown ID and bounded history.
- [ ] Implement immutable terminal transitions and canonical report export with atomic per-file writes.
- [ ] Generate Markdown without raw code and SARIF with rule IDs/relative URIs/line positions.
- [ ] Reopen generated artifacts in tests and assert findings and UNKNOWN counts agree with canonical JSON.

### Task 4: MCP and CLI

- [ ] Use official SDK Tool builders and stdio transport; validate allowed arguments independently of advertised JSON schema.
- [ ] CLI `scan /absolute/repo --output /absolute/reports`; MCP `mcp --allow-root /absolute/projects --output /absolute/reports`.
- [ ] Real subprocess test sends initialize, notifications/initialized, tools/list, scan_start, scan_status and scan_result; verify stdout is only protocol JSON.
- [ ] Validate cancellation/invalid input and process EOF cleanup in integration tests.
- [ ] Run `mvn verify`, build executable jar, run CLI fixture and independently parse all exported reports.

### Task 5: Delivery and review

- [ ] Write Chinese README, rule support matrix, example safe/unsafe projects and MCP client configuration.
- [ ] Independent review of evidence claims, trust boundaries and coverage, then fix actionable issues and rerun affected tests.
- [ ] Record actual verification commands/results and remaining limits; do not label fixture validation as production assurance.
