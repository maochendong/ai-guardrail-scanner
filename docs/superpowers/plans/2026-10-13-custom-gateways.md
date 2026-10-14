# Custom Gateway and Function Calling Implementation Plan

> **For agentic workers:** Use available collaboration workers for isolated modules; review implementations against the approved scope. Referenced superpowers execution skills are unavailable. The user's explicit continuation authorizes implementation and verification in this session.

**Goal:** Recognize custom Java model gateways, report Guard and function-calling evidence without project-specific signatures, and validate through Codex on both real projects.

**Architecture:** One bounded local call graph and one protocol/source model are shared by two rule modules. Scanner composes them with the unchanged Spring AI rule family; reports reuse the evidence contract.

**Tech Stack:** Existing Java 21, JavaParser 3.28.2, official MCP SDK, Jackson and JUnit. No new runtime dependencies required.

**Spec:** `docs/superpowers/specs/2026-10-13-custom-gateways-design.md`

## Global Constraints

- No target code/build execution, source upload, dependency downloads or target project edits.
- No project/package/business class names embedded in rules; standard wire keys and API type identities are allowed.
- Candidate dispatch cannot silently become proven model origin or guard coverage. Preserve UNKNOWN independently of observations.
- Graph budgets: 30,000 methods, 100,000 calls, 16 targets per call, depth 8; cooperative cancellation and explicit diagnostics.
- Export only controlled explanations and relative locations. Security verification always false.

### Task 1: Local source call graph

Files: create `analysis/LocalCallGraph.java` and `analysis/LocalCallGraphTest.java` in main/test trees.

- [x] Write resolution tests for declared fields/parameters, source return types, factory calls, nested types, interface dispatch, duplicate FQNs, overload ambiguity, shadowed and reassigned variables, recursion and cancellation.
- [x] Implement the exact graph API in the spec; preserve candidate sets and unknown reasons instead of choosing the first declaration.
- [x] Run `./scripts/mvn.sh -Dtest=LocalCallGraphTest test`; inspect both resolved and unresolved edges.

### Task 2: Protocol-based model source summaries

Files: create `analysis/GatewayModel.java` and `analysis/GatewayModelTest.java`.

- [x] Test OkHttp explicit request endpoint and configuration-driven RestClient request/response records, with renamed application types.
- [x] Add negative fixtures for ordinary HTTP, string/comment mentions, unused response, unrelated return values and ambiguous implementations.
- [x] Implement `build`, `origin`, invocation/participating-method queries, bounded evidence traces and separate callback parameter summaries.
- [x] Run `./scripts/mvn.sh -Dtest=GatewayModelTest test`; verify candidate dispatch does not become certainty.

### Task 3: Guard and Function Calling assessments

Files: create `analysis/CustomGuardRules.java`, `analysis/rules/FunctionCallingRules.java` and their corresponding tests.

- [x] Guard tests cover model value -> local predicate/result record -> conditional early exit; mismatched value, ignored return, late check and callback send must remain distinguishable.
- [x] Function-calling tests cover standard and custom protocol fields with proven origin, fixed switch/registry lookup, reject branches, JSON-only parsing, dynamic execution and separate context inputs.
- [x] Each module exposes `catalog()` and `assess(project,graph,model,cancelled)`; no direct target filesystem reads.
- [x] Run both new test classes and inspect source positions and static explanatory text.

### Task 4: Scanner/report integration and regressions

Files: modify `scan/Scanner.java`, `analysis/RuleEngine.java` catalog exposure as needed, `model/ScanModel.java` additive metadata if needed, version/build/readme/rule docs and protocol test catalog expectations.

- [x] Build the graph/model once, merge new assessments and diagnostics, and set AI detection using protocol evidence without falsely identifying Spring AI.
- [x] Preserve report budgets and all existing assessment semantics; extend report scope text to mention bounded inter-method analysis.
- [x] Run `./scripts/mvn.sh clean verify`, then packaged-JAR MCP tests. Fix newly exposed regressions before installation.

### Task 5: Deployment and real project verification

- [x] Independently review rules for false assurance, project-name coupling, source leaks and missing ambiguity handling; fix demonstrated defects.
- [x] Install versioned JAR outside target/; back up and update only the existing Codex server argument, preserving allowed roots and other MCP settings.
- [x] Use actual MCP start/status/result on both real targets, retrieve JSON/Markdown/SARIF, confirm terminal states, and preserve target Git HEAD/status baselines.
- [x] Save a before/after verification record with actual counts, meaningful evidence, remaining UNKNOWN paths and stable artifact links. Do not equate workflow completion with security approval.
