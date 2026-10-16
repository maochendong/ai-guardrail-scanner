# Field, Decision and Stream Implementation Plan

> Agentic workers: use the ownership-separated tasks below; root integrates and verifies the final artifact. The user has authorized implementation and GitHub delivery.

**Goal:** Resolve code-supported field, composite-decision and streaming relation uncertainty while preserving unproven scope.

**Architecture:** Extend existing bounded IR and engines; precise field construction and projection, conjunctive predicates tied to one decision object, and explicit stream derivation facts. No application-specific branches or execution of target code.

**Tech Stack:** Native Java 7 compiler, Java 7/8 runtime, ANTLR, Gson, JUnit and Python acceptance scripts.

**Spec:** `docs/superpowers/specs/2026-10-16-field-decision-stream-design.md`

## Global constraints

- Native Java 7/8 runtime compatibility; no newer API or runtime dependency.
- Target source read-only; operator contracts outside target roots; do not promote candidate qualification.
- Tests before final release; build operations serialized to prevent conflicting Maven outputs.

## Task 1: Field flow (dto_flow)

Files: `BusinessFlow.java`, `BusinessJavaAnalysis.java`, `BusinessPythonAnalysis.java`, `BusinessAnalysis.java`; dedicated field-flow regression test classes.

- [x] Capture real projection failures and construct renamed fixtures: known `Map.put("records", value)`, known dictionary keys, source-defined DTO constructors/accessors, and known JSON literals.
- [x] Preserve the exact field value; test wrong key, wrong object, opaque member, unknown mutation, branch joins and missing fields. Dynamic JSON is not concrete field evidence.
- [x] Run focused tests with `scripts/build-compatible.sh -Dtest=<new test classes> test` after root grants the build slot; report real site effects.

## Task 2: Compound predicates (root)

Files: `BusinessPolicy.java`, `BusinessAnalysis.java` after field engine ownership handoff; new `BusinessCompoundDecisionTest.java` and policy tests.

- [x] Parse `decision.all` with 1–8 unique selectors and explicit accept polarity; reject mixed formats, duplicates, invalid slots and ambiguous outer negation.
- [x] Model accepted clause facts for one check-return object and current epoch; grant the underlying control only when every required clause is satisfied.
- [x] Regress `allowed && !needConfirm`, rejecting `!allowed || needConfirm`, missing/OR/wrong-object/recheck/exception/mutation paths, legacy decision and candidate assurance.

## Task 3: Streaming relation (stream_guard)

Files: `BusinessStreamTiming.java` and dedicated streaming regressions; root owns `Reports.java`, `scripts/report_schema.py` and schema tests.

- [x] Preserve bounded explicit composition dependencies and exact field projections agreed with the adapters.
- [x] Emit derived-from-release relation only for supported data dependencies; never reuse it as same-value or accepted-before-release evidence.
- [x] Consume compound predicates consistently with the main engine; test wrong aggregate, post-check, overwrite, unknown mutation, candidate/open and loop boundaries.

## Task 4: Evidence and final delivery (root / flow_evidence)

- [x] Snapshot target HEAD/status/diffs and existing policy; keep 0.8.0 stable reports as comparison baseline.
- [x] Update source-backed private mappings only if required by supported semantics, with reviewed evidence and unchanged qualification where manual evidence is absent.
- [x] Run focused checks, independent soundness review, then `scripts/verify-release.py` with two native JDK homes, three projects and the selected policy in a fresh directory.
- [x] Install the same verified JAR; run `scripts/verify-codex-integration.py`, compare stable reports and target integrity.
- [x] Produce separate UNKNOWN, manual and engineering lists, document limitations and exact changes, and prepare the scoped public delivery.

GitHub commit/push and remote HEAD verification are recorded after delivery in the local receipt, outside the public repository.
