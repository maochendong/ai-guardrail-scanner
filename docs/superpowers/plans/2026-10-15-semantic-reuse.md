# External Semantic Reuse Implementation Plan

> Agentic workers: execute the ownership-separated tasks below in the current authorized checkout; root coordinates integration and final verification.

**Goal:** Resolve source-supported missing API boundaries and reuse qualified external semantics in generic assessments without inventing coverage.

**Architecture:** Share the existing BusinessFlow analysis, preserving native generic checks and explicit per-rule/per-language evidence provenance. Operator mappings stay outside the scanned roots and public repository.

**Tech Stack:** Java 7/8, existing ANTLR/Gson runtime, JUnit, Python acceptance scripts.

**Spec:** `docs/superpowers/specs/2026-10-15-semantic-reuse-design.md`

## Global Constraints

- Native Java 7 compiler and native JDK 7/8 runtime verification.
- No target-application edits, project-name heuristics, candidate trust promotion or artificial UNKNOWN reduction.
- Publish only scanner code, synthetic tests and sanitized evidence summaries.

## Task 1: Real API contracts

- [x] Read the final prior stable reports and review all 9 `NO_RESOLVED_MAPPED_SINK` assessments.
- [x] Snapshot private policy and target integrity, map actual recommend/retrieve/tool boundaries without replacing existing roles.
- [x] Validate loading and exact source/argument bindings; record unresolved applicability separately.

Owner: real_api_pack. Files: operator-managed policy outside repository; local `scan-results/semantic-reuse-20261015/mapping-review.*`.

## Task 2: Shared generic semantics

- [x] Add failing synthetic fixtures for Java and Python same-value Guard protection, ignored/late/wrong-value checks, candidate/open/stale contracts, profile and language isolation.
- [x] Implement shared evidence consumption in `compat/src/main/java/dev/aiguard/compat/`, preserving ordinary checks and independent unresolved paths.
- [x] Run focused native-compatible JUnit tests, then review soundness and rule correspondence.

Owner: generic_semantics. Interfaces: `Scanner.scan(..., BusinessPolicy)`, existing semantic flow and report assessments; retain original no-policy overloads.

## Task 3: Integration and release verification

- [x] Update current version references, report validation if necessary, authoring guidance and technical architecture.
- [x] Run `scripts/verify-release.py` with the two native JDK homes, three original project roots and external policy into a fresh evidence directory.
- [x] Compare results with 0.7.0, enumerate changed/remaining UNKNOWN and manual evidence, verify unchanged targets.
- [x] Install the same validated JAR, run a fresh Codex integration process and compare stable reports.
- [ ] Review exact staged diff, commit and push authorized scanner files; verify remote HEAD. This final delivery step is recorded by the resulting Git commit and remote verification, rather than a pre-push completion claim.

Owner: root. Unit regressions run through `scripts/build-compatible.sh`; script regressions through the bundled Python interpreter and `unittest discover -s scripts/tests`.

## Task 4: Technical presentation detail

- [x] Expand slide 9 into detailed parsing, semantic representation, bounded flow, rule evaluation and report stages.
- [x] Make semantic-reuse text match the completed implementation; preserve unrelated slides and existing video bytes.
- [x] Export editable PPT, render the real PPT and inspect layout; synchronize HTML and narration.

Owner: technical_slide_detail. Local presentation artifacts are delivered separately, not added to the public code commit.
