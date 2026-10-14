# Python syntax, injected clients and result-consumption evidence

The user authorized closing the two Python parse gaps, extending the RAG client and validation call chains, and revalidating all three projects with generic rules. This extends the previously approved bounded offline scanner design.

## Confirmed gaps

- Python `case` is a soft keyword, but the vendored `name` production omits it. Ordinary identifiers in two wm helper files fail parsing. Add it to the general name production while retaining real match/case parsing and rejection of malformed syntax. Python's [soft-keyword specification](https://docs.python.org/3/reference/lexical_analysis.html#soft-keywords) is the semantic reference.
- Python instances retain a class scope but lose constructor arguments. An imported client factory can reach one object's field and be passed into another constructor without reaching that second object's SDK call in the current analysis.
- Model-content consumers are observed, but their returned values are not linked to later conditions, returns or output fields. A method named `validate` alone provides no security evidence.

## Approach and alternatives

Extend the existing Java 7 ANTLR adapter with bounded instance/call contexts. This keeps the runtime self-contained and makes source relationships explainable. A Python interpreter sidecar would introduce a new runtime dependency; global class-level merging would be simpler but can contaminate unrelated instances/calls and create false conclusions. Neither alternative fits the agreed contract.

Constructor and method calls bind supported positional and keyword arguments, self, and visible defaults. Each instance retains its constructor context. Source evaluation uses context-specific memoization or disables reuse under active contexts. Unknown unpacking, ambiguous construction, decorators, mutation and mixed returns cannot become definite SDK or raw-content provenance. Existing work, recursion and cancellation limits remain enforced; exhausted contexts produce coverage diagnostics.

Use a separate result-provenance relation for a source-visible call consuming model content. Its result may be observed entering a condition, a source-visible predicate or a return/output field. This relation is not raw taint, validation success, authorization or rollback proof. Reassignment and unrelated calls must break unsupported relations. Streaming release before a later consumer is a source-order observation only; unknown custom semantics never produce a violation from order alone.

## Acceptance

- Both previously failing helper files parse without changing target source. Minimal renamed fixtures prove ordinary `case` identifiers and genuine match/case remain supported; malformed constructs still fail.
- The RAG injected-client call is associated with imported SDK provenance through constructor arguments and fields, while alternative runtime injection remains UNKNOWN. The model-content consumer, its returned result and downstream use have source locations, including streaming order limitations.
- Cross-instance/cross-call isolation, shadowing, unknown clients, overwritten results, ignored checks and unrelated predicates do not yield unsupported definite findings.
- No target project names, application class names or business method names select behavior. No target application, Python import, build, model endpoint or database is executed.
- Preserve native Java 7/8 operation, 26 rule IDs and existing Java/FC evidence. Package 0.3.1, schema 1.2 and rule set `java-python-guardrail-v3.1`; retain 0.3.0 for rollback.
- Run the same final JAR on real JDK 7/8, scan all three projects, compare reports across runtimes, then install and verify through a fresh Codex MCP process. Record remaining unknowns instead of claiming safety.
