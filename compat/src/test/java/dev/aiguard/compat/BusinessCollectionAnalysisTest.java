package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.*;
import org.junit.Test;

/** A checked key and a copied record are evidence for review, never an all-items safety proof. */
public class BusinessCollectionAnalysisTest {
  private static final Cancel NONE =
      new Cancel() {
        public void check() {}
      };
  private static final String PREFIX =
      "package sample;import java.util.*;import sample.Api;import sample.Decision;"
          + "class Runner {Map<String,Object> recommend(String account){"
          + "Map<String,Object> out=new LinkedHashMap<String,Object>();"
          + "List<Map<String,Object>> records=new ArrayList<Map<String,Object>>();"
          + "out.put(\"items\",records);List<Map<String,Object>> visible=Api.items();";
  private static final String LOOP = "for(Map<String,Object> record:visible){";
  private static final String CHECK =
      "Decision decision=Api.inspect(account,record.get(\"productKey\"));";
  private static final String REJECT = "if(!decision.allowed()||decision.needsReview())continue;";
  private static final String COPY =
      "Map<String,Object> item=new LinkedHashMap<String,Object>(record);";

  private BusinessPolicy policy(String assurance, String failure) throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(
        Findings.map(
            "symbol",
            "sample.Api#inspect",
            "arity",
            2,
            "kind",
            "check",
            "control",
            "suitability",
            "args",
            Arrays.asList(0, 1),
            "accept",
            true,
            "assurance",
            assurance,
            "failureMode",
            failure,
            "decision",
            Findings.map(
                "all",
                Arrays.asList(
                    Findings.map("symbol", "sample.Decision#allowed", "arg", -1, "accept", true),
                    Findings.map(
                        "symbol", "sample.Decision#needsReview", "arg", -1, "accept", false)))));
    contracts.add(
        Findings.map(
            "symbol",
            "sample.Runner#recommend",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "recommend",
            "boundary",
            "return",
            "args",
            Arrays.asList(0),
            "identity",
            1,
            "valuePath",
            Arrays.asList("items")));
    return BusinessPolicy.parse(
        "bank-all", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
  }

  private BusinessCollectionAnalysis scan(String loopBody, String after) throws Exception {
    return scan(loopBody, after, "reviewed", "closed");
  }

  private BusinessCollectionAnalysis scan(
      String loopBody, String after, String assurance, String failure) throws Exception {
    BusinessPolicy policy = policy(assurance, failure);
    BusinessFlow.Program program =
        BusinessJavaAnalysis.adapt(
            Arrays.asList(
                new SourceFile(
                    "Runner.java", PREFIX + LOOP + loopBody + "}" + after + "return out;}}")),
            NONE,
            policy);
    return BusinessCollectionAnalysis.analyze(program, policy, NONE);
  }

  private List<Map<String, Object>> sites(BusinessCollectionAnalysis result) {
    List<Map<String, Object>> sites = result.sitesByRule.get(BusinessPolicy.SUITABILITY);
    return sites == null ? Collections.<Map<String, Object>>emptyList() : sites;
  }

  private Map<String, Object> only(BusinessCollectionAnalysis result) {
    assertFalse(result.truncated);
    assertEquals(result.sitesByRule.toString(), 1, sites(result).size());
    return sites(result).get(0);
  }

  private void neverAccepted(BusinessCollectionAnalysis result) {
    assertFalse("The review must retain the source append relation", sites(result).isEmpty());
    for (Map<String, Object> site : sites(result)) {
      assertEquals("UNKNOWN", site.get("coverage"));
      assertEquals("UNKNOWN", site.get("disposition"));
      assertEquals(site.toString(), "not-established", site.get("decisionBinding"));
    }
  }

  @Test
  public void rejectedItemsContinueAndTheSameElementsReachTheOutputCollection() throws Exception {
    Map<String, Object> site = only(scan(CHECK + REJECT + "records.add(record);", ""));
    assertEquals("UNKNOWN", site.get("disposition"));
    assertEquals("UNKNOWN", site.get("coverage"));
    assertEquals("same-element", site.get("elementBinding"));
    assertEquals("same-subject", site.get("subjectBinding"));
    assertEquals("all-required-predicates", site.get("decisionBinding"));
    assertEquals(Arrays.asList("productKey"), site.get("checkedElementPath"));
    assertEquals("same-collection", site.get("outputBinding"));
    assertTrue(((List<?>) site.get("limitations")).contains("NO_ALL_ITERATIONS_PROOF"));
    assertEquals(BusinessPolicy.SUITABILITY, site.get("ruleId"));
    assertEquals("UNSUPPORTED", site.get("unknownCategory"));
    assertFalse(((List<?>) site.get("reviewActions")).isEmpty());
    assertLocatedReview(site);
  }

  @SuppressWarnings("unchecked")
  private void assertLocatedReview(Map<String, Object> site) {
    List<Map<String, Object>> evidence = (List<Map<String, Object>>) site.get("evidence");
    assertEquals(3, evidence.size());
    String[] prefixes = {"", "append", "check"};
    String[] roles = {"collection-output", "collection-append", "collection-check"};
    for (int i = 0; i < prefixes.length; i++) {
      Map<String, Object> location = evidence.get(i);
      assertEquals(
          site.get(prefixes[i].isEmpty() ? "path" : prefixes[i] + "Path"), location.get("path"));
      assertEquals(
          site.get(prefixes[i].isEmpty() ? "line" : prefixes[i] + "Line"), location.get("line"));
      assertEquals(roles[i], location.get("role"));
      assertEquals(
          location.get("path") + ":" + location.get("line") + ":" + roles[i],
          location.get("nodeId"));
      assertFalse(location.containsKey("symbol"));
    }
    for (Map<String, Object> action : (List<Map<String, Object>>) site.get("reviewActions")) {
      List<Map<String, Object>> locations = (List<Map<String, Object>>) action.get("locations");
      assertEquals(3, locations.size());
      for (Map<String, Object> location : evidence)
        assertTrue(
            locations.contains(
                Findings.map(
                    "path",
                    location.get("path"),
                    "line",
                    location.get("line"),
                    "nodeId",
                    location.get("nodeId"))));
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  public void sameOutputLocationRetainsEachCheckAndAppendReviewLocation() throws Exception {
    BusinessCollectionAnalysis result =
        scan(
            "\nDecision first=Api.inspect(account,record.get(\"productKey\"));\n"
                + "if(first.allowed()&&!first.needsReview())records.add(record);\n"
                + "Decision second=Api.inspect(account,record.get(\"productKey\"));\n"
                + "if(second.allowed()&&!second.needsReview())records.add(record);\n",
            "\n");
    List<Map<String, Object>> sites = sites(result);
    assertTrue(sites.size() > 1);
    Set<Object> outputs = new HashSet<Object>();
    Set<String> relations = new HashSet<String>();
    for (Map<String, Object> site : sites) {
      assertLocatedReview(site);
      assertEquals("UNKNOWN", site.get("disposition"));
      outputs.add(site.get("line"));
      relations.add(site.get("checkLine") + ":" + site.get("appendLine"));
    }
    assertEquals(1, outputs.size());
    assertTrue(relations.size() > 1);
    Map<String, Object> parent =
        Findings.map(
            "ruleId",
            BusinessPolicy.SUITABILITY,
            "disposition",
            "UNKNOWN",
            "collectionReviewSites",
            sites);
    Unknowns.complete(Arrays.asList(parent), Collections.<Map<String, Object>>emptyList());
    assertEquals("UNKNOWN", parent.get("disposition"));
    for (Map<String, Object> site : sites)
      for (Map<String, Object> action : (List<Map<String, Object>>) site.get("reviewActions")) {
        boolean located = false;
        for (Map<String, Object> merged : (List<Map<String, Object>>) parent.get("reviewActions"))
          if (action.get("kind").equals(merged.get("kind"))
              && action.get("code").equals(merged.get("code")))
            located =
                ((List<?>) merged.get("locations")).containsAll((List<?>) action.get("locations"));
        assertTrue("parent review lost a check/append/output location", located);
      }
  }

  @Test
  public void partialOrAlternativeDecisionLeavesAnUncontrolledAppendPath() throws Exception {
    for (String condition :
        Arrays.asList(
            "decision.allowed()",
            "!decision.needsReview()",
            "decision.allowed()||!decision.needsReview()")) {
      BusinessCollectionAnalysis result =
          scan(CHECK + "if(" + condition + "){records.add(record);}", "");
      assertFalse(sites(result).isEmpty());
      boolean unresolved = false;
      for (Map<String, Object> site : sites(result))
        unresolved |= "not-established".equals(site.get("decisionBinding"));
      assertTrue(condition, unresolved);
    }
  }

  @Test
  public void predicatesFromDifferentDecisionsCannotBeCombined() throws Exception {
    neverAccepted(
        scan(
            CHECK
                + "Decision other=Api.inspect(account,record.get(\"productKey\"));"
                + "if(!decision.allowed()||other.needsReview())continue;"
                + "records.add(record);",
            ""));
  }

  @Test
  public void laterCheckCannotProtectAnEarlierAppend() throws Exception {
    neverAccepted(scan("records.add(record);" + CHECK + REJECT, ""));
  }

  @Test
  public void aDifferentAppendedElementDoesNotInheritAKeyCheck() throws Exception {
    Map<String, Object> site =
        only(
            scan(
                CHECK
                    + REJECT
                    + "Map<String,Object> item=new"
                    + " LinkedHashMap<String,Object>();records.add(item);",
                ""));
    assertEquals("unresolved", site.get("elementBinding"));
    assertEquals("not-established", site.get("decisionBinding"));
  }

  @Test
  public void alternateUncheckedAppendIsRetainedSeparately() throws Exception {
    BusinessCollectionAnalysis result =
        scan(
            CHECK
                + "if(decision.allowed()&&!decision.needsReview()){records.add(record);}else{records.add(record);}",
            "");
    boolean controlled = false, uncontrolled = false;
    for (Map<String, Object> site : sites(result)) {
      controlled |= "all-required-predicates".equals(site.get("decisionBinding"));
      uncontrolled |= "not-established".equals(site.get("decisionBinding"));
    }
    assertTrue(controlled);
    assertTrue(uncontrolled);
  }

  @Test
  public void returningAnotherNewCollectionDoesNotTransferTheAppendRelation() throws Exception {
    assertTrue(
        sites(
                scan(
                    CHECK + REJECT + COPY + "records.add(item);",
                    "List<Map<String,Object>> other=new"
                        + " ArrayList<Map<String,Object>>();out.put(\"items\",other);"))
            .isEmpty());
  }

  @Test
  public void rewrittenKeyAndUnknownMutationCannotEstablishDecisionBinding() throws Exception {
    for (String mutation :
        Arrays.asList(
            "record.put(\"productKey\",\"different\");",
            "Api.mutate(record);",
            "Api.mutate(records);"))
      neverAccepted(scan(CHECK + REJECT + mutation + "records.add(record);", ""));
  }

  @Test
  public void copyingAnUnknownRuntimeMapRetainsSourceDependencyWithoutFieldEquality()
      throws Exception {
    Map<String, Object> site =
        only(
            scan(
                CHECK + REJECT + COPY + "item.put(\"displayLabel\",\"sample\");records.add(item);",
                ""));
    assertEquals("derived-element", site.get("elementBinding"));
    assertEquals("not-established", site.get("decisionBinding"));
    assertEquals("UNKNOWN", site.get("coverage"));
    assertTrue(
        ((List<?>) site.get("limitations"))
            .contains("COPY_CONSTRUCTOR_NOT_FIELD_VALUE_EQUIVALENCE"));
  }

  @Test
  public void unqualifiedKeyConversionRetainsOnlyDerivedSourceRelation() throws Exception {
    Map<String, Object> site =
        only(
            scan(
                "Object key=Api.convert(record.get(\"productKey\"));Decision"
                    + " decision=Api.inspect(account,key);"
                    + REJECT
                    + "records.add(record);",
                ""));
    assertEquals(Arrays.asList("productKey"), site.get("checkedElementPath"));
    assertEquals("derived-element", site.get("elementBinding"));
    assertEquals("not-established", site.get("decisionBinding"));
  }

  @Test
  public void unknownMapCopyMayMutateItsInputEvenWhenTheCopyIsIgnored() throws Exception {
    neverAccepted(scan(CHECK + REJECT + COPY + "records.add(record);", ""));
  }

  @Test
  public void mutationAfterAppendIsNotHiddenByTheCapturedPredicate() throws Exception {
    neverAccepted(scan(CHECK + REJECT + "records.add(record);Api.mutate(record);", ""));
  }

  @Test
  public void candidateAndOpenChecksNeverGainCollectionApproval() throws Exception {
    for (String[] qualifiers :
        Arrays.asList(new String[] {"candidate", "closed"}, new String[] {"reviewed", "open"}))
      neverAccepted(
          scan(CHECK + REJECT + "records.add(record);", "", qualifiers[0], qualifiers[1]));
  }

  @Test
  public void continueAndBreakExcludeSubsequentAppendsInTheIteration() throws Exception {
    for (String exit : Arrays.asList("continue;", "break;"))
      assertTrue(sites(scan(CHECK + REJECT + exit + COPY + "records.add(item);", "")).isEmpty());
  }

  @Test
  public void contradictoryPredicateBranchDoesNotInventAReachableAppend() throws Exception {
    assertTrue(
        sites(
                scan(
                    CHECK
                        + "if(decision.allowed()&&!decision.allowed()){"
                        + COPY
                        + "records.add(item);}",
                    ""))
            .isEmpty());
  }

  @Test
  public void booleanComparisonBranchesPreserveTheSameCompleteDecision() throws Exception {
    Map<String, Object> site =
        only(
            scan(
                CHECK
                    + "if(decision.allowed()==false||decision.needsReview()!=false)continue;"
                    + "records.add(record);",
                ""));
    assertEquals("all-required-predicates", site.get("decisionBinding"));
  }

  @Test
  public void missingCheckDoesNotFabricateACheckLocation() throws Exception {
    assertTrue(sites(scan(COPY + "records.add(item);", "")).isEmpty());
  }

  @Test
  public void unqualifiedGeneratedAccessorCannotPreserveAnEarlierDecision() throws Exception {
    BusinessPolicy policy = policy("reviewed", "closed");
    BusinessFlow.Program program =
        BusinessJavaAnalysis.adapt(
            Arrays.asList(
                new SourceFile(
                    "Runner.java",
                    PREFIX
                        + LOOP
                        + CHECK
                        + REJECT
                        + "record.get(\"unrelated\");records.add(record);}return out;}}")),
            NONE,
            policy);
    for (BusinessFlow.Function function : program.functions)
      for (BusinessFlow.Stmt statement : function.body) markGenerated(statement);
    neverAccepted(BusinessCollectionAnalysis.analyze(program, policy, NONE));
  }

  private void markGenerated(BusinessFlow.Stmt statement) {
    markGenerated(statement.expr);
    for (BusinessFlow.Stmt child : statement.body) markGenerated(child);
    for (BusinessFlow.Stmt child : statement.otherwise) markGenerated(child);
  }

  private void markGenerated(BusinessFlow.Expr expression) {
    if (expression == null) return;
    if (expression.name.equals("unrelated")) expression.generatedMethodUncertain = true;
    markGenerated(expression.receiver);
    for (BusinessFlow.Expr argument : expression.args) markGenerated(argument);
    for (BusinessFlow.Expr member : expression.members.values()) markGenerated(member);
  }

  @Test
  public void cancellationPropagatesBeforeAnalyzingAnyFunction() throws Exception {
    final RuntimeException cancelled = new RuntimeException("cancelled");
    BusinessFlow.Program program = new BusinessFlow.Program();
    program.functions.add(new BusinessFlow.Function());
    try {
      BusinessCollectionAnalysis.analyze(
          program,
          policy("reviewed", "closed"),
          new Cancel() {
            public void check() {
              throw cancelled;
            }
          });
      fail("cancellation was swallowed");
    } catch (RuntimeException expected) {
      assertSame(cancelled, expected);
    }
  }
}
