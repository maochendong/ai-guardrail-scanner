package dev.aiguard.compat;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Value dependency and decision conjunctions are separate from security qualification. */
public class BusinessStreamAssociationTest {
  private static final Cancel NEVER =
      new Cancel() {
        public void check() {}
      };

  private BusinessPolicy policy() throws Exception {
    List<Map<String, Object>> contracts = new ArrayList<Map<String, Object>>();
    contracts.add(
        Findings.map(
            "symbol", "edge.stream", "arity", 0, "kind", "source", "label", "model-output"));
    for (String check : Arrays.asList("check", "quality", "judge", "candidate", "open")) {
      Map<String, Object> contract =
          Findings.map(
              "symbol",
              "edge." + check,
              "arity",
              1,
              "kind",
              "check",
              "control",
              "guard",
              "args",
              Arrays.asList(0),
              "accept",
              true,
              "failureMode",
              "quality".equals(check) || "open".equals(check) ? "open" : "closed",
              "assurance",
              "quality".equals(check) || "candidate".equals(check) ? "candidate" : "reviewed");
      if (Arrays.asList("judge", "candidate", "open").contains(check)) {
        contract.put(
            "decision",
            Findings.map(
                "all",
                Arrays.asList(
                    Findings.map("symbol", "edge.allowed", "arg", 0, "accept", true),
                    Findings.map("symbol", "edge.needs_confirm", "arg", 0, "accept", false))));
      }
      contracts.add(contract);
    }
    contracts.add(
        Findings.map(
            "symbol",
            "edge.emit",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0),
            "requiresLabel",
            "model-output"));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.publish",
            "arity",
            1,
            "kind",
            "sink",
            "channel",
            "release",
            "args",
            Arrays.asList(0)));
    contracts.add(
        Findings.map(
            "symbol",
            "edge.candidate_keep",
            "arity",
            1,
            "kind",
            "transform",
            "control",
            "preserve",
            "arg",
            0,
            "assurance",
            "candidate"));
    contracts.add(
        Findings.map(
            "symbol",
            "workflow.forward",
            "arity",
            0,
            "kind",
            "sink",
            "channel",
            "release",
            "boundary",
            "yield",
            "args",
            Arrays.asList(0),
            "valuePath",
            Arrays.asList("content"),
            "requiresLabel",
            "model-output"));
    return BusinessPolicy.parse(
        "bank-common", Json.COMPACT.toJson(Findings.map("version", 2, "contracts", contracts)));
  }

  private BusinessStreamTiming python(String source) throws Exception {
    BusinessPolicy policy = policy();
    return BusinessStreamTiming.analyze(
        BusinessPythonAnalysis.adapt(
            Arrays.asList(new SourceFile("workflow.py", source)), NEVER, policy),
        policy,
        NEVER);
  }

  private String stream(String body, String after) {
    return "import edge\ndef forward():\n    full = ''\n    for chunk in edge.stream():\n"
        + body
        + after;
  }

  private boolean has(BusinessStreamTiming timing, String order, String binding) {
    for (Map<String, Object> site : timing.sites)
      if (order.equals(site.get("ordering")) && binding.equals(site.get("valueBinding")))
        return true;
    return false;
  }

  private void noAccepted(BusinessStreamTiming timing) {
    for (Map<String, Object> site : timing.sites)
      assertNotEquals(site.toString(), "ACCEPTED_CHECK_PRECEDES_RELEASE", site.get("ordering"));
  }

  private void noDerived(BusinessStreamTiming timing) {
    for (Map<String, Object> site : timing.sites)
      assertNotEquals(
          site.toString(), "checked-value-derived-from-release", site.get("valueBinding"));
  }

  @Test
  public void appendedTokenRelatesToLaterAggregateWithoutApprovingEarlierRelease()
      throws Exception {
    BusinessStreamTiming timing =
        python(
            stream(
                "        full += chunk\n        yield {'content': chunk}\n",
                "    edge.quality(full)\n"));
    assertTrue(
        timing.sites.toString(),
        has(timing, "RELEASE_PRECEDES_MAPPED_CHECK", "checked-value-derived-from-release"));
    noAccepted(timing);
    for (Map<String, Object> site : timing.sites) {
      assertEquals("candidate", site.get("assurance"));
      assertEquals("open", site.get("failureMode"));
      assertTrue(
          ((List<?>) site.get("limits"))
              .contains("DERIVATION_IS_NOT_CONTENT_OR_GUARD_EQUIVALENCE"));
    }
  }

  @Test
  public void aggregateAcceptanceCannotApproveAnElement() throws Exception {
    BusinessStreamTiming timing =
        python(
            stream(
                "        full += chunk\n"
                    + "        if edge.check(full):\n"
                    + "            yield {'content': chunk}\n",
                ""));
    assertTrue(
        timing.sites.toString(),
        has(timing, "ORDER_UNRESOLVED", "checked-value-derived-from-release"));
    noAccepted(timing);
  }

  @Test
  public void reassigningAggregateRemovesTheOldDependency() throws Exception {
    BusinessStreamTiming timing =
        python(
            stream(
                "        full += chunk\n        yield {'content': chunk}\n",
                "    full = 'replacement'\n    edge.quality(full)\n"));
    noDerived(timing);
    noAccepted(timing);
  }

  @Test
  public void candidateTransformCannotClaimTheOriginalAggregateDependency() throws Exception {
    BusinessStreamTiming timing =
        python(
            stream(
                "        full += chunk\n        yield {'content': chunk}\n",
                "    full = edge.candidate_keep(full)\n    edge.quality(full)\n"));
    noDerived(timing);
    noAccepted(timing);
  }

  @Test
  public void ignoredCandidateTransformCannotRetainInputApprovalOrExceptionApproval()
      throws Exception {
    for (String body :
        Arrays.asList(
            "        edge.candidate_keep(chunk)\n        edge.emit(chunk)\n",
            "        try:\n            edge.candidate_keep(chunk)\n"
                + "        except Exception:\n            edge.emit(chunk)\n")) {
      BusinessStreamTiming timing =
          python(
              "import edge\ndef forward():\n"
                  + "    chunk = edge.stream()\n    if edge.check(chunk):\n"
                  + body);
      assertFalse(timing.sites.toString(), timing.sites.isEmpty());
      noAccepted(timing);
    }
  }

  @Test
  public void unknownMutationOfAggregateOrElementPreventsDependencyProof() throws Exception {
    for (String body :
        Arrays.asList(
            "        full += chunk\n        unknown(full)\n        yield {'content': chunk}\n",
            "        unknown(chunk)\n        full += chunk\n        yield {'content': chunk}\n")) {
      BusinessStreamTiming timing = python(stream(body, "    edge.quality(full)\n"));
      noDerived(timing);
      noAccepted(timing);
    }
  }

  @Test
  public void dynamicConcatenationCannotRetainAnEarlierOperandGuard() throws Exception {
    BusinessStreamTiming timing =
        python(
            "import edge\ndef forward():\n"
                + "    chunk = edge.stream()\n    if edge.check(chunk):\n"
                + "        full = '' + chunk\n        edge.emit(chunk)\n");
    noAccepted(timing);
    assertTrue(timing.sites.toString(), has(timing, "ORDER_UNRESOLVED", "unknown"));
  }

  @Test
  public void concatenationExceptionDoesNotRetainSuccessfulOperandProtection() throws Exception {
    BusinessStreamTiming timing =
        python(
            "import edge\n"
                + "def forward():\n"
                + "    chunk = edge.stream()\n"
                + "    if edge.check(chunk):\n"
                + "        try:\n"
                + "            full = '' + chunk\n"
                + "        except Exception:\n"
                + "            edge.emit(chunk)\n");
    noAccepted(timing);
    assertFalse(timing.sites.toString(), timing.sites.isEmpty());
  }

  @Test
  public void unrelatedStreamValueCannotBorrowAggregationDependency() throws Exception {
    BusinessStreamTiming timing =
        python(
            stream(
                "        full += edge.stream()\n        yield {'content': chunk}\n",
                "    edge.quality(full)\n"));
    noDerived(timing);
    noAccepted(timing);
  }

  @Test
  public void dictionaryGetterKeepsOnlyTheActualGuardedMember() throws Exception {
    BusinessStreamTiming timing =
        python(
            "import edge\ndef forward():\n"
                + "    chunk = edge.stream()\n    result = {'content': chunk}\n"
                + "    if edge.check(result.get('content')):\n        yield result\n");
    assertTrue(timing.sites.toString(), has(timing, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same"));
  }

  @Test
  public void branchLocalDictionaryWriteDoesNotModifyTheOtherBranch() throws Exception {
    BusinessStreamTiming timing =
        python(
            "import edge\ndef forward():\n"
                + "    chunk = edge.stream()\n    result = {'content': chunk}\n"
                + "    if edge.check(chunk):\n        if flag:\n"
                + "            result['content'] = edge.stream()\n        yield result\n");
    assertTrue(timing.sites.toString(), has(timing, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same"));
    assertTrue(timing.sites.toString(), has(timing, "ORDER_UNRESOLVED", "different"));
  }

  @Test
  public void nestedAliasMutationInvalidatesItsContainingObjectGuard() throws Exception {
    for (String extra : Arrays.asList("", "    outer = {'box': box}\n    box = outer\n")) {
      BusinessStreamTiming timing =
          python(
              "import edge\ndef forward():\n"
                  + "    inner = {'content': edge.stream()}\n    box = {'nested': inner}\n"
                  + extra
                  + "    if edge.check(box):\n        inner['content'] = edge.stream()\n"
                  + "        edge.publish(box)\n");
      noAccepted(timing);
      assertTrue(timing.sites.toString(), has(timing, "ORDER_UNRESOLVED", "different"));
    }
  }

  @Test
  public void nestedWriteDoesNotInvalidateAnUnrelatedGuardedSiblingValue() throws Exception {
    BusinessStreamTiming timing =
        python(
            "import edge\ndef forward():\n"
                + "    safe = edge.stream()\n    inner = {'content': edge.stream()}\n"
                + "    box = {'nested': inner, 'other': safe}\n    if edge.check(safe):\n"
                + "        inner['content'] = edge.stream()\n        edge.emit(safe)\n");
    assertTrue(timing.sites.toString(), has(timing, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same"));
  }

  @Test
  public void jsonParsingCannotHideAnUnapprovedFirstReleaseInCatch() throws Exception {
    for (String input : Arrays.asList("'{broken'", "payload", "'{\"key\":1,\"key\":2}'")) {
      BusinessStreamTiming timing =
          python(
              "import edge\n"
                  + "import json\n"
                  + "def forward():\n"
                  + "    chunk = edge.stream()\n"
                  + "    other = edge.stream()\n"
                  + "    if edge.check(chunk):\n"
                  + "        try:\n"
                  + "            parsed = json.loads("
                  + input
                  + ")\n"
                  + "        except Exception:\n"
                  + "            edge.emit(other)\n"
                  + "        edge.emit(chunk)\n");
      noAccepted(timing);
      boolean catchRelease = false;
      for (Map<String, Object> site : timing.sites)
        catchRelease |= Integer.valueOf(10).equals(site.get("line"));
      assertTrue(timing.sites.toString(), catchRelease);
    }
  }

  @Test
  public void duplicateJsonKeysCannotMakeNormalPathReleaseDisappear() throws Exception {
    BusinessStreamTiming timing =
        python(
            "import edge\nimport json\ndef forward():\n"
                + "    chunk = edge.stream()\n    parsed = json.loads('{\"key\":1,\"key\":2}')\n"
                + "    edge.emit(chunk)\n");
    assertFalse(timing.sites.toString(), timing.sites.isEmpty());
    noAccepted(timing);
  }

  @Test
  public void unknownFieldAccessAndMutationKeepUnapprovedCatchRelease() throws Exception {
    for (String operation :
        Arrays.asList(
            "result = opaque.get('key')", "opaque['key'] = chunk", "result = opaque.key")) {
      BusinessStreamTiming timing =
          python(
              "import edge\n"
                  + "def forward():\n"
                  + "    chunk = edge.stream()\n"
                  + "    other = edge.stream()\n"
                  + "    if edge.check(chunk):\n"
                  + "        try:\n"
                  + "            "
                  + operation
                  + "\n"
                  + "        except Exception:\n"
                  + "            edge.emit(other)\n"
                  + "        edge.emit(chunk)\n");
      noAccepted(timing);
      boolean catchRelease = false;
      for (Map<String, Object> site : timing.sites)
        catchRelease |= Integer.valueOf(9).equals(site.get("line"));
      assertTrue(timing.sites.toString(), catchRelease);
    }
  }

  @Test
  public void decisionFieldWriteCannotRetainAnEarlierConjunctiveApproval() throws Exception {
    BusinessStreamTiming timing =
        python(
            "import edge\ndef forward():\n"
                + "    chunk = edge.stream()\n    verdict = edge.judge(chunk)\n"
                + "    if edge.allowed(verdict) and not edge.needs_confirm(verdict):\n"
                + "        verdict.allowed = False\n        yield {'content': chunk}\n");
    noAccepted(timing);
  }

  private BusinessStreamTiming decision(String check, String condition, String extra)
      throws Exception {
    return python(
        "import edge\ndef forward():\n    chunk = edge.stream()\n"
            + "    verdict = edge."
            + check
            + "(chunk)\n"
            + extra
            + "    if "
            + condition
            + ":\n        yield {'content': chunk}\n");
  }

  @Test
  public void bothRequiredPredicatesOfOneDecisionCanControlTheSameValue() throws Exception {
    BusinessStreamTiming timing =
        decision("judge", "edge.allowed(verdict) and not edge.needs_confirm(verdict)", "");
    assertTrue(timing.sites.toString(), has(timing, "ACCEPTED_CHECK_PRECEDES_RELEASE", "same"));
  }

  @Test
  public void onePredicateOrDisjunctionCannotProveConjunction() throws Exception {
    for (String condition :
        Arrays.asList(
            "edge.allowed(verdict)",
            "edge.allowed(verdict) or not edge.needs_confirm(verdict)",
            "edge.allowed(verdict) and edge.needs_confirm(verdict)"))
      noAccepted(decision("judge", condition, ""));
  }

  @Test
  public void separateDecisionObjectsCannotSupplyEachOthersPredicates() throws Exception {
    noAccepted(
        decision(
            "judge",
            "edge.allowed(verdict) and not edge.needs_confirm(other)",
            "    other = edge.judge(chunk)\n"));
  }

  @Test
  public void oppositeReadsOfOneDecisionCannotCreateAReleasePath() throws Exception {
    BusinessStreamTiming timing =
        decision(
            "judge",
            "edge.allowed(verdict) and not edge.needs_confirm(verdict)"
                + " and edge.needs_confirm(verdict)",
            "");
    assertTrue(timing.sites.toString(), timing.sites.isEmpty());
  }

  @Test
  public void mutatedDecisionCannotSupplyAQualifiedPredicate() throws Exception {
    noAccepted(
        decision(
            "judge",
            "edge.allowed(verdict) and not edge.needs_confirm(verdict)",
            "    unknown(verdict)\n"));
  }

  @Test
  public void candidateOrOpenCompoundDecisionDoesNotBecomeProtection() throws Exception {
    for (String check : Arrays.asList("candidate", "open"))
      noAccepted(decision(check, "edge.allowed(verdict) and not edge.needs_confirm(verdict)", ""));
  }

  @Test
  public void asyncFunctionDoesNotAcquireSynchronousTimingFromValueDependency() throws Exception {
    String source =
        stream(
                "        full += chunk\n        yield {'content': chunk}\n",
                "    edge.quality(full)\n")
            .replace("def forward", "async def forward");
    BusinessStreamTiming timing = python(source);
    assertTrue(
        timing.sites.toString(),
        has(timing, "ORDER_UNRESOLVED", "checked-value-derived-from-release"));
    noAccepted(timing);
  }
}
