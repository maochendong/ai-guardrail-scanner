import ast
import copy
import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('schema_matrix', SCRIPTS / 'verify-runtime-matrix.py')
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


def fixture():
    reason = {'category': 'UNSUPPORTED', 'code': 'RECEIVER_BINDING_UNRESOLVED',
              'explanation': 'receiver <binding> unresolved.'}
    location = {'path': 'src/A & B.java', 'line': 7, 'nodeId': 'src/A & B.java:7:sink'}
    actions = [
        {'kind': 'EXTEND_ANALYSIS', 'code': 'RESOLVE_RECEIVER_BINDING', 'status': 'OPEN',
         'ownerRole': '扫描器维护人员', 'reasonCodes': [reason['code']],
         'requiredEvidence': ['确认接收者构造与注入。'], 'locations': [location]},
        {'kind': 'VERIFY_RUNTIME', 'code': 'VERIFY_GUARD_FAIL_CLOSED', 'status': 'OPEN',
         'ownerRole': '应用测试与安全负责人', 'reasonCodes': [reason['code']],
         'requiredEvidence': ['提供异常与超时负测。'], 'locations': [location]},
    ]
    site = {'ruleId': 'BANK-GUARD-001', 'path': location['path'], 'line': 7,
            'symbol': 'sample.Port#release', 'disposition': 'UNKNOWN',
            'unknownCategory': 'UNSUPPORTED', 'unknownReasons': [reason],
            'evidence': [dict(location, role='sink', detail='Unresolved sink.')],
            'reviewActions': copy.deepcopy(actions), 'manualReviewRequired': True}
    assessment = {'ruleId': 'BANK-GUARD-001', 'disposition': 'VIOLATED', 'evidence': [],
                  'siteAssessments': [site], 'siteAssessmentsTruncated': False,
                  'controlReviewSites': [], 'controlReviewSitesTruncated': False,
                  'callContextSites': [], 'callContextSitesTruncated': False,
                  'streamTimingSites': [], 'streamTimingSitesTruncated': False,
                  'reviewActions': copy.deepcopy(actions), 'manualReviewRequired': True}
    counts = {'MISSING_MAPPING': 0, 'INSUFFICIENT_EVIDENCE': 0, 'UNSUPPORTED': 0}
    coverage = dict.fromkeys(['contractDefinitions', 'matchedDefinitions', 'matchedCallSites',
                             'matchedBoundarySites', 'candidateCallSites', 'argumentBindingFailures',
                             'analyzedFunctions', 'incompleteSourceFiles'], 0)
    coverage['sourceDigestMatched'] = True
    report = {'assessments': [assessment], 'unknownSummary': counts, 'diagnostics': [],
              'mappingCoverage': coverage, 'policy': {'profile': 'bank-all'}}
    state = {'unknownSummary': copy.deepcopy(counts), 'unknowns': 0,
             'mappingCoverage': copy.deepcopy(coverage)}
    exported = copy.deepcopy(assessment)
    exported['unknownReasons'] = []
    exported['siteAssessments'][0].pop('symbol')
    properties = {'unknownSummary': copy.deepcopy(counts), 'unknownAssessments': 0,
                  'unknownAssessmentsDetails': [], 'reviewAssessmentsDetails': [exported],
                  'contextAssessmentsDetails': [],
                  'mappingCoverage': copy.deepcopy(coverage)}
    markdown = '''# UNKNOWN 原因分类：缺少映射、证据不足、暂不支持
### BANK-GUARD-001 · Guard

必须人工复核：是。
- 复核动作 RESOLVE_RECEIVER_BINDING [EXTEND_ANALYSIS / OPEN]；负责角色：扫描器维护人员；原因：[RECEIVER_BINDING_UNRESOLVED]
  - 所需证据：确认接收者构造与注入。
  - 定位：src/A &#38; B.java 第 7 行
- 复核动作 VERIFY_GUARD_FAIL_CLOSED [VERIFY_RUNTIME / OPEN]；负责角色：应用测试与安全负责人；原因：[RECEIVER_BINDING_UNRESOLVED]
  - 所需证据：提供异常与超时负测。
  - 定位：src/A &#38; B.java 第 7 行

调用点 UNKNOWN：src/A &#38; B.java 第 7 行
- 调用点原因 RECEIVER_BINDING_UNRESOLVED：receiver &#60;binding&#62; unresolved.
调用点必须人工复核：是。
- 复核动作 RESOLVE_RECEIVER_BINDING [EXTEND_ANALYSIS / OPEN]；负责角色：扫描器维护人员；原因：[RECEIVER_BINDING_UNRESOLVED]
  - 所需证据：确认接收者构造与注入。
  - 定位：src/A &#38; B.java 第 7 行
- 复核动作 VERIFY_GUARD_FAIL_CLOSED [VERIFY_RUNTIME / OPEN]；负责角色：应用测试与安全负责人；原因：[RECEIVER_BINDING_UNRESOLVED]
  - 所需证据：提供异常与超时负测。
  - 定位：src/A &#38; B.java 第 7 行
'''
    return report, state, properties, markdown


def context_fixture():
    report, state, properties, markdown = fixture()
    parent = report['assessments'][0]
    parent['callContextSites'] = [{'callPath': 'src/A & B.java', 'callLine': 3,
                                 'calleePath': 'src/Service.java', 'calleeLine': 12,
                                 'binding': 'candidate', 'parameterStates': ['trusted', 'unknown']}]
    parent['streamTimingSites'] = [{'path': 'stream.py', 'line': 8, 'checkPath': 'stream.py',
                                   'checkLine': 10, 'ordering': 'RELEASE_PRECEDES_MAPPED_CHECK',
                                   'valueBinding': 'unknown', 'assurance': 'candidate',
                                   'failureMode': 'open', 'limits': ['本地边界不等于网络送达。']}]
    for field in ['callContextSites', 'streamTimingSites']:
        properties['reviewAssessmentsDetails'][0][field] = copy.deepcopy(parent[field])
    properties['contextAssessmentsDetails'] = copy.deepcopy(properties['reviewAssessmentsDetails'])
    markdown += '\n调用上下文：src/A &#38; B.java 第 3 行 → src/Service.java 第 12 行；绑定：candidate；参数身份：[trusted, unknown]\n'
    markdown += '\n首包时序：stream.py 第 8 行；检查：stream.py 第 10 行；顺序：RELEASE_PRECEDES_MAPPED_CHECK；值绑定：unknown；资格：candidate；失败语义：open\n'
    markdown += '- 时序限制：本地边界不等于网络送达。\n'
    return report, state, properties, markdown


def semantic_fixture():
    from report_schema import exported_detail
    report, state, properties, markdown = fixture()
    parent = report['assessments'][0]
    parent['ruleId'] = 'AI-GUARD-002'
    parent['siteAssessments'][0]['ruleId'] = 'AI-GUARD-002'
    report['policy']['digest'] = 'a' * 64
    parent['semanticOrigin'] = {'kind': 'external-api-contract', 'engine': 'BusinessAnalysis',
                                'policyDigest': 'a' * 64, 'language': 'java',
                                'sourceRuleIds': ['BANK-GUARD-001']}
    parent['semanticScope'] = 'MAPPED_LOCAL_SITES_ONLY'
    parent['semanticCoverageIncomplete'] = True
    properties['reviewAssessmentsDetails'] = [exported_detail(parent)]
    properties['semanticAssessmentsDetails'] = [exported_detail(parent)]
    provenance = ('语义来源：external-api-contract；引擎：BusinessAnalysis；策略摘要：' + 'a' * 64 +
                  '；来源规则：[BANK-GUARD-001]；语言：java。\n'
                  '语义范围：MAPPED_LOCAL_SITES_ONLY；覆盖仍不完整：true。\n')
    markdown = markdown.replace('### BANK-GUARD-001 · Guard\n',
                                '### AI-GUARD-002 · Guard\n' + provenance)
    return report, state, properties, markdown


class ReportSchemaTest(unittest.TestCase):
    def verify(self, data):
        matrix.verify_unknowns(*data, context='fixture')

    def test_semantic_provenance_round_trip(self):
        self.verify(semantic_fixture())

    def test_missing_semantic_sarif_is_rejected(self):
        data = semantic_fixture()
        del data[2]['semanticAssessmentsDetails']
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_wrong_semantic_policy_is_rejected(self):
        data = semantic_fixture()
        data[0]['policy']['digest'] = 'b' * 64
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_cross_language_semantic_site_is_rejected(self):
        data = semantic_fixture()
        data[0]['assessments'][0]['siteAssessments'][0]['path'] = 'other.py'
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_semantic_observed_cannot_hide_unknown_or_violated_sites(self):
        from report_schema import validate_semantics
        for disposition in ['UNKNOWN', 'VIOLATED']:
            report, _, _, markdown = semantic_fixture()
            parent = report['assessments'][0]
            parent['disposition'] = 'OBSERVED'
            parent['siteAssessments'][0]['disposition'] = disposition
            with self.assertRaisesRegex(AssertionError, 'unsafe semantic promotion'):
                validate_semantics(parent, markdown, report, 'fixture')

    def test_truncated_semantic_coverage_cannot_claim_complete(self):
        from report_schema import validate_semantics
        report, _, _, markdown = semantic_fixture()
        parent = report['assessments'][0]
        parent['siteAssessmentsTruncated'] = True
        parent['semanticCoverageIncomplete'] = False
        with self.assertRaisesRegex(AssertionError, 'truncated semantic coverage'):
            validate_semantics(parent, markdown, report, 'fixture')

    def test_stale_source_cannot_export_located_semantics(self):
        from report_schema import validate_semantics
        report, _, _, markdown = semantic_fixture()
        report['mappingCoverage']['sourceDigestMatched'] = False
        with self.assertRaisesRegex(AssertionError, 'stale semantic source binding'):
            validate_semantics(report['assessments'][0], markdown, report, 'fixture')

    def test_whole_rule_semantic_coverage_is_rejected(self):
        data = semantic_fixture()
        data[0]['assessments'][0]['semanticScope'] = 'WHOLE_APPLICATION'
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_missing_semantic_markdown_is_rejected(self):
        report, state, properties, markdown = semantic_fixture()
        markdown = '\n'.join(line for line in markdown.splitlines() if not line.startswith('语义来源：'))
        with self.assertRaises(AssertionError):
            self.verify((report, state, properties, markdown))

    def test_private_semantic_fields_are_not_exported(self):
        from report_schema import exported_detail
        item = semantic_fixture()[0]['assessments'][0]
        item['semanticOrigin']['privateContractBody'] = 'must not be exported'
        self.assertNotIn('privateContractBody', exported_detail(item)['semanticOrigin'])

    def test_violation_parent_keeps_unknown_site_review(self):
        self.verify(fixture())

    def test_context_and_timing_round_trip(self):
        self.verify(context_fixture())

    def test_missing_context_sarif_is_rejected(self):
        data = context_fixture()
        data[2]['contextAssessmentsDetails'] = []
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_candidate_check_cannot_claim_accepted_precheck(self):
        data = context_fixture()
        data[0]['assessments'][0]['streamTimingSites'][0]['ordering'] = 'ACCEPTED_CHECK_PRECEDES_RELEASE'
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_derived_stream_relation_round_trip_keeps_its_limitation(self):
        report, state, properties, markdown = context_fixture()
        relation = 'checked-value-derived-from-release'
        limit = 'DERIVATION_IS_NOT_CONTENT_OR_GUARD_EQUIVALENCE'
        for assessment in [report['assessments'][0], properties['reviewAssessmentsDetails'][0],
                           properties['contextAssessmentsDetails'][0]]:
            assessment['streamTimingSites'][0]['valueBinding'] = relation
            assessment['streamTimingSites'][0]['limits'].append(limit)
        markdown = markdown.replace('值绑定：unknown', '值绑定：' + relation)
        markdown += '- 时序限制：' + limit + '\n'
        self.verify((report, state, properties, markdown))

    def test_derived_stream_relation_cannot_authorize_or_hide_its_limit(self):
        from report_schema import validate_context
        for missing_limit in [True, False]:
            report, _, _, markdown = context_fixture()
            item = report['assessments'][0]
            item['callContextSites'] = []
            site = item['streamTimingSites'][0]
            site.update(valueBinding='checked-value-derived-from-release', assurance='reviewed', failureMode='closed')
            if not missing_limit:
                site['limits'].append('DERIVATION_IS_NOT_CONTENT_OR_GUARD_EQUIVALENCE')
                site['ordering'] = 'ACCEPTED_CHECK_PRECEDES_RELEASE'
            with self.assertRaisesRegex(AssertionError, 'derived stream value lacks limitation|unqualified accepted check'):
                validate_context(item, markdown, 'fixture')

    def test_timing_missing_check_location_is_rejected(self):
        data = context_fixture()
        data[0]['assessments'][0]['streamTimingSites'][0]['checkLine'] = 0
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_derived_stream_relation_requires_check_location_even_when_order_unresolved(self):
        from report_schema import validate_context
        report, _, _, markdown = context_fixture()
        item = report['assessments'][0]
        item['callContextSites'] = []
        site = item['streamTimingSites'][0]
        site.update(valueBinding='checked-value-derived-from-release', ordering='ORDER_UNRESOLVED',
                    checkPath='', checkLine=0)
        site['limits'].append('DERIVATION_IS_NOT_CONTENT_OR_GUARD_EQUIVALENCE')
        with self.assertRaisesRegex(AssertionError, 'derived stream value lacks check location'):
            validate_context(item, markdown, 'fixture')

    def test_context_unknown_identity_cannot_be_encoded_as_trusted_boolean(self):
        data = context_fixture()
        data[0]['assessments'][0]['callContextSites'][0]['parameterStates'][0] = True
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_missing_context_truncation_is_rejected(self):
        for field in ['callContextSitesTruncated', 'streamTimingSitesTruncated']:
            data = context_fixture()
            del data[0]['assessments'][0][field]
            with self.assertRaises(AssertionError):
                self.verify(data)

    def test_missing_markdown_context_or_timing_is_rejected(self):
        for line in ['调用上下文：', '首包时序：', '- 时序限制：']:
            report, state, properties, markdown = context_fixture()
            markdown = '\n'.join(part for part in markdown.splitlines() if not part.startswith(line))
            with self.assertRaises(AssertionError):
                self.verify((report, state, properties, markdown))

    def test_private_context_fields_are_not_sarif_metadata(self):
        from report_schema import exported_detail
        data = context_fixture()
        parent = data[0]['assessments'][0]
        for field in ['callContextSites', 'streamTimingSites']:
            parent[field][0]['symbol'] = 'private.Type#method'
            self.assertNotIn('symbol', exported_detail(parent)[field][0])

    def test_duplicate_rule_sections_are_consumed_in_assessment_order(self):
        report, state, properties, markdown = fixture()
        unknown = report['assessments'][0]
        unknown.update(disposition='UNKNOWN', unknownCategory='UNSUPPORTED',
                       unknownReasons=copy.deepcopy(unknown['siteAssessments'][0]['unknownReasons']))
        exported = properties['reviewAssessmentsDetails'].pop()
        exported.update(disposition='UNKNOWN', unknownCategory='UNSUPPORTED',
                        unknownReasons=copy.deepcopy(unknown['unknownReasons']))
        later, later_exported = copy.deepcopy(unknown), copy.deepcopy(exported)
        for item in [later, later_exported]:
            item['unknownReasons'][0]['explanation'] = 'another receiver is unresolved.'
            item['siteAssessments'][0]['unknownReasons'][0]['explanation'] = 'another receiver is unresolved.'
        observed = dict(unknown, disposition='OBSERVED', unknownReasons=[],
                        siteAssessments=[], reviewActions=[], manualReviewRequired=False)
        observed.pop('unknownCategory')
        report['assessments'] = [observed, unknown, later]
        properties['unknownAssessmentsDetails'] = [exported, later_exported]
        for container in [report, state, properties]:
            container['unknownSummary']['UNSUPPORTED'] = 2
        state['unknowns'] = properties['unknownAssessments'] = 2
        title = '### BANK-GUARD-001 · Guard\n'
        unknown_markdown = markdown[markdown.index(title):].replace(title, title +
            '- 原因 RECEIVER_BINDING_UNRESOLVED [UNSUPPORTED（暂不支持）]：receiver &#60;binding&#62; unresolved.\n', 1)
        later_markdown = unknown_markdown.replace('receiver &#60;binding&#62; unresolved.',
                                                  'another receiver is unresolved.')
        observed_markdown = title + '必须人工复核：否。\n'
        prefix = '# UNKNOWN 原因分类：缺少映射、证据不足、暂不支持\n'
        self.verify((report, state, properties,
                     prefix + observed_markdown + unknown_markdown + later_markdown))
        with self.assertRaises(AssertionError):
            self.verify((report, state, properties,
                         prefix + observed_markdown + later_markdown + unknown_markdown))

    def test_missing_sarif_review_under_violated_parent_is_rejected(self):
        data = fixture()
        data[2]['reviewAssessmentsDetails'] = []
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_unknown_parent_exports_complete_site_and_action_details(self):
        data = fixture()
        report, state, properties, markdown = data
        parent = report['assessments'][0]
        parent['disposition'] = 'UNKNOWN'
        parent['unknownCategory'] = 'UNSUPPORTED'
        parent['unknownReasons'] = copy.deepcopy(parent['siteAssessments'][0]['unknownReasons'])
        for container in [report, state, properties]:
            container['unknownSummary']['UNSUPPORTED'] = 1
        state['unknowns'] = properties['unknownAssessments'] = 1
        exported = properties['reviewAssessmentsDetails'].pop()
        exported.update(disposition='UNKNOWN', unknownCategory='UNSUPPORTED',
                        unknownReasons=copy.deepcopy(parent['unknownReasons']))
        properties['unknownAssessmentsDetails'] = [exported]
        markdown = markdown.replace('### BANK-GUARD-001 · Guard\n',
                                    '### BANK-GUARD-001 · Guard\n'
                                    '- 原因 RECEIVER_BINDING_UNRESOLVED [UNSUPPORTED（暂不支持）]：receiver &#60;binding&#62; unresolved.\n')
        self.verify((report, state, properties, markdown))
        del exported['siteAssessments']
        with self.assertRaises(AssertionError):
            self.verify((report, state, properties, markdown))

    def test_unknown_site_requires_its_own_primary_reason(self):
        data = fixture()
        data[0]['assessments'][0]['siteAssessments'][0]['unknownCategory'] = 'INSUFFICIENT_EVIDENCE'
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_parent_cannot_drop_actions_even_if_sarif_drops_them_too(self):
        data = fixture()
        parent = data[0]['assessments'][0]
        parent['reviewActions'] = []
        parent['manualReviewRequired'] = False
        data[2]['reviewAssessmentsDetails'] = []
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_manual_review_flag_and_action_kinds_must_agree(self):
        data = fixture()
        data[0]['assessments'][0]['manualReviewRequired'] = False
        data[2]['reviewAssessmentsDetails'][0]['manualReviewRequired'] = False
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_sarif_cannot_change_site_action_ownership(self):
        data = fixture()
        data[2]['reviewAssessmentsDetails'][0]['siteAssessments'][0]['reviewActions'][0]['ownerRole'] = '其他人'
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_action_must_reference_a_causal_reason(self):
        data = fixture()
        data[0]['assessments'][0]['siteAssessments'][0]['reviewActions'][0]['reasonCodes'] = ['UNRELATED_REASON']
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_markdown_must_include_precise_site_reason_and_action_evidence(self):
        for old, replacement in [
                ('receiver &#60;binding&#62; unresolved.', 'another explanation'),
                ('调用点 UNKNOWN：src/A &#38; B.java 第 7 行', '调用点 UNKNOWN：other.java 第 7 行'),
                ('调用点必须人工复核：是。', '调用点必须人工复核：否。'),
                ('  - 所需证据：提供异常与超时负测。', ''),
                ('负责角色：应用测试与安全负责人', '负责角色：未指定')]:
            with self.subTest(missing=old):
                report, state, properties, markdown = fixture()
                with self.assertRaises(AssertionError):
                    self.verify((report, state, properties, markdown.replace(old, replacement)))

    def test_truncated_sites_require_visible_markdown_boundary(self):
        data = fixture()
        data[0]['assessments'][0]['siteAssessmentsTruncated'] = True
        data[2]['reviewAssessmentsDetails'][0]['siteAssessmentsTruncated'] = True
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_existing_count_mapping_and_diagnostic_checks_remain_enforced(self):
        for mutation in ['counts', 'coverage', 'diagnostic']:
            with self.subTest(mutation=mutation):
                data = fixture()
                if mutation == 'counts':
                    data[1]['unknowns'] = 1
                elif mutation == 'coverage':
                    data[2]['mappingCoverage']['candidateCallSites'] = -1
                else:
                    data[0]['diagnostics'].append({'code': 'BROKEN', 'category': 'other'})
                with self.assertRaises(AssertionError):
                    self.verify(data)

    def control_fixture(self):
        report, state, properties, markdown = fixture()
        parent = report['assessments'][0]
        parent['controlReviewSites'] = parent['siteAssessments']
        parent['siteAssessments'] = []
        parent['mappedPathOutcomes'] = 1
        exported = properties['reviewAssessmentsDetails'][0]
        exported['controlReviewSites'] = exported['siteAssessments']
        exported['siteAssessments'] = []
        exported['mappedPathOutcomes'] = 1
        markdown = markdown.replace('调用点 UNKNOWN：', '控制复核 UNKNOWN：').replace(
            '- 调用点原因 ', '- 控制复核原因 ').replace('调用点必须人工复核：', '控制复核必须人工复核：')
        return report, state, properties, markdown

    def test_control_reviews_export_separately_without_becoming_unknown_assessments(self):
        data = self.control_fixture()
        self.verify(data)
        self.assertEqual(0, data[1]['unknowns'])
        self.assertEqual(0, data[2]['unknownAssessments'])
        self.assertEqual(1, data[0]['assessments'][0]['mappedPathOutcomes'])

    def test_sarif_cannot_relabel_control_review_as_reached_output(self):
        data = self.control_fixture()
        exported = data[2]['reviewAssessmentsDetails'][0]
        exported['siteAssessments'] = exported['controlReviewSites']
        exported['controlReviewSites'] = []
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_unknown_control_primary_reason_is_validated(self):
        data = self.control_fixture()
        data[0]['assessments'][0]['controlReviewSites'][0]['unknownCategory'] = 'MISSING_MAPPING'
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_control_review_cannot_claim_an_observed_or_violated_output(self):
        for disposition in ['OBSERVED', 'VIOLATED']:
            data = self.control_fixture()
            data[0]['assessments'][0]['controlReviewSites'][0]['disposition'] = disposition
            with self.assertRaises(AssertionError):
                self.verify(data)

    def test_control_truncation_needs_its_own_markdown_warning(self):
        report, state, properties, markdown = self.control_fixture()
        report['assessments'][0]['controlReviewSitesTruncated'] = True
        properties['reviewAssessmentsDetails'][0]['controlReviewSitesTruncated'] = True
        with self.assertRaises(AssertionError):
            self.verify((report, state, properties, markdown + '\n调用点评估列表已截断\n'))
        self.verify((report, state, properties,
                     markdown + '\n控制复核列表已截断；复核动作未覆盖全部控制调用。\n'))

    def test_bank_report_cannot_silently_omit_control_review_schema(self):
        data = fixture()
        for parent in [data[0]['assessments'][0], data[2]['reviewAssessmentsDetails'][0]]:
            del parent['controlReviewSites']
            del parent['controlReviewSitesTruncated']
        with self.assertRaises(AssertionError):
            self.verify(data)

    def test_both_runtime_and_codex_use_the_same_schema_gate(self):
        for name in ['verify-runtime-matrix.py', 'verify-codex-integration.py']:
            tree = ast.parse((SCRIPTS / name).read_text())
            imports = [node for node in tree.body if isinstance(node, ast.ImportFrom)
                       and node.module == 'report_schema']
            self.assertEqual(1, len(imports), name)
            self.assertIn('verify_unknowns', [alias.name for alias in imports[0].names])
            self.assertFalse(any(isinstance(node, ast.FunctionDef) and node.name == 'verify_unknowns'
                                 for node in tree.body), name)
            values = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                      and isinstance(node.value, str)}
            self.assertTrue({'0.9.0', '1.8', 'java-python-guardrail-v10'} <= values, name)
            self.assertTrue({'0.5.1', '1.4', 'java-python-guardrail-v6'}.isdisjoint(values), name)


if __name__ == '__main__':
    unittest.main()
