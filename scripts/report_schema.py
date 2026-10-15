"""Shared report acceptance checks for native JVM and installed Codex verification."""
import html
import json

if not __debug__:
    raise RuntimeError('Verification requires assertions; disable -O and PYTHONOPTIMIZE.')

CATEGORIES = {'MISSING_MAPPING', 'INSUFFICIENT_EVIDENCE', 'UNSUPPORTED'}
ACTION_KINDS = {'MAP_API', 'EXTEND_ANALYSIS', 'CONFIRM_SCOPE', 'VERIFY_RUNTIME', 'TRIAGE_EVIDENCE'}
MANUAL_KINDS = {'CONFIRM_SCOPE', 'VERIFY_RUNTIME'}
DETAIL_FIELDS = ['ruleId', 'domain', 'disposition', 'severity', 'title', 'explanation',
                 'recommendation', 'limitations', 'profile', 'mappedPathOutcomes',
                 'unknownCategory', 'manualReviewRequired', 'siteAssessmentsTruncated',
                 'controlReviewSitesTruncated']
SITE_FIELDS = ['ruleId', 'disposition', 'unknownCategory', 'unknownReasons', 'evidence',
               'reviewActions', 'manualReviewRequired']
SITE_GROUPS = [('siteAssessments', '调用点', '调用点评估列表已截断'),
               ('controlReviewSites', '控制复核', '控制复核列表已截断')]


def selected(item, fields):
    return {key: item[key] for key in fields if key in item}


def exported_detail(item):
    """The SARIF metadata allowlist deliberately excludes symbols and analysis internals."""
    result = selected(item, DETAIL_FIELDS)
    result['unknownReasons'] = [selected(reason, ['category', 'code', 'explanation'])
                                for reason in item.get('unknownReasons', [])]
    result['evidence'] = [selected(evidence, ['path', 'line', 'detail', 'role', 'nodeId'])
                          for evidence in item.get('evidence', [])]
    if 'reviewActions' in item:
        result['reviewActions'] = []
        for action in item['reviewActions']:
            safe = selected(action, ['kind', 'code', 'status', 'ownerRole', 'reasonCodes', 'requiredEvidence'])
            safe['locations'] = [selected(location, ['path', 'line', 'nodeId'])
                                 for location in action['locations']]
            result['reviewActions'].append(safe)
    for field, _, _ in SITE_GROUPS:
        if field in item:
            result[field] = [dict(exported_detail(selected(site, SITE_FIELDS)),
                                  **selected(site, ['path', 'line'])) for site in item[field]]
    return result


def md_value(value):
    # Reports.escape renders controls and bidi marks as spaces, then escapes ASCII punctuation.
    return ''.join(' ' if ord(char) < 32 or 127 <= ord(char) <= 159
                   or 0x202a <= ord(char) <= 0x202e or 0x2066 <= ord(char) <= 0x2069
                   else char for char in str(value))


def validate_reasons(item, tag):
    reasons = item.get('unknownReasons', [])
    assert isinstance(reasons, list), (tag, 'invalid UNKNOWN reasons')
    if item['disposition'] == 'UNKNOWN':
        assert item.get('unknownCategory') in CATEGORIES, (tag, 'missing UNKNOWN category')
        assert reasons, (tag, 'missing UNKNOWN reasons')
        assert reasons[0]['category'] == item['unknownCategory'], (tag, 'primary reason mismatch')
    for reason in reasons:
        assert set(reason) == {'category', 'code', 'explanation'}, (tag, reason)
        assert reason['category'] in CATEGORIES, (tag, reason)
        assert all(isinstance(reason[key], str) and reason[key] for key in ['code', 'explanation']), (tag, reason)
    assert len(reasons) == len({json.dumps(r, sort_keys=True) for r in reasons}), (tag, 'duplicate reasons')
    return {reason['code'] for reason in reasons}


def validate_review(item, allowed_codes, markdown, tag, prefix=''):
    required = item['disposition'] == 'UNKNOWN' or any(item.get(field) for field, _, _ in SITE_GROUPS)
    if not required and 'reviewActions' not in item:
        return
    actions = item.get('reviewActions')
    assert isinstance(actions, list), (tag, 'missing review actions')
    if item['disposition'] == 'UNKNOWN':
        assert actions, (tag, 'UNKNOWN has no review action')
    assert type(item.get('manualReviewRequired')) is bool, (tag, 'missing manual review flag')
    manual = any(action.get('kind') in MANUAL_KINDS for action in actions)
    assert item['manualReviewRequired'] == manual, (tag, 'manual review flag mismatch')
    assert prefix + '必须人工复核：' + ('是' if manual else '否') + '。' in markdown, (tag, 'Markdown manual review flag missing')
    keys, explained = set(), set()
    for action in actions:
        assert set(action) == {'kind', 'code', 'status', 'ownerRole', 'reasonCodes', 'requiredEvidence', 'locations'}, (tag, action)
        assert action['kind'] in ACTION_KINDS and action['status'] == 'OPEN', (tag, action)
        assert all(isinstance(action[key], str) and action[key] for key in ['code', 'ownerRole']), (tag, action)
        key = (action['kind'], action['code'])
        assert key not in keys, (tag, 'duplicate review action', key)
        keys.add(key)
        for field in ['reasonCodes', 'requiredEvidence']:
            values = action[field]
            assert isinstance(values, list) and values and all(isinstance(value, str) and value for value in values), (tag, field, action)
            assert len(values) == len(set(values)), (tag, 'duplicate action values', field)
        assert set(action['reasonCodes']) <= allowed_codes, (tag, 'action refers to unrelated reason', action)
        explained.update(action['reasonCodes'])
        line = '- 复核动作 {code} [{kind} / {status}]；负责角色：{ownerRole}；原因：[{reasons}]'.format(
            **{key: md_value(action[key]) for key in ['code', 'kind', 'status', 'ownerRole']},
            reasons=', '.join(md_value(code) for code in action['reasonCodes']))
        assert line in markdown, (tag, 'Markdown exact action missing', action['code'])
        for evidence in action['requiredEvidence']:
            assert '所需证据：' + md_value(evidence) in markdown, (tag, 'Markdown required evidence missing')
        assert isinstance(action['locations'], list), (tag, 'invalid action locations')
        for location in action['locations']:
            assert set(location) <= {'path', 'line', 'nodeId'}, (tag, location)
            assert isinstance(location.get('path'), str) and type(location.get('line')) is int and location['line'] > 0, (tag, location)
            if 'nodeId' in location:
                assert isinstance(location['nodeId'], str) and location['nodeId'], (tag, location)
            assert '定位：{} 第 {} 行'.format(md_value(location['path']), location['line']) in markdown, (tag, 'Markdown action location missing')
    assert allowed_codes <= explained, (tag, 'reason has no review action', allowed_codes - explained)


def before_next_site(section):
    ends = [section.find('\n' + prefix + ' UNKNOWN：') for _, prefix, _ in SITE_GROUPS]
    return section[:min(end for end in ends if end >= 0)] if any(end >= 0 for end in ends) else section


def verify_unknowns(report, state, sarif_properties, markdown, context):
    unknown = [item for item in report['assessments'] if item['disposition'] == 'UNKNOWN']
    counts = dict.fromkeys(sorted(CATEGORIES), 0)
    plain = '\n' + html.unescape(markdown)
    section_cursor = 0
    for item in report['assessments']:
        tag = (context, item['ruleId'])
        codes = validate_reasons(item, tag)
        if item['disposition'] == 'UNKNOWN':
            counts[item['unknownCategory']] += 1
        marker = '\n### ' + md_value(item['ruleId']) + ' · '
        start = plain.find('\n### ', section_cursor)
        assert start >= 0 and plain.startswith(marker, start), (tag, 'Markdown rule evidence missing or out of order')
        end = plain.find('\n### ', start + len(marker))
        section_cursor = len(plain) if end < 0 else end
        section = plain[start + len(marker):section_cursor]
        parent_section = before_next_site(section)
        if item['disposition'] == 'UNKNOWN':
            labels = {'MISSING_MAPPING': '缺少映射', 'INSUFFICIENT_EVIDENCE': '证据不足', 'UNSUPPORTED': '暂不支持'}
            for reason in item['unknownReasons']:
                expected = '- 原因 {} [{}（{}）]：{}'.format(md_value(reason['code']), reason['category'], labels[reason['category']], md_value(reason['explanation']))
                assert expected in parent_section, (tag, 'Markdown exact reason missing', reason['code'])
        for field, prefix, truncated_message in SITE_GROUPS:
            sites = item.get(field, [])
            assert isinstance(sites, list), (tag, 'invalid site assessments', field)
            if item['ruleId'].startswith('BANK-') or field in item:
                assert field in item and type(item.get(field + 'Truncated')) is bool and len(sites) <= 128, (tag, 'invalid site assessment bound', field)
            for site in sites:
                site_tag = (tag, field, site.get('path'), site.get('line'))
                assert site.get('ruleId') == item['ruleId'], (site_tag, 'site rule mismatch')
                states = {'UNKNOWN'} if field == 'controlReviewSites' else {'UNKNOWN', 'OBSERVED', 'VIOLATED'}
                assert site.get('disposition') in states, (site_tag, 'invalid site disposition')
                assert isinstance(site.get('path'), str) and type(site.get('line')) is int and site['line'] > 0, (site_tag, 'invalid site location')
                site_codes = validate_reasons(site, site_tag)
                codes.update(site_codes)
                if site['disposition'] == 'UNKNOWN':
                    site_marker = '{} UNKNOWN：{} 第 {} 行'.format(prefix, md_value(site['path']), site['line'])
                    assert site_marker in section, (site_tag, 'Markdown unknown site missing')
                    site_section = before_next_site(section.split(site_marker, 1)[1])
                    for reason in site['unknownReasons']:
                        assert '- {}原因 {}：{}'.format(prefix, md_value(reason['code']), md_value(reason['explanation'])) in site_section, (site_tag, 'Markdown exact site reason missing')
                    validate_review(site, site_codes, site_section, site_tag, prefix=prefix)
                    for action in site['reviewActions']:
                        parents = [candidate for candidate in item.get('reviewActions', []) if (candidate['kind'], candidate['code']) == (action['kind'], action['code'])]
                        assert len(parents) == 1, (site_tag, 'parent lost site review action')
                        assert set(action['reasonCodes']) <= set(parents[0]['reasonCodes']), (site_tag, 'parent lost site reason')
                        assert all(location in parents[0]['locations'] for location in action['locations']), (site_tag, 'parent lost site location')
            if item.get(field + 'Truncated'):
                assert truncated_message in section, (tag, 'Markdown truncated site warning missing', field)
        validate_review(item, codes, parent_section, tag)
    assert report.get('unknownSummary') == counts, (context, 'report UNKNOWN counts')
    assert state.get('unknownSummary') == counts, (context, 'status UNKNOWN counts')
    assert state['unknowns'] == sum(counts.values()), (context, 'status UNKNOWN total')
    assert sarif_properties.get('unknownSummary') == counts, (context, 'SARIF UNKNOWN counts')
    assert sarif_properties.get('unknownAssessments') == len(unknown), (context, 'SARIF legacy UNKNOWN total')
    assert sarif_properties.get('unknownAssessmentsDetails') == [exported_detail(item) for item in unknown], (context, 'SARIF UNKNOWN details differ')
    reviews = [exported_detail(item) for item in report['assessments'] if item['disposition'] != 'UNKNOWN' and item.get('reviewActions')]
    assert sarif_properties.get('reviewAssessmentsDetails') == reviews, (context, 'SARIF review details differ')
    assert all(d.get('category') in CATEGORIES for d in report['diagnostics']), (context, 'unclassified diagnostics')
    assert 'UNKNOWN 原因分类' in markdown and all(label in markdown for label in ['缺少映射', '证据不足', '暂不支持']), (context, 'Markdown UNKNOWN breakdown missing')
    coverage = report.get('mappingCoverage')
    assert isinstance(coverage, dict), (context, 'mapping coverage missing')
    assert state.get('mappingCoverage') == coverage, (context, 'status mapping coverage differs')
    assert sarif_properties.get('mappingCoverage') == coverage, (context, 'SARIF mapping coverage differs')
    if report['policy']['profile'] != 'generic':
        for key in ['contractDefinitions', 'matchedDefinitions', 'matchedCallSites', 'matchedBoundarySites', 'candidateCallSites', 'argumentBindingFailures', 'analyzedFunctions', 'incompleteSourceFiles']:
            assert type(coverage.get(key)) is int and coverage[key] >= 0, (context, 'invalid mapping count', key)
        assert coverage['matchedDefinitions'] <= coverage['contractDefinitions'], (context, 'mapping definition counts')
        assert type(coverage.get('sourceDigestMatched')) is bool, (context, 'missing source binding result')
