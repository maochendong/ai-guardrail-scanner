#!/usr/bin/env python3
"""Exercise the shipped MCP JAR in real JVM processes; never execute target projects."""
from report_schema import verify_unknowns, verified_report_content
import argparse
import hashlib
import json
from pathlib import Path
import queue
import re
import shutil
import subprocess
import threading
import time
import zipfile


def validate_runtimes(commands):
    """Require two real, distinct native runtimes before creating any matrix output."""
    if len(commands) != 2:
        raise ValueError('A Java 7/8 matrix requires exactly two --java executables.')
    executables = [str(Path(shutil.which(str(command)) or command).resolve()) for command in commands]
    if len(set(executables)) != 2:
        raise ValueError('Duplicate JVM executable; both Java 7 and Java 8 are required.')
    result = []
    for java in executables:
        version = subprocess.run([java, '-version'], text=True, capture_output=True,
                                 check=True, timeout=15)
        output = version.stdout + version.stderr
        matched = re.search(r'(?:java|openjdk) version "(1\.[78]\.[^"\s]+)"', output)
        if matched is None:
            raise ValueError('Expected an actual Java 7 or Java 8 runtime: ' + java)
        value = matched.group(1)
        result.append({'java': java, 'version': value, 'major': value[:3], 'versionOutput': output})
    if {row['major'] for row in result} != {'1.7', '1.8'}:
        raise ValueError('Runtime versions must cover both Java 7 and Java 8.')
    return result


class Client:
    def __init__(self, java, jar, roots, output, profile='generic', bank_policy=None):
        command = [str(java), '-Xmx768m', '-jar', str(jar), 'mcp']
        for root in roots:
            command += ['--allow-root', str(root)]
        command += ['--output', str(output), '--profile', profile]
        if bank_policy is not None:
            command += ['--bank-policy', str(bank_policy)]
        self.command = command
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, encoding='utf-8', bufsize=1)
        self.queue, self.sequence, self.transcript = queue.Queue(), 0, []
        def read():
            for line in self.process.stdout:
                try:
                    self.queue.put(json.loads(line))
                except json.JSONDecodeError:
                    self.queue.put({'invalidFrame': True})
            self.queue.put({'eof': True})
        threading.Thread(target=read, daemon=True).start()

    def rpc(self, method, params=None):
        self.sequence += 1
        request = {'jsonrpc': '2.0', 'id': self.sequence, 'method': method}
        if params is not None:
            request['params'] = params
        self.process.stdin.write(json.dumps(request) + '\n')
        self.process.stdin.flush()
        response = self.queue.get(timeout=150)
        assert response.get('id') == self.sequence, response
        assert 'error' not in response, response
        return response['result']

    def tool(self, name, arguments, error=False):
        response = self.rpc('tools/call', {'name': name, 'arguments': arguments})
        assert bool(response.get('isError')) == error, (name, response)
        value = json.loads(response['content'][0]['text'])
        self.transcript.append({'tool': name, 'arguments': arguments, 'isError': error, 'result': value})
        return value

    def initialize(self):
        value = self.rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                                        'clientInfo': {'name': 'native-jvm-verification', 'version': '0.9.0'}})
        self.process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        self.process.stdin.flush()
        assert value['serverInfo']['version'] == '0.9.0'
        return value

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise AssertionError('MCP process did not exit on EOF')
        stderr = self.process.stderr.read()
        assert self.process.returncode == 0, (self.process.returncode, stderr)
        return stderr


def stable_report(report):
    return {key: report[key] for key in ['schemaVersion', 'ruleSetVersion', 'sourceDigest',
                                        'project', 'complete', 'securityVerified', 'policy', 'gateDecision',
                                        'unknownSummary', 'mappingCoverage', 'assessments', 'diagnostics']}


def expected_ids(rules, languages, profile):
    ids = {rule['id'] for rule in rules if
           (rule['id'].startswith('AI-PY-') and 'python' in languages) or
           (rule['id'].startswith('AI-') and not rule['id'].startswith('AI-PY-') and 'java' in languages)}
    if profile != 'generic':
        ids.update(['BANK-DATA-001', 'BANK-IAM-001', 'BANK-GUARD-001'])
    if profile in ['bank-customer', 'bank-all']:
        ids.update(['BANK-CUST-001', 'BANK-CUST-002'])
    if profile in ['bank-internal', 'bank-all']:
        ids.update(['BANK-INTERNAL-001', 'BANK-INTERNAL-002'])
    return ids


def verify_policy(report, profile, bank_policy):
    assert report['complete'] is False and report['securityVerified'] is False
    assert report['policy']['profile'] == profile
    policy_input = json.loads(bank_policy.read_text()) if bank_policy is not None else {'version': 1, 'contracts': []}
    assert report['policy']['version'] == 'bank-policy-v' + str(policy_input['version']), report['policy']
    digest = report['policy']['digest']
    assert len(digest) == 64 and all(c in '0123456789abcdef' for c in digest)
    contracts = policy_input.get('contracts', [])
    assert report['policy']['contractCount'] == len(contracts)
    assert report['gateDecision'] == ('BLOCK' if any(
        a['disposition'] == 'VIOLATED' for a in report['assessments']) else 'REVIEW')



def main():
    if not __debug__:
        raise RuntimeError('Verification requires assertions; disable -O and PYTHONOPTIMIZE.')
    parser = argparse.ArgumentParser()
    parser.add_argument('--java', action='append', required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--project', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=['generic', 'bank-common', 'bank-customer', 'bank-internal', 'bank-all'], default='generic')
    parser.add_argument('--bank-policy', type=Path)
    parser.add_argument('--expect-java-functions', action='store_true')
    parser.add_argument('--expect-python-rag', action='store_true')
    parser.add_argument('--require-python-parse-success', action='store_true')
    parser.add_argument('--require-resolved-python-clients', action='store_true')
    parser.add_argument('--expect-python-guard-results', action='store_true')
    args = parser.parse_args()
    try:
        runtimes = validate_runtimes(args.java)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    args.output = args.output.resolve()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('--output must be new or empty so stale matrix evidence cannot be reused')
    if args.bank_policy is not None:
        args.bank_policy = args.bank_policy.resolve()
        assert args.bank_policy.is_file(), args.bank_policy
    args.project = [project.resolve() for project in args.project]
    args.output.mkdir(parents=True, exist_ok=True)
    cancellation_fixture = args.output.resolve() / 'cancellation-fixture'
    cancellation_fixture.mkdir(exist_ok=True)
    (cancellation_fixture / 'Cancel.java').write_text('class Cancel {\n' + ''.join(
        'int method%d() { return %d; }\n' % (i, i) for i in range(12000)) + '}\n')
    assert args.jar.is_file()
    classes = []
    with zipfile.ZipFile(args.jar) as jar:
        for name in jar.namelist():
            if name.endswith('.class'):
                data = jar.read(name)
                assert data[:4] == bytes.fromhex('cafebabe'), name
                major = int.from_bytes(data[6:8], 'big')
                assert major <= 51, (name, major)
                classes.append(major)
    summary = {'jar': str(args.jar.resolve()), 'sha256': hashlib.sha256(args.jar.read_bytes()).hexdigest(),
               'classCount': len(classes), 'maxClassMajor': max(classes), 'profile': args.profile,
               'requiredRuntimeMajors': ['1.7', '1.8'], 'verifiedRuntimeMajors': [], 'runtimes': []}
    reference = {}
    for index, runtime in enumerate(runtimes):
        java = runtime['java']
        runtime_output = args.output / ('runtime-' + str(index + 1))
        runtime_output.mkdir(exist_ok=True)
        version_text = runtime['versionOutput']
        client = Client(java, args.jar.resolve(), args.project + [cancellation_fixture],
                        runtime_output / 'reports', args.profile, args.bank_policy)
        row = dict(runtime, command=client.command, projects=[])
        try:
            row['initialize'] = client.initialize()
            assert len(client.rpc('tools/list')['tools']) == 5
            rules = client.tool('guardrail_rules', {})
            assert len(rules) == len({rule['id'] for rule in rules})
            assert len(rules) == 33, len(rules)
            row['ruleCount'] = len(rules)
            client.tool('guardrail_scan_start', {'repository': '/'}, error=True)
            client.tool('guardrail_scan_start', {'repository': 42}, error=True)
            client.tool('guardrail_scan_status', {'scanId': 'invalid'}, error=True)
            for project in args.project:
                started = time.monotonic()
                state = client.tool('guardrail_scan_start', {'repository': str(project)})
                scan_id, states = state['scanId'], [state['state']]
                while state['state'] == 'RUNNING':
                    time.sleep(.15)
                    state = client.tool('guardrail_scan_status', {'scanId': scan_id})
                    if states[-1] != state['state']:
                        states.append(state['state'])
                    assert time.monotonic() - started < 150
                assert state['state'] == 'COMPLETED', state
                formats = {fmt: client.tool('guardrail_scan_result', {'scanId': scan_id, 'format': fmt})
                           for fmt in ['json', 'markdown', 'sarif']}
                documents = {fmt: verified_report_content(result, fmt, state, runtime_output / 'reports', str(project))
                             for fmt, result in formats.items()}
                report = json.loads(documents['json'])
                sarif = json.loads(documents['sarif'])['runs'][0]
                assert report['runtime']['javaVersion'].startswith(('1.7.', '1.8.'))
                assert report['runtime']['javaVersion'] in version_text
                assert report['schemaVersion'] == '1.8'
                verify_policy(report, args.profile, args.bank_policy)
                assert {a['ruleId'] for a in report['assessments']} == expected_ids(
                    rules, report['project']['languages'], args.profile)
                assert state['policy'] == report['policy']
                assert state['gateDecision'] == report['gateDecision']
                verify_unknowns(report, state, sarif['properties'], documents['markdown'], str(project))
                assert report['runtime']['scannerVersion'] == '0.9.0'
                assert report['ruleSetVersion'] == 'java-python-guardrail-v10'
                if args.require_python_parse_success:
                    assert not any(d['code'] in ['PYTHON_PARSE_FAILED', 'PYTHON_PARSE_DEPTH',
                                                 'PYTHON_ANALYSIS_LIMIT', 'BANK_PYTHON_PARSE_FAILED',
                                                 'BANK_PYTHON_ANALYSIS_DEPTH', 'BANK_PYTHON_ANALYSIS_LIMIT']
                                   for d in report['diagnostics']), project
                if args.require_resolved_python_clients and report['project']['languages'] == ['python']:
                    assert not any(d['code'] == 'PYTHON_UNRESOLVED_MODEL_CALL'
                                   for d in report['diagnostics']), project
                if args.expect_python_guard_results and report['project']['languages'] == ['python']:
                    assert any(a['ruleId'] == 'AI-PY-007' and a['disposition'] == 'OBSERVED'
                               and 'consumer-result' in a['explanation']
                               for a in report['assessments']), project
                if args.expect_java_functions and report['project']['javaFiles']:
                    for rule in ['AI-GW-001', 'AI-FC-001', 'AI-FC-002', 'AI-FC-003']:
                        assert any(a['ruleId'] == rule and a['disposition'] == 'OBSERVED'
                                   for a in report['assessments']), (project, rule)
                if args.expect_python_rag and report['project']['languages'] == ['python']:
                    assert report['project']['aiDetected'] is True
                    for rule in ['AI-PY-001', 'AI-PY-004', 'AI-PY-005']:
                        assert any(a['ruleId'] == rule and a['disposition'] == 'OBSERVED'
                                   for a in report['assessments']), (project, rule)
                    assert not any(d['code'] in ['PYTHON_PARSE_FAILED', 'PYTHON_FLOW_LIMIT',
                                                 'PYTHON_ANALYSIS_LIMIT'] for d in report['diagnostics'])
                assert {item['ruleId'] for item in sarif['results']} == {
                    item['ruleId'] for item in report['assessments'] if item['disposition'] == 'VIOLATED'}
                assert sarif['properties']['project'] == report['project']
                assert sarif['properties']['policy'] == report['policy']
                assert sarif['properties']['gateDecision'] == report['gateDecision']
                assert sarif['properties']['securityVerified'] is False
                assert {item['domain'] for item in report['assessments']} == {'L' + str(i) for i in range(1, 8)}
                assert client.tool('guardrail_scan_cancel', {'scanId': scan_id}) == state
                client.tool('guardrail_scan_result', {'scanId': scan_id, 'format': 'raw'}, error=True)
                key = str(project)
                if key in reference:
                    assert stable_report(report) == reference[key], 'Cross-JVM evidence mismatch: ' + key
                else:
                    reference[key] = stable_report(report)
                counts = {d: sum(a['disposition'] == d for a in report['assessments'])
                          for d in ['VIOLATED', 'OBSERVED', 'UNKNOWN', 'NOT_APPLICABLE']}
                project_result = {'repository': key, 'scanId': scan_id, 'states': states,
                                  'seconds': round(time.monotonic() - started, 3), 'project': report['project'],
                                  'counts': counts, 'policy': report['policy'], 'gateDecision': report['gateDecision'],
                                  'unknownSummary': report['unknownSummary'], 'mappingCoverage': report['mappingCoverage'],
                                  'artifacts': formats['json']['artifacts']}
                row['projects'].append(project_result)
                print(json.dumps({'runtime': report['runtime']['javaVersion'], **project_result}, ensure_ascii=False), flush=True)
            cancelling = client.tool('guardrail_scan_start', {'repository': str(cancellation_fixture)})
            assert cancelling['state'] == 'RUNNING', cancelling
            cancelled = client.tool('guardrail_scan_cancel', {'scanId': cancelling['scanId']})
            assert cancelled['state'] == 'CANCELLED', cancelled
            assert client.tool('guardrail_scan_status', {'scanId': cancelling['scanId']}) == cancelled
            client.tool('guardrail_scan_result', {'scanId': cancelling['scanId']}, error=True)
            row['runningCancellationVerified'] = True
        except Exception as error:
            row['failure'] = {'type': type(error).__name__, 'message': str(error)}
            raise
        finally:
            (runtime_output / 'mcp-transcript.json').write_text(json.dumps(client.transcript, ensure_ascii=False, indent=2) + '\n')
            row['stderr'] = client.close()
            summary['runtimes'].append(row)
            (args.output / 'runtime-matrix.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
        assert not (runtime_output / 'reports' / cancelling['scanId']).exists(), 'Cancelled scan published reports'
        row['cancelledReportNotPublished'] = True
        initialize = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'recovery-verification', 'version': '1'}}}
        frames = (json.dumps(initialize).encode() + b'\n{invalid}\n\xff\n'
                  + b'{"jsonrpc":"2.0","id":2,"method":42}\n'
                  + b'{"jsonrpc":"2.0","id":3,"method":"ping"}\n')
        process = subprocess.Popen(client.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(frames, timeout=10)
        assert process.returncode == 0, stderr
        recovered = [json.loads(line) for line in stdout.splitlines()]
        assert len(recovered) == 5 and recovered[0]['id'] == 1, recovered
        assert [row['error']['code'] for row in recovered[1:4]] == [-32700, -32700, -32600], recovered
        assert all(row['id'] is None for row in recovered[1:4]), recovered
        assert recovered[4] == {'jsonrpc': '2.0', 'id': 3, 'result': {}}, recovered
        row['malformedFrameRecoveryVerified'] = True
        process = subprocess.Popen(client.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(b'x' * (1024 * 1024 + 1), timeout=10)
        assert process.returncode != 0 and not stdout, 'Oversize frame was not rejected'
        row['oversizeFrameRejected'] = True
    (args.output / 'stable-reports.json').write_text(json.dumps(reference, ensure_ascii=False, indent=2) + '\n')
    summary['verifiedRuntimeMajors'] = sorted(row['major'] for row in summary['runtimes'])
    assert summary['verifiedRuntimeMajors'] == summary['requiredRuntimeMajors']
    summary['crossRuntimeEquivalent'] = True
    summary['passed'] = True
    (args.output / 'runtime-matrix.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print('Native Java 7/8 matrix passed; shipped class major <= 51 and report evidence matches.', flush=True)


if __name__ == '__main__':
    main()
