#!/usr/bin/env python3
"""Exercise the shipped MCP JAR in real JVM processes; never execute target projects."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import threading
import time
import zipfile


class Client:
    def __init__(self, java, jar, roots, output):
        command = [str(java), '-Xmx768m', '-jar', str(jar), 'mcp']
        for root in roots:
            command += ['--allow-root', str(root)]
        command += ['--output', str(output)]
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
                                        'clientInfo': {'name': 'native-jvm-verification', 'version': '0.3.1'}})
        self.process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        self.process.stdin.flush()
        assert value['serverInfo']['version'] == '0.3.1'
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


def stable(report):
    return {key: report[key] for key in ['schemaVersion', 'ruleSetVersion', 'sourceDigest',
                                        'project', 'complete', 'securityVerified', 'assessments', 'diagnostics']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--java', action='append', required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--project', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expect-java-functions', action='store_true')
    parser.add_argument('--expect-python-rag', action='store_true')
    parser.add_argument('--require-python-parse-success', action='store_true')
    parser.add_argument('--require-resolved-python-clients', action='store_true')
    parser.add_argument('--expect-python-guard-results', action='store_true')
    args = parser.parse_args()
    args.output = args.output.resolve()
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
               'classCount': len(classes), 'maxClassMajor': max(classes), 'runtimes': []}
    reference = {}
    for index, java in enumerate(args.java):
        runtime_output = args.output / ('runtime-' + str(index + 1))
        runtime_output.mkdir(exist_ok=True)
        version = subprocess.run([java, '-version'], text=True, capture_output=True, check=True)
        version_text = version.stdout + version.stderr
        client = Client(java, args.jar.resolve(), args.project + [cancellation_fixture], runtime_output / 'reports')
        row = {'java': java, 'versionOutput': version_text, 'command': client.command, 'projects': []}
        try:
            row['initialize'] = client.initialize()
            assert len(client.rpc('tools/list')['tools']) == 5
            rules = client.tool('guardrail_rules', {})
            assert len(rules) == len({rule['id'] for rule in rules})
            assert len(rules) >= 26, len(rules)
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
                for fmt, result in formats.items():
                    assert not result['contentOmitted'], (project, fmt)
                    assert Path(result['artifacts'][fmt]).read_text() == result['content']
                report = json.loads(formats['json']['content'])
                sarif = json.loads(formats['sarif']['content'])['runs'][0]
                assert report['runtime']['javaVersion'].startswith(('1.7.', '1.8.'))
                assert report['runtime']['javaVersion'] in version_text
                assert report['securityVerified'] is False
                assert report['runtime']['scannerVersion'] == '0.3.1'
                assert report['ruleSetVersion'] == 'java-python-guardrail-v3.1'
                if args.require_python_parse_success:
                    assert not any(d['code'] in ['PYTHON_PARSE_FAILED', 'PYTHON_PARSE_DEPTH',
                                                 'PYTHON_ANALYSIS_LIMIT'] for d in report['diagnostics']), project
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
                assert {item['domain'] for item in report['assessments']} == {'L' + str(i) for i in range(1, 8)}
                assert client.tool('guardrail_scan_cancel', {'scanId': scan_id}) == state
                client.tool('guardrail_scan_result', {'scanId': scan_id, 'format': 'raw'}, error=True)
                key = str(project)
                if key in reference:
                    assert stable(report) == reference[key], 'Cross-JVM evidence mismatch: ' + key
                else:
                    reference[key] = stable(report)
                counts = {d: sum(a['disposition'] == d for a in report['assessments'])
                          for d in ['VIOLATED', 'OBSERVED', 'UNKNOWN', 'NOT_APPLICABLE']}
                project_result = {'repository': key, 'scanId': scan_id, 'states': states,
                                  'seconds': round(time.monotonic() - started, 3), 'project': report['project'],
                                  'counts': counts, 'artifacts': formats['json']['artifacts']}
                row['projects'].append(project_result)
                print(json.dumps({'runtime': report['runtime']['javaVersion'], **project_result}, ensure_ascii=False), flush=True)
            cancelling = client.tool('guardrail_scan_start', {'repository': str(cancellation_fixture)})
            assert cancelling['state'] == 'RUNNING', cancelling
            cancelled = client.tool('guardrail_scan_cancel', {'scanId': cancelling['scanId']})
            assert cancelled['state'] == 'CANCELLED', cancelled
            assert client.tool('guardrail_scan_status', {'scanId': cancelling['scanId']}) == cancelled
            client.tool('guardrail_scan_result', {'scanId': cancelling['scanId']}, error=True)
            row['runningCancellationVerified'] = True
        finally:
            (runtime_output / 'mcp-transcript.json').write_text(json.dumps(client.transcript, ensure_ascii=False, indent=2) + '\n')
            row['stderr'] = client.close()
            summary['runtimes'].append(row)
            (args.output / 'runtime-matrix.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
        for malformed in [b'{invalid}\n', b'x' * (1024 * 1024 + 1)]:
            process = subprocess.Popen(client.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(malformed, timeout=10)
            assert process.returncode != 0
            assert not stdout, 'Malformed frame caused non-protocol output'
        row['malformedAndOversizeFramesRejected'] = True
    summary['crossRuntimeEquivalent'] = True
    summary['passed'] = True
    (args.output / 'runtime-matrix.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    print('Native Java 7/8 matrix passed; shipped class major <= 51 and report evidence matches.', flush=True)


if __name__ == '__main__':
    main()
