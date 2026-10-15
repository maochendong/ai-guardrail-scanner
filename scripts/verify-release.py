#!/usr/bin/env python3
"""Build and verify one release JAR on native Java 7 and 8; never execute target code."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('runtime_matrix', ROOT / 'scripts/verify-runtime-matrix.py')
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


def run(command, log, env=None, timeout=900):
    started = time.monotonic()
    with log.open('w') as output:
        subprocess.run([str(part) for part in command], cwd=ROOT, env=env,
                       stdout=output, stderr=subprocess.STDOUT, check=True, timeout=timeout)
    return round(time.monotonic() - started, 3)


def test_inventory(directory, jar):
    classes, count, classpath = [], 0, None
    for report in sorted(directory.glob('TEST-*.xml')):
        suite = ET.parse(report).getroot()
        if any(int(suite.get(key, 0)) for key in ['failures', 'errors', 'skipped']):
            raise ValueError('Release requires all discovered tests to pass without skips: ' + report.name)
        classes.append(suite.attrib['name'])
        count += int(suite.attrib['tests'])
        prop = suite.find("./properties/property[@name='java.class.path']")
        if prop is None:
            raise ValueError('Missing test classpath: ' + report.name)
        current = prop.attrib['value']
        if classpath is not None and classpath != current:
            raise ValueError('Tests used different classpaths')
        classpath = current
    if not classes or count == 0:
        raise ValueError('No tests found in the fresh build')
    # Test the packaged production classes, not loose target/classes output.
    production = str(ROOT / 'compat/target/classes')
    entries = [str(jar) if entry == production else entry
               for entry in classpath.split(os.pathsep) if entry]
    if production in entries or str(jar) not in entries:
        raise ValueError('Cannot bind native tests to the release JAR')
    return classes, count, os.pathsep.join(entries)


def main():
    if not __debug__:
        raise RuntimeError('Verification requires assertions; disable -O and PYTHONOPTIMIZE.')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java7-home', type=Path, required=True)
    parser.add_argument('--java8-home', type=Path, required=True)
    parser.add_argument('--project', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=['generic', 'bank-common', 'bank-customer', 'bank-internal', 'bank-all'], default='generic')
    parser.add_argument('--bank-policy', type=Path)
    flags = ['expect-java-functions', 'expect-python-rag', 'require-python-parse-success',
             'require-resolved-python-clients', 'expect-python-guard-results']
    for flag in flags:
        parser.add_argument('--' + flag, action='store_true')
    args = parser.parse_args()
    try:
        runtimes = matrix.validate_runtimes([
            args.java7_home / 'bin/java', args.java8_home / 'bin/java'])
        if [r['major'] for r in runtimes] != ['1.7', '1.8']:
            raise ValueError('--java7-home and --java8-home must match their named versions')
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error('--output must be new or empty so stale evidence cannot be reused')
    output.mkdir(parents=True, exist_ok=True)
    summary = {'passed': False, 'runtimes': [], 'requiredRuntimeMajors': ['1.7', '1.8']}
    try:
        print('Verifying release-script regressions', flush=True)
        run([sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/tests', '-v'],
            output / 'script-tests.log', timeout=120)
        print('Compiling with native javac 7 and running clean verify', flush=True)
        env = dict(os.environ, JAVA7_HOME=str(args.java7_home.resolve()))
        summary['buildSeconds'] = run([ROOT / 'scripts/build-compatible.sh', 'clean', 'verify'],
                                      output / 'build.log', env=env)
        jar = ROOT / 'compat/target/ai-guardrail-scanner-java7.jar'
        digest = hashlib.sha256(jar.read_bytes()).hexdigest()
        summary.update(jar=str(jar), sha256=digest)
        classes, expected, classpath = test_inventory(ROOT / 'compat/target/surefire-reports', jar)
        summary.update(testClassCount=len(classes), testCountPerRuntime=expected)
        for runtime in runtimes:
            print('Running all packaged-JAR tests on Java ' + runtime['version'], flush=True)
            log = output / ('jdk' + runtime['major'][-1] + '-tests.log')
            elapsed = run([runtime['java'], '-Xmx768m', '-cp', classpath,
                           'org.junit.runner.JUnitCore'] + classes, log)
            matched = re.search(r'^OK \((\d+) tests?\)$', log.read_text(), re.MULTILINE)
            if matched is None or int(matched.group(1)) != expected:
                raise ValueError('Native test count differs from clean build: ' + str(log))
            summary['runtimes'].append(dict(runtime, testCount=expected, seconds=elapsed, passed=True))
        print('Verifying projects through both native MCP processes', flush=True)
        command = [sys.executable, ROOT / 'scripts/verify-runtime-matrix.py', '--jar', jar,
                   '--output', output / 'matrix', '--profile', args.profile]
        for runtime in runtimes:
            command.extend(['--java', runtime['java']])
        for project in args.project:
            command.extend(['--project', project.resolve()])
        if args.bank_policy is not None:
            command.extend(['--bank-policy', args.bank_policy.resolve()])
        for flag in flags:
            if getattr(args, flag.replace('-', '_')):
                command.append('--' + flag)
        summary['matrixSeconds'] = run(command, output / 'matrix.log', timeout=1800)
        evidence = json.loads((output / 'matrix/runtime-matrix.json').read_text())
        if (not evidence.get('passed') or evidence.get('verifiedRuntimeMajors') != ['1.7', '1.8']
                or evidence.get('sha256') != digest
                or hashlib.sha256(jar.read_bytes()).hexdigest() != digest):
            raise ValueError('Matrix evidence or release JAR changed during verification')
        summary.update(passed=True, matrix=str(output / 'matrix/runtime-matrix.json'))
        print('Release verification passed on native Java 7/8: ' + digest, flush=True)
    finally:
        (output / 'release-verification.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    main()
