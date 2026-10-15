import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'runtime_matrix', Path(__file__).resolve().parents[1] / 'verify-runtime-matrix.py')
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


class RuntimeMatrixTest(unittest.TestCase):
    def test_existing_evidence_directory_is_rejected_before_scanning(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / 'runtime-matrix.json'
            evidence.write_text('{"passed":true}')
            argv = ['matrix', '--java', '/java7', '--java', '/java8', '--jar', '/missing.jar',
                    '--project', '/project', '--output', directory]
            with patch.object(sys, 'argv', argv), patch.object(matrix, 'validate_runtimes', return_value=[]):
                with self.assertRaises(SystemExit) as error:
                    matrix.main()
            self.assertEqual(2, error.exception.code)

    def test_optimized_python_cannot_skip_verification_checks(self):
        result = subprocess.run([sys.executable, '-O', str(SPEC.origin), '--help'],
                                capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Verification requires assertions', result.stderr)

    def runtime(self, version):
        return subprocess.CompletedProcess([], 0, '', 'java version "' + version + '"\n')

    def test_single_runtime_cannot_claim_cross_runtime_equivalence(self):
        with self.assertRaises(ValueError), patch.object(matrix.subprocess, 'run') as run:
            matrix.validate_runtimes(['/jdk7/bin/java'])
        run.assert_not_called()

    def test_duplicate_runtime_is_rejected(self):
        with self.assertRaises(ValueError), patch.object(matrix.subprocess, 'run'):
            matrix.validate_runtimes(['/jdk7/bin/java', '/jdk7/bin/java'])

    def test_two_executables_from_same_major_do_not_form_a_matrix(self):
        with patch.object(matrix.subprocess, 'run', side_effect=[
                self.runtime('1.7.0_79'), self.runtime('1.7.0_80')]):
            with self.assertRaises(ValueError):
                matrix.validate_runtimes(['/jdk7a/bin/java', '/jdk7b/bin/java'])

    def test_new_jvm_is_not_native_java_seven_or_eight(self):
        with patch.object(matrix.subprocess, 'run', side_effect=[
                self.runtime('1.7.0_79'), self.runtime('21.0.4')]):
            with self.assertRaises(ValueError):
                matrix.validate_runtimes(['/jdk7/bin/java', '/jdk21/bin/java'])

    def test_unreadable_version_is_rejected(self):
        with patch.object(matrix.subprocess, 'run', return_value=self.runtime('unknown')):
            with self.assertRaises(ValueError):
                matrix.validate_runtimes(['/jdk7/bin/java', '/jdk8/bin/java'])

    def test_both_native_versions_are_recorded_in_requested_order(self):
        with patch.object(matrix.subprocess, 'run', side_effect=[
                self.runtime('1.8.0_40'), self.runtime('1.7.0_79')]):
            result = matrix.validate_runtimes(['/jdk8/bin/java', '/jdk7/bin/java'])
        self.assertEqual(['1.8', '1.7'], [row['major'] for row in result])
        self.assertEqual(['1.8.0_40', '1.7.0_79'], [row['version'] for row in result])


if __name__ == '__main__':
    unittest.main()
