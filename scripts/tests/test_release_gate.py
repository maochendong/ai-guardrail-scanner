import importlib.util
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

SPEC = importlib.util.spec_from_file_location(
    'release_gate', Path(__file__).resolve().parents[1] / 'verify-release.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseGateTest(unittest.TestCase):
    def test_optimized_release_cannot_launch_an_unchecked_matrix(self):
        result = subprocess.run([sys.executable, '-O', str(SPEC.origin), '--help'],
                                capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Verification requires assertions', result.stderr)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.jar = self.root / 'release.jar'

    def report(self, name='ExampleTest', tests=2, skipped=0, classpath=True):
        suite = ET.Element('testsuite', name=name, tests=str(tests), skipped=str(skipped))
        props = ET.SubElement(suite, 'properties')
        if classpath:
            value = os.pathsep.join([str(release.ROOT / 'compat/target/test-classes'),
                                     str(release.ROOT / 'compat/target/classes'), '/lib/junit.jar'])
            ET.SubElement(props, 'property', name='java.class.path', value=value)
        ET.ElementTree(suite).write(self.root / ('TEST-' + name + '.xml'))

    def test_no_discovered_tests_cannot_pass_release(self):
        with self.assertRaises(ValueError):
            release.test_inventory(self.root, self.jar)

    def test_native_tests_use_final_jar_instead_of_loose_production_classes(self):
        self.report()
        classes, count, classpath = release.test_inventory(self.root, self.jar)
        self.assertEqual(['ExampleTest'], classes)
        self.assertEqual(2, count)
        self.assertIn(str(self.jar), classpath.split(os.pathsep))
        self.assertNotIn(str(release.ROOT / 'compat/target/classes'), classpath.split(os.pathsep))

    def test_skipped_tests_require_attention(self):
        self.report(skipped=1)
        with self.assertRaises(ValueError):
            release.test_inventory(self.root, self.jar)

    def test_missing_classpath_cannot_produce_native_test_claim(self):
        self.report(classpath=False)
        with self.assertRaises(ValueError):
            release.test_inventory(self.root, self.jar)

    def test_all_fresh_suites_contribute_to_native_count(self):
        self.report('FirstTest', tests=2)
        self.report('SecondTest', tests=3)
        classes, count, _ = release.test_inventory(self.root, self.jar)
        self.assertEqual(['FirstTest', 'SecondTest'], classes)
        self.assertEqual(5, count)


if __name__ == '__main__':
    unittest.main()
