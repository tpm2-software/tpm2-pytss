import os
import ast
import sys
import pathlib
import unittest
import subprocess


# Top of the git repo
ROOT = pathlib.Path(__file__).parent.parent

ENV = os.environ.copy()
ENV["PYTHONPATH"] = str(ROOT)


def filepath(filename):
    return ROOT / "examples" / filename


class TestExamples(unittest.TestCase):
    def test_fapi_get_random(self):
        # Length of random bytes to get
        length = 32
        # Capture output
        stdout = subprocess.check_output(
            [sys.executable, str(filepath("fapi_get_random.py")), str(length)], env=ENV,
        )
        # Ensure the output is of the correct length
        self.assertEqual(length, len(stdout))
