import ast
import sys
import pathlib
import unittest
import subprocess


def filepath(filename):
    return pathlib.Path(__file__).parent.parent / "examples" / filename


class TestExamples(unittest.TestCase):
    def test_fapi_get_random(self):
        # Capture output
        stdout = (
            subprocess.check_output(
                [sys.executable, str(filepath("fapi_get_random.py"))]
            )
            .decode()
            .strip()
        )
        # Parse the length
        length = int(ast.literal_eval(stdout.split(")")[0].split("(")[-1]))
        # Parse the value of the bytearray
        array = bytearray(ast.literal_eval(stdout.split("(")[-1].replace(")", "")))
        # Ensure the bytearray makes sense
        self.assertEqual(length, len(array))
