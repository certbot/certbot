"""
This test module is here to provide at least on test on Windows, and thus avoid
pytest to fail because no tests could be found.
"""
import unittest


class DummyTest(unittest.TestCase):
    """Dummy test"""
    def test_dummy(self):
        self.assertTrue(True)
