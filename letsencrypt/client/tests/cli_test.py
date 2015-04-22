import unittest


class CLITest(unittest.TestCase):

    def test_it(self):
        from letsencrypt.client import cli


if __name__ == '__main__':
    unittest.main()
