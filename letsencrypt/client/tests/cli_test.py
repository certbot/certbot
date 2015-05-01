import unittest


class CLITest(unittest.TestCase):

    def test_it(self):
        from letsencrypt.client import cli
        self.assertRaises(SystemExit, cli.main, ['--help'])


if __name__ == '__main__':
    unittest.main()
