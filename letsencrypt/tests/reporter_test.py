"""Tests for letsencrypt.reporter."""
import StringIO
import sys
import unittest


class ReporterTest(unittest.TestCase):
    """Tests for letsencrypt.reporter.Reporter."""

    def setUp(self):
        from letsencrypt import reporter
        self.reporter = reporter.Reporter()

        self.old_stdout = sys.stdout
        sys.stdout = StringIO.StringIO()

    def tearDown(self):
        sys.stdout = self.old_stdout

    def test_tty_print_empty(self):
        sys.stdout.isatty = lambda: True
        self.test_no_tty_print_empty()

    def test_no_tty_print_empty(self):
        self.reporter.print_messages()
        self.assertEqual(sys.stdout.getvalue(), "")
        try:
            raise ValueError
        except ValueError:
            self.reporter.print_messages()
        self.assertEqual(sys.stdout.getvalue(), "")

    def test_tty_successful_exit(self):
        sys.stdout.isatty = lambda: True
        self._successful_exit_common()

    def test_no_tty_successful_exit(self):
        self._successful_exit_common()

    def test_tty_unsuccessful_exit(self):
        sys.stdout.isatty = lambda: True
        self._unsuccessful_exit_common()

    def test_no_tty_unsuccessful_exit(self):
        self._unsuccessful_exit_common()

    def _successful_exit_common(self):
        self._add_messages()
        self.reporter.print_messages()
        output = sys.stdout.getvalue()
        self.assertTrue("IMPORTANT NOTES:" in output)
        self.assertTrue("High" in output)
        self.assertTrue("Med" in output)
        self.assertTrue("Low" in output)

    def _unsuccessful_exit_common(self):
        self._add_messages()
        try:
            raise ValueError
        except ValueError:
            self.reporter.print_messages()
        output = sys.stdout.getvalue()
        self.assertTrue("IMPORTANT NOTES:" in output)
        self.assertTrue("High" in output)
        self.assertTrue("Med" not in output)
        self.assertTrue("Low" not in output)

    def _add_messages(self):
        self.reporter.add_message("High", self.reporter.HIGH_PRIORITY, True)
        self.reporter.add_message("Med", self.reporter.MEDIUM_PRIORITY)
        self.reporter.add_message("Low", self.reporter.LOW_PRIORITY)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
