"""Test :mod:`certbot._internal.display.util`."""
import io
import socket
import sys
import tempfile
import unittest
from unittest import mock

import pytest

from acme import messages as acme_messages
from certbot import errors


class WrapLinesTest(unittest.TestCase):
    def test_wrap_lines(self):
        from certbot._internal.display.util import wrap_lines
        msg = ("This is just a weak test{0}"
               "This function is only meant to be for easy viewing{0}"
               "Test a really really really really really really really really "
               "really really really really long line...".format('\n'))
        text = wrap_lines(msg)

        self.assertEqual(text.count('\n'), 3)


class PlaceParensTest(unittest.TestCase):
    @classmethod
    def _call(cls, label):
        from certbot._internal.display.util import parens_around_char
        return parens_around_char(label)

    def test_single_letter(self):
        self.assertEqual("(a)", self._call("a"))

    def test_multiple(self):
        self.assertEqual("(L)abel", self._call("Label"))
        self.assertEqual("(y)es please", self._call("yes please"))


class InputWithTimeoutTest(unittest.TestCase):
    """Tests for certbot._internal.display.util.input_with_timeout."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot._internal.display.util import input_with_timeout
        return input_with_timeout(*args, **kwargs)

    def test_eof(self):
        with tempfile.TemporaryFile("r+") as f:
            with mock.patch("certbot._internal.display.util.sys.stdin", new=f):
                self.assertRaises(EOFError, self._call)

    def test_input(self, prompt=None):
        expected = "foo bar"
        stdin = io.StringIO(expected + "\n")
        with mock.patch("certbot.compat.misc.select.select") as mock_select:
            mock_select.return_value = ([stdin], [], [],)
            self.assertEqual(self._call(prompt), expected)

    @mock.patch("certbot._internal.display.util.sys.stdout")
    def test_input_with_prompt(self, mock_stdout):
        prompt = "test prompt: "
        self.test_input(prompt)
        mock_stdout.write.assert_called_once_with(prompt)
        mock_stdout.flush.assert_called_once_with()

    def test_timeout(self):
        stdin = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stdin.bind(('', 0))
        stdin.listen(1)
        with mock.patch("certbot._internal.display.util.sys.stdin", stdin):
            self.assertRaises(errors.Error, self._call, timeout=0.001)
        stdin.close()


class SeparateListInputTest(unittest.TestCase):
    """Test Module functions."""
    def setUp(self):
        self.exp = ["a", "b", "c", "test"]

    @classmethod
    def _call(cls, input_):
        from certbot._internal.display.util import separate_list_input
        return separate_list_input(input_)

    def test_commas(self):
        self.assertEqual(self._call("a,b,c,test"), self.exp)

    def test_spaces(self):
        self.assertEqual(self._call("a b c test"), self.exp)

    def test_both(self):
        self.assertEqual(self._call("a, b, c, test"), self.exp)

    def test_mess(self):
        actual = [
            self._call("  a , b    c \t test"),
            self._call(",a, ,, , b c  test  "),
            self._call(",,,,, , a b,,, , c,test"),
        ]

        for act in actual:
            self.assertEqual(act, self.exp)


class SummarizeDomainListTest(unittest.TestCase):
    @classmethod
    def _call(cls, domains):
        from certbot._internal.display.util import summarize_domain_list
        return summarize_domain_list(domains)

    def test_single_domain(self):
        self.assertEqual("example.com", self._call(["example.com"]))

    def test_two_domains(self):
        self.assertEqual("example.com and example.org",
                         self._call(["example.com", "example.org"]))

    def test_many_domains(self):
        self.assertEqual("example.com and 2 more domains",
                         self._call(["example.com", "example.org", "a.example.com"]))

    def test_empty_domains(self):
        self.assertEqual("", self._call([]))


class DescribeACMEErrorTest(unittest.TestCase):
    @classmethod
    def _call(cls, typ: str = "urn:ietf:params:acme:error:badCSR",
              title: str = "Unacceptable CSR",
              detail: str = "CSR contained unknown extensions"):
        from certbot._internal.display.util import describe_acme_error
        return describe_acme_error(
            acme_messages.Error(typ=typ, title=title, detail=detail))

    def test_title_and_detail(self):
        self.assertEqual("Unacceptable CSR :: CSR contained unknown extensions", self._call())

    def test_detail(self):
        self.assertEqual("CSR contained unknown extensions", self._call(title=None))

    def test_description(self):
        self.assertEqual(acme_messages.ERROR_CODES["badCSR"], self._call(title=None, detail=None))

    def test_unknown_type(self):
        self.assertEqual(
            "urn:ietf:params:acme:error:unknownErrorType",
            self._call(typ="urn:ietf:params:acme:error:unknownErrorType", title=None, detail=None))


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))  # pragma: no cover
