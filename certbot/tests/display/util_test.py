"""Test :mod:`certbot.display.util`."""
import inspect
import os
import socket
import tempfile
import unittest

import six
import mock

from certbot import errors
from certbot import interfaces

from certbot.display import util as display_util


CHOICES = [("First", "Description1"), ("Second", "Description2")]
TAGS = ["tag1", "tag2", "tag3"]
TAGS_CHOICES = [("1", "tag1"), ("2", "tag2"), ("3", "tag3")]


class InputWithTimeoutTest(unittest.TestCase):
    """Tests for certbot.display.util.input_with_timeout."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.display.util import input_with_timeout
        return input_with_timeout(*args, **kwargs)

    def test_eof(self):
        with tempfile.TemporaryFile("r+") as f:
            with mock.patch("certbot.display.util.sys.stdin", new=f):
                self.assertRaises(EOFError, self._call)

    def test_input(self, prompt=None):
        expected = "foo bar"
        stdin = six.StringIO(expected + "\n")
        with mock.patch("certbot.display.util.select.select") as mock_select:
            mock_select.return_value = ([stdin], [], [],)
            self.assertEqual(self._call(prompt), expected)

    @mock.patch("certbot.display.util.sys.stdout")
    def test_input_with_prompt(self, mock_stdout):
        prompt = "test prompt: "
        self.test_input(prompt)
        mock_stdout.write.assert_called_once_with(prompt)
        mock_stdout.flush.assert_called_once_with()

    def test_timeout(self):
        stdin = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stdin.bind(('', 0))
        stdin.listen(1)
        with mock.patch("certbot.display.util.sys.stdin", stdin):
            self.assertRaises(errors.Error, self._call, timeout=0.001)


class FileOutputDisplayTest(unittest.TestCase):
    """Test stdout display.

    Most of this class has to deal with visual output.  In order to test how the
    functions look to a user, uncomment the test_visual function.

    """
    # pylint:disable=too-many-public-methods
    def setUp(self):
        super(FileOutputDisplayTest, self).setUp()
        self.mock_stdout = mock.MagicMock()
        self.displayer = display_util.FileDisplay(self.mock_stdout, False)

    def test_notification_no_pause(self):
        self.displayer.notification("message", False)
        string = self.mock_stdout.write.call_args[0][0]

        self.assertTrue("message" in string)

    def test_notification_pause(self):
        input_with_timeout = "certbot.display.util.input_with_timeout"
        with mock.patch(input_with_timeout, return_value="enter"):
            self.displayer.notification("message", force_interactive=True)

        self.assertTrue("message" in self.mock_stdout.write.call_args[0][0])

    def test_notification_noninteractive(self):
        self._force_noninteractive(self.displayer.notification, "message")
        string = self.mock_stdout.write.call_args[0][0]
        self.assertTrue("message" in string)

    def test_notification_noninteractive2(self):
        # The main purpose of this test is to make sure we only call
        # logger.warning once which _force_noninteractive checks internally
        self._force_noninteractive(self.displayer.notification, "message")
        string = self.mock_stdout.write.call_args[0][0]
        self.assertTrue("message" in string)

        self.assertTrue(self.displayer.skipped_interaction)

        self._force_noninteractive(self.displayer.notification, "message2")
        string = self.mock_stdout.write.call_args[0][0]
        self.assertTrue("message2" in string)

    @mock.patch("certbot.display.util."
                "FileDisplay._get_valid_int_ans")
    def test_menu(self, mock_ans):
        mock_ans.return_value = (display_util.OK, 1)
        ret = self.displayer.menu("message", CHOICES, force_interactive=True)
        self.assertEqual(ret, (display_util.OK, 0))

    def test_menu_noninteractive(self):
        default = 0
        result = self._force_noninteractive(
            self.displayer.menu, "msg", CHOICES, default=default)
        self.assertEqual(result, (display_util.OK, default))

    def test_input_cancel(self):
        input_with_timeout = "certbot.display.util.input_with_timeout"
        with mock.patch(input_with_timeout, return_value="c"):
            code, _ = self.displayer.input("message", force_interactive=True)

        self.assertTrue(code, display_util.CANCEL)

    def test_input_normal(self):
        input_with_timeout = "certbot.display.util.input_with_timeout"
        with mock.patch(input_with_timeout, return_value="domain.com"):
            code, input_ = self.displayer.input("message", force_interactive=True)

        self.assertEqual(code, display_util.OK)
        self.assertEqual(input_, "domain.com")

    def test_input_noninteractive(self):
        default = "foo"
        code, input_ = self._force_noninteractive(
            self.displayer.input, "message", default=default)

        self.assertEqual(code, display_util.OK)
        self.assertEqual(input_, default)

    def test_input_assertion_fail(self):
        # If the call to util.assert_valid_call is commented out, an
        # error.Error is raised, otherwise, an AssertionError is raised.
        self.assertRaises(Exception, self._force_noninteractive,
                          self.displayer.input, "message", cli_flag="--flag")

    def test_input_assertion_fail2(self):
        with mock.patch("certbot.display.util.assert_valid_call"):
            self.assertRaises(errors.Error, self._force_noninteractive,
                              self.displayer.input, "msg", cli_flag="--flag")

    def test_yesno(self):
        input_with_timeout = "certbot.display.util.input_with_timeout"
        with mock.patch(input_with_timeout, return_value="Yes"):
            self.assertTrue(self.displayer.yesno(
                "message", force_interactive=True))
        with mock.patch(input_with_timeout, return_value="y"):
            self.assertTrue(self.displayer.yesno(
                "message", force_interactive=True))
        with mock.patch(input_with_timeout, side_effect=["maybe", "y"]):
            self.assertTrue(self.displayer.yesno(
                "message", force_interactive=True))
        with mock.patch(input_with_timeout, return_value="No"):
            self.assertFalse(self.displayer.yesno(
                "message", force_interactive=True))
        with mock.patch(input_with_timeout, side_effect=["cancel", "n"]):
            self.assertFalse(self.displayer.yesno(
                "message", force_interactive=True))

        with mock.patch(input_with_timeout, return_value="a"):
            self.assertTrue(self.displayer.yesno(
                "msg", yes_label="Agree", force_interactive=True))

    def test_yesno_noninteractive(self):
        self.assertTrue(self._force_noninteractive(
            self.displayer.yesno, "message", default=True))

    @mock.patch("certbot.display.util.input_with_timeout")
    def test_checklist_valid(self, mock_input):
        mock_input.return_value = "2 1"
        code, tag_list = self.displayer.checklist(
            "msg", TAGS, force_interactive=True)
        self.assertEqual(
            (code, set(tag_list)), (display_util.OK, set(["tag1", "tag2"])))

    @mock.patch("certbot.display.util.input_with_timeout")
    def test_checklist_empty(self, mock_input):
        mock_input.return_value = ""
        code, tag_list = self.displayer.checklist("msg", TAGS, force_interactive=True)
        self.assertEqual(
            (code, set(tag_list)), (display_util.OK, set(["tag1", "tag2", "tag3"])))

    @mock.patch("certbot.display.util.input_with_timeout")
    def test_checklist_miss_valid(self, mock_input):
        mock_input.side_effect = ["10", "tag1 please", "1"]

        ret = self.displayer.checklist("msg", TAGS, force_interactive=True)
        self.assertEqual(ret, (display_util.OK, ["tag1"]))

    @mock.patch("certbot.display.util.input_with_timeout")
    def test_checklist_miss_quit(self, mock_input):
        mock_input.side_effect = ["10", "c"]

        ret = self.displayer.checklist("msg", TAGS, force_interactive=True)
        self.assertEqual(ret, (display_util.CANCEL, []))

    def test_checklist_noninteractive(self):
        default = TAGS
        code, input_ = self._force_noninteractive(
            self.displayer.checklist, "msg", TAGS, default=default)

        self.assertEqual(code, display_util.OK)
        self.assertEqual(input_, default)

    def test_scrub_checklist_input_valid(self):
        # pylint: disable=protected-access
        indices = [
            ["1"],
            ["1", "2", "1"],
            ["2", "3"],
        ]
        exp = [
            set(["tag1"]),
            set(["tag1", "tag2"]),
            set(["tag2", "tag3"]),
        ]
        for i, list_ in enumerate(indices):
            set_tags = set(
                self.displayer._scrub_checklist_input(list_, TAGS))
            self.assertEqual(set_tags, exp[i])

    @mock.patch("certbot.display.util.input_with_timeout")
    def test_directory_select(self, mock_input):
        # pylint: disable=star-args
        args = ["msg", "/var/www/html", "--flag", True]
        user_input = "/var/www/html"
        mock_input.return_value = user_input

        returned = self.displayer.directory_select(*args)
        self.assertEqual(returned, (display_util.OK, user_input))

    def test_directory_select_noninteractive(self):
        default = "/var/www/html"
        code, input_ = self._force_noninteractive(
            self.displayer.directory_select, "msg", default=default)

        self.assertEqual(code, display_util.OK)
        self.assertEqual(input_, default)

    def _force_noninteractive(self, func, *args, **kwargs):
        skipped_interaction = self.displayer.skipped_interaction

        with mock.patch("certbot.display.util.sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with mock.patch("certbot.display.util.logger") as mock_logger:
                result = func(*args, **kwargs)

        if skipped_interaction:
            self.assertFalse(mock_logger.warning.called)
        else:
            self.assertEqual(mock_logger.warning.call_count, 1)

        return result

    def test_scrub_checklist_input_invalid(self):
        # pylint: disable=protected-access
        indices = [
            ["0"],
            ["4"],
            ["tag1"],
            ["1", "tag1"],
            ["2", "o"]
        ]
        for list_ in indices:
            self.assertEqual(
                self.displayer._scrub_checklist_input(list_, TAGS), [])

    def test_print_menu(self):
        # pylint: disable=protected-access
        # This is purely cosmetic... just make sure there aren't any exceptions
        self.displayer._print_menu("msg", CHOICES)
        self.displayer._print_menu("msg", TAGS)

    def test_wrap_lines(self):
        # pylint: disable=protected-access
        msg = ("This is just a weak test{0}"
               "This function is only meant to be for easy viewing{0}"
               "Test a really really really really really really really really "
               "really really really really long line...".format(os.linesep))
        text = display_util._wrap_lines(msg)

        self.assertEqual(text.count(os.linesep), 3)

    def test_get_valid_int_ans_valid(self):
        # pylint: disable=protected-access
        input_with_timeout = "certbot.display.util.input_with_timeout"
        with mock.patch(input_with_timeout, return_value="1"):
            self.assertEqual(
                self.displayer._get_valid_int_ans(1), (display_util.OK, 1))
        ans = "2"
        with mock.patch(input_with_timeout, return_value=ans):
            self.assertEqual(
                self.displayer._get_valid_int_ans(3),
                (display_util.OK, int(ans)))

    def test_get_valid_int_ans_invalid(self):
        # pylint: disable=protected-access
        answers = [
            ["0", "c"],
            ["4", "one", "C"],
            ["c"],
        ]
        input_with_timeout = "certbot.display.util.input_with_timeout"
        for ans in answers:
            with mock.patch(input_with_timeout, side_effect=ans):
                self.assertEqual(
                    self.displayer._get_valid_int_ans(3),
                    (display_util.CANCEL, -1))

    def test_methods_take_force_interactive(self):
        # Every IDisplay method implemented by FileDisplay must take
        # force_interactive to prevent workflow regressions.
        for name in interfaces.IDisplay.names():  # pylint: disable=no-member
            arg_spec = inspect.getargspec(getattr(self.displayer, name))
            self.assertTrue("force_interactive" in arg_spec.args)


class NoninteractiveDisplayTest(unittest.TestCase):
    """Test non-interactive display.

    These tests are pretty easy!

    """
    def setUp(self):
        super(NoninteractiveDisplayTest, self).setUp()
        self.mock_stdout = mock.MagicMock()
        self.displayer = display_util.NoninteractiveDisplay(self.mock_stdout)

    def test_notification_no_pause(self):
        self.displayer.notification("message", 10)
        string = self.mock_stdout.write.call_args[0][0]

        self.assertTrue("message" in string)

    def test_input(self):
        d = "an incomputable value"
        ret = self.displayer.input("message", default=d)
        self.assertEqual(ret, (display_util.OK, d))
        self.assertRaises(errors.MissingCommandlineFlag, self.displayer.input, "message")

    def test_menu(self):
        ret = self.displayer.menu("message", CHOICES, default=1)
        self.assertEqual(ret, (display_util.OK, 1))
        self.assertRaises(errors.MissingCommandlineFlag, self.displayer.menu, "message", CHOICES)

    def test_yesno(self):
        d = False
        ret = self.displayer.yesno("message", default=d)
        self.assertEqual(ret, d)
        self.assertRaises(errors.MissingCommandlineFlag, self.displayer.yesno, "message")

    def test_checklist(self):
        d = [1, 3]
        ret = self.displayer.checklist("message", TAGS, default=d)
        self.assertEqual(ret, (display_util.OK, d))
        self.assertRaises(errors.MissingCommandlineFlag, self.displayer.checklist, "message", TAGS)

    def test_directory_select(self):
        default = "/var/www/html"
        expected = (display_util.OK, default)
        actual = self.displayer.directory_select("msg", default)
        self.assertEqual(expected, actual)

        self.assertRaises(
            errors.MissingCommandlineFlag, self.displayer.directory_select, "msg")

    def test_methods_take_kwargs(self):
        # Every IDisplay method implemented by NoninteractiveDisplay
        # should take **kwargs because every method of FileDisplay must
        # take force_interactive which doesn't apply to
        # NoninteractiveDisplay.
        for name in interfaces.IDisplay.names():  # pylint: disable=no-member
            method = getattr(self.displayer, name)
            # asserts method accepts arbitrary keyword arguments
            self.assertFalse(inspect.getargspec(method).keywords is None)


class SeparateListInputTest(unittest.TestCase):
    """Test Module functions."""
    def setUp(self):
        self.exp = ["a", "b", "c", "test"]

    @classmethod
    def _call(cls, input_):
        from certbot.display.util import separate_list_input
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


class PlaceParensTest(unittest.TestCase):
    @classmethod
    def _call(cls, label):  # pylint: disable=protected-access
        from certbot.display.util import _parens_around_char
        return _parens_around_char(label)

    def test_single_letter(self):
        self.assertEqual("(a)", self._call("a"))

    def test_multiple(self):
        self.assertEqual("(L)abel", self._call("Label"))
        self.assertEqual("(y)es please", self._call("yes please"))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
