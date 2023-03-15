"""Test :mod:`certbot._internal.display.obj`."""
import sys
import unittest
from unittest import mock

import pytest

from certbot import errors
from certbot._internal.display import obj as display_obj
from certbot.display import util as display_util
from typing import Callable, List, Optional, Tuple, Union
from unittest.mock import MagicMock

CHOICES = [("First", "Description1"), ("Second", "Description2")]
TAGS = ["tag1", "tag2", "tag3"]


class FileOutputDisplayTest(unittest.TestCase):
    """Test stdout display.

    Most of this class has to deal with visual output.  In order to test how the
    functions look to a user, uncomment the test_visual function.

    """
    def setUp(self) -> None:
        super().setUp()
        self.mock_stdout = mock.MagicMock()
        self.displayer = display_obj.FileDisplay(self.mock_stdout, False)

    @mock.patch("certbot._internal.display.obj.logger")
    def test_notification_no_pause(self, mock_logger: MagicMock) -> None:
        self.displayer.notification("message", False)
        string = self.mock_stdout.write.call_args[0][0]

        assert "message" in string
        mock_logger.debug.assert_called_with("Notifying user: %s", "message")

    def test_notification_pause(self) -> None:
        input_with_timeout = "certbot._internal.display.util.input_with_timeout"
        with mock.patch(input_with_timeout, return_value="enter"):
            self.displayer.notification("message", force_interactive=True)

        assert "message" in self.mock_stdout.write.call_args[0][0]

    def test_notification_noninteractive(self) -> None:
        self._force_noninteractive(self.displayer.notification, "message")
        string = self.mock_stdout.write.call_args[0][0]
        assert "message" in string

    def test_notification_noninteractive2(self) -> None:
        # The main purpose of this test is to make sure we only call
        # logger.warning once which _force_noninteractive checks internally
        self._force_noninteractive(self.displayer.notification, "message")
        string = self.mock_stdout.write.call_args[0][0]
        assert "message" in string

        assert self.displayer.skipped_interaction

        self._force_noninteractive(self.displayer.notification, "message2")
        string = self.mock_stdout.write.call_args[0][0]
        assert "message2" in string

    def test_notification_decoration(self) -> None:
        from certbot.compat import os
        self.displayer.notification("message", pause=False, decorate=False)
        string = self.mock_stdout.write.call_args[0][0]
        assert string == "message" + os.linesep

        self.displayer.notification("message2", pause=False)
        string = self.mock_stdout.write.call_args[0][0]
        assert "- - - " in string
        assert "message2" + os.linesep in string

    @mock.patch("certbot._internal.display.obj."
                "FileDisplay._get_valid_int_ans")
    def test_menu(self, mock_ans: MagicMock) -> None:
        mock_ans.return_value = (display_util.OK, 1)
        ret = self.displayer.menu("message", CHOICES, force_interactive=True)
        assert ret == (display_util.OK, 0)

    def test_menu_noninteractive(self) -> None:
        default = 0
        result = self._force_noninteractive(
            self.displayer.menu, "msg", CHOICES, default=default)
        assert result == (display_util.OK, default)

    def test_input_cancel(self) -> None:
        input_with_timeout = "certbot._internal.display.util.input_with_timeout"
        with mock.patch(input_with_timeout, return_value="c"):
            code, _ = self.displayer.input("message", force_interactive=True)

        assert code, display_util.CANCEL

    def test_input_normal(self) -> None:
        input_with_timeout = "certbot._internal.display.util.input_with_timeout"
        with mock.patch(input_with_timeout, return_value="domain.com"):
            code, input_ = self.displayer.input("message", force_interactive=True)

        assert code == display_util.OK
        assert input_ == "domain.com"

    def test_input_noninteractive(self) -> None:
        default = "foo"
        code, input_ = self._force_noninteractive(
            self.displayer.input, "message", default=default)

        assert code == display_util.OK
        assert input_ == default

    def test_input_assertion_fail(self) -> None:
        # If the call to util.assert_valid_call is commented out, an
        # error.Error is raised, otherwise, an AssertionError is raised.
        with pytest.raises(Exception):
            self._force_noninteractive(self.displayer.input, "message", cli_flag="--flag")

    def test_input_assertion_fail2(self) -> None:
        with mock.patch("certbot.display.util.assert_valid_call"):
            with pytest.raises(errors.Error):
                self._force_noninteractive(self.displayer.input, "msg", cli_flag="--flag")

    def test_yesno(self) -> None:
        input_with_timeout = "certbot._internal.display.util.input_with_timeout"
        with mock.patch(input_with_timeout, return_value="Yes"):
            assert self.displayer.yesno(
                "message", force_interactive=True)
        with mock.patch(input_with_timeout, return_value="y"):
            assert self.displayer.yesno(
                "message", force_interactive=True)
        with mock.patch(input_with_timeout, side_effect=["maybe", "y"]):
            assert self.displayer.yesno(
                "message", force_interactive=True)
        with mock.patch(input_with_timeout, return_value="No"):
            assert not self.displayer.yesno(
                "message", force_interactive=True)
        with mock.patch(input_with_timeout, side_effect=["cancel", "n"]):
            assert not self.displayer.yesno(
                "message", force_interactive=True)

        with mock.patch(input_with_timeout, return_value="a"):
            assert self.displayer.yesno(
                "msg", yes_label="Agree", force_interactive=True)

    def test_yesno_noninteractive(self) -> None:
        assert self._force_noninteractive(
            self.displayer.yesno, "message", default=True)

    @mock.patch("certbot._internal.display.util.input_with_timeout")
    def test_checklist_valid(self, mock_input: MagicMock) -> None:
        mock_input.return_value = "2 1"
        code, tag_list = self.displayer.checklist(
            "msg", TAGS, force_interactive=True)
        assert (code, set(tag_list)) == (display_util.OK, {"tag1", "tag2"})

    @mock.patch("certbot._internal.display.util.input_with_timeout")
    def test_checklist_empty(self, mock_input: MagicMock) -> None:
        mock_input.return_value = ""
        code, tag_list = self.displayer.checklist("msg", TAGS, force_interactive=True)
        assert (code, set(tag_list)) == (display_util.OK, {"tag1", "tag2", "tag3"})

    @mock.patch("certbot._internal.display.util.input_with_timeout")
    def test_checklist_miss_valid(self, mock_input: MagicMock) -> None:
        mock_input.side_effect = ["10", "tag1 please", "1"]

        ret = self.displayer.checklist("msg", TAGS, force_interactive=True)
        assert ret == (display_util.OK, ["tag1"])

    @mock.patch("certbot._internal.display.util.input_with_timeout")
    def test_checklist_miss_quit(self, mock_input: MagicMock) -> None:
        mock_input.side_effect = ["10", "c"]

        ret = self.displayer.checklist("msg", TAGS, force_interactive=True)
        assert ret == (display_util.CANCEL, [])

    def test_checklist_noninteractive(self) -> None:
        default = TAGS
        code, input_ = self._force_noninteractive(
            self.displayer.checklist, "msg", TAGS, default=default)

        assert code == display_util.OK
        assert input_ == default

    def test_scrub_checklist_input_valid(self) -> None:
        # pylint: disable=protected-access
        indices = [
            ["1"],
            ["1", "2", "1"],
            ["2", "3"],
        ]
        exp = [
            {"tag1"},
            {"tag1", "tag2"},
            {"tag2", "tag3"},
        ]
        for i, list_ in enumerate(indices):
            set_tags = set(
                self.displayer._scrub_checklist_input(list_, TAGS))
            assert set_tags == exp[i]

    @mock.patch("certbot._internal.display.util.input_with_timeout")
    def test_directory_select(self, mock_input: MagicMock) -> None:
        args = ["msg", "/var/www/html", "--flag", True]
        user_input = "/var/www/html"
        mock_input.return_value = user_input

        returned = self.displayer.directory_select(*args)
        assert returned == (display_util.OK, user_input)

    def test_directory_select_noninteractive(self) -> None:
        default = "/var/www/html"
        code, input_ = self._force_noninteractive(
            self.displayer.directory_select, "msg", default=default)

        assert code == display_util.OK
        assert input_ == default

    def _force_noninteractive(self, func: Callable, *args, **kwargs) -> Optional[Union[Tuple[str, str], Tuple[str, List[str]], Tuple[str, int], bool]]:
        skipped_interaction = self.displayer.skipped_interaction

        with mock.patch("certbot._internal.display.obj.sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            with mock.patch("certbot._internal.display.obj.logger") as mock_logger:
                result = func(*args, **kwargs)

        if skipped_interaction:
            assert mock_logger.warning.called is False
        else:
            assert mock_logger.warning.call_count == 1

        return result

    def test_scrub_checklist_input_invalid(self) -> None:
        # pylint: disable=protected-access
        indices = [
            ["0"],
            ["4"],
            ["tag1"],
            ["1", "tag1"],
            ["2", "o"]
        ]
        for list_ in indices:
            assert self.displayer._scrub_checklist_input(list_, TAGS) == []

    def test_print_menu(self) -> None:
        # pylint: disable=protected-access
        # This is purely cosmetic... just make sure there aren't any exceptions
        self.displayer._print_menu("msg", CHOICES)
        self.displayer._print_menu("msg", TAGS)

    def test_get_valid_int_ans_valid(self) -> None:
        # pylint: disable=protected-access
        input_with_timeout = "certbot._internal.display.util.input_with_timeout"
        with mock.patch(input_with_timeout, return_value="1"):
            assert self.displayer._get_valid_int_ans(1) == (display_util.OK, 1)
        ans = "2"
        with mock.patch(input_with_timeout, return_value=ans):
            assert self.displayer._get_valid_int_ans(3) == \
                (display_util.OK, int(ans))

    def test_get_valid_int_ans_invalid(self) -> None:
        # pylint: disable=protected-access
        answers = [
            ["0", "c"],
            ["4", "one", "C"],
            ["c"],
        ]
        input_with_timeout = "certbot._internal.display.util.input_with_timeout"
        for ans in answers:
            with mock.patch(input_with_timeout, side_effect=ans):
                assert self.displayer._get_valid_int_ans(3) == \
                    (display_util.CANCEL, -1)


class NoninteractiveDisplayTest(unittest.TestCase):
    """Test non-interactive display. These tests are pretty easy!"""
    def setUp(self) -> None:
        self.mock_stdout = mock.MagicMock()
        self.displayer = display_obj.NoninteractiveDisplay(self.mock_stdout)

    @mock.patch("certbot._internal.display.obj.logger")
    def test_notification_no_pause(self, mock_logger: MagicMock) -> None:
        self.displayer.notification("message", 10)
        string = self.mock_stdout.write.call_args[0][0]

        assert "message" in string
        mock_logger.debug.assert_called_with("Notifying user: %s", "message")

    def test_notification_decoration(self) -> None:
        from certbot.compat import os
        self.displayer.notification("message", pause=False, decorate=False)
        string = self.mock_stdout.write.call_args[0][0]
        assert string == "message" + os.linesep

        self.displayer.notification("message2", pause=False)
        string = self.mock_stdout.write.call_args[0][0]
        assert "- - - " in string
        assert "message2" + os.linesep in string

    def test_input(self) -> None:
        d = "an incomputable value"
        ret = self.displayer.input("message", default=d)
        assert ret == (display_util.OK, d)
        with pytest.raises(errors.MissingCommandlineFlag):
            self.displayer.input("message")

    def test_menu(self) -> None:
        ret = self.displayer.menu("message", CHOICES, default=1)
        assert ret == (display_util.OK, 1)
        with pytest.raises(errors.MissingCommandlineFlag):
            self.displayer.menu("message", CHOICES)

    def test_yesno(self) -> None:
        d = False
        ret = self.displayer.yesno("message", default=d)
        assert ret == d
        with pytest.raises(errors.MissingCommandlineFlag):
            self.displayer.yesno("message")

    def test_checklist(self) -> None:
        d = [1, 3]
        ret = self.displayer.checklist("message", TAGS, default=d)
        assert ret == (display_util.OK, d)
        with pytest.raises(errors.MissingCommandlineFlag):
            self.displayer.checklist("message", TAGS)

    def test_directory_select(self) -> None:
        default = "/var/www/html"
        expected = (display_util.OK, default)
        actual = self.displayer.directory_select("msg", default)
        assert expected == actual

        with pytest.raises(errors.MissingCommandlineFlag):
            self.displayer.directory_select("msg")


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
