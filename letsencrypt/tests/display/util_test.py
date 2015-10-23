"""Test :mod:`letsencrypt.display.util`."""
import os
import unittest

import mock

from letsencrypt.display import util as display_util


CHOICES = [("First", "Description1"), ("Second", "Description2")]
TAGS = ["tag1", "tag2", "tag3"]
TAGS_CHOICES = [("1", "tag1"), ("2", "tag2"), ("3", "tag3")]


class NcursesDisplayTest(unittest.TestCase):
    """Test ncurses display.

    Since this is mostly a wrapper, it might be more helpful to test the
    actual dialog boxes. The test file located in ./tests/display.py
    (relative to the root of the repository) will actually display the
    various boxes but requires the user to do the verification. If
    something seems amiss please use that test script to debug it, the
    automatic tests rely on too much mocking.

    """
    def setUp(self):
        super(NcursesDisplayTest, self).setUp()
        self.displayer = display_util.NcursesDisplay()

        self.default_menu_options = {
            "choices": CHOICES,
            "ok_label": "OK",
            "cancel_label": "Cancel",
            "help_button": False,
            "help_label": "",
            "width": display_util.WIDTH,
            "height": display_util.HEIGHT,
            "menu_height": display_util.HEIGHT - 6,
        }

    @mock.patch("letsencrypt.display.util.dialog.Dialog.msgbox")
    def test_notification(self, mock_msgbox):
        """Kind of worthless... one liner."""
        self.displayer.notification("message")
        self.assertEqual(mock_msgbox.call_count, 1)

    @mock.patch("letsencrypt.display.util.dialog.Dialog.menu")
    def test_menu_tag_and_desc(self, mock_menu):
        mock_menu.return_value = (display_util.OK, "First")

        ret = self.displayer.menu("Message", CHOICES)
        mock_menu.assert_called_with("Message", **self.default_menu_options)

        self.assertEqual(ret, (display_util.OK, 0))

    @mock.patch("letsencrypt.display.util.dialog.Dialog.menu")
    def test_menu_tag_and_desc_cancel(self, mock_menu):
        mock_menu.return_value = (display_util.CANCEL, "")

        ret = self.displayer.menu("Message", CHOICES)

        mock_menu.assert_called_with("Message", **self.default_menu_options)

        self.assertEqual(ret, (display_util.CANCEL, -1))

    @mock.patch("letsencrypt.display.util.dialog.Dialog.menu")
    def test_menu_desc_only(self, mock_menu):
        mock_menu.return_value = (display_util.OK, "1")

        ret = self.displayer.menu("Message", TAGS, help_label="More Info")

        self.default_menu_options.update(
            choices=TAGS_CHOICES, help_button=True, help_label="More Info")
        mock_menu.assert_called_with("Message", **self.default_menu_options)

        self.assertEqual(ret, (display_util.OK, 0))

    @mock.patch("letsencrypt.display.util.dialog.Dialog.menu")
    def test_menu_desc_only_help(self, mock_menu):
        mock_menu.return_value = (display_util.HELP, "2")

        ret = self.displayer.menu("Message", TAGS, help_label="More Info")

        self.assertEqual(ret, (display_util.HELP, 1))

    @mock.patch("letsencrypt.display.util.dialog.Dialog.menu")
    def test_menu_desc_only_cancel(self, mock_menu):
        mock_menu.return_value = (display_util.CANCEL, "")

        ret = self.displayer.menu("Message", TAGS, help_label="More Info")

        self.assertEqual(ret, (display_util.CANCEL, -1))

    @mock.patch("letsencrypt.display.util."
                "dialog.Dialog.inputbox")
    def test_input(self, mock_input):
        self.displayer.input("message")
        self.assertEqual(mock_input.call_count, 1)

    @mock.patch("letsencrypt.display.util.dialog.Dialog.yesno")
    def test_yesno(self, mock_yesno):
        mock_yesno.return_value = display_util.OK

        self.assertTrue(self.displayer.yesno("message"))

        mock_yesno.assert_called_with(
            "message", display_util.HEIGHT, display_util.WIDTH,
            yes_label="Yes", no_label="No")

    @mock.patch("letsencrypt.display.util."
                "dialog.Dialog.checklist")
    def test_checklist(self, mock_checklist):
        self.displayer.checklist("message", TAGS)

        choices = [
            (TAGS[0], "", True),
            (TAGS[1], "", True),
            (TAGS[2], "", True),
        ]
        mock_checklist.assert_called_with(
            "message", width=display_util.WIDTH, height=display_util.HEIGHT,
            choices=choices)


class FileOutputDisplayTest(unittest.TestCase):
    """Test stdout display.

    Most of this class has to deal with visual output.  In order to test how the
    functions look to a user, uncomment the test_visual function.

    """
    def setUp(self):
        super(FileOutputDisplayTest, self).setUp()
        self.mock_stdout = mock.MagicMock()
        self.displayer = display_util.FileDisplay(self.mock_stdout)

    def test_notification_no_pause(self):
        self.displayer.notification("message", 10, False)
        string = self.mock_stdout.write.call_args[0][0]

        self.assertTrue("message" in string)

    def test_notification_pause(self):
        with mock.patch("__builtin__.raw_input", return_value="enter"):
            self.displayer.notification("message")

        self.assertTrue("message" in self.mock_stdout.write.call_args[0][0])

    @mock.patch("letsencrypt.display.util."
                "FileDisplay._get_valid_int_ans")
    def test_menu(self, mock_ans):
        mock_ans.return_value = (display_util.OK, 1)
        ret = self.displayer.menu("message", CHOICES)
        self.assertEqual(ret, (display_util.OK, 0))

    def test_input_cancel(self):
        with mock.patch("__builtin__.raw_input", return_value="c"):
            code, _ = self.displayer.input("message")

        self.assertTrue(code, display_util.CANCEL)

    def test_input_normal(self):
        with mock.patch("__builtin__.raw_input", return_value="domain.com"):
            code, input_ = self.displayer.input("message")

        self.assertEqual(code, display_util.OK)
        self.assertEqual(input_, "domain.com")

    def test_yesno(self):
        with mock.patch("__builtin__.raw_input", return_value="Yes"):
            self.assertTrue(self.displayer.yesno("message"))
        with mock.patch("__builtin__.raw_input", return_value="y"):
            self.assertTrue(self.displayer.yesno("message"))
        with mock.patch("__builtin__.raw_input", side_effect=["maybe", "y"]):
            self.assertTrue(self.displayer.yesno("message"))
        with mock.patch("__builtin__.raw_input", return_value="No"):
            self.assertFalse(self.displayer.yesno("message"))
        with mock.patch("__builtin__.raw_input", side_effect=["cancel", "n"]):
            self.assertFalse(self.displayer.yesno("message"))

        with mock.patch("__builtin__.raw_input", return_value="a"):
            self.assertTrue(self.displayer.yesno("msg", yes_label="Agree"))

    @mock.patch("letsencrypt.display.util.FileDisplay.input")
    def test_checklist_valid(self, mock_input):
        mock_input.return_value = (display_util.OK, "2 1")
        code, tag_list = self.displayer.checklist("msg", TAGS)
        self.assertEqual(
            (code, set(tag_list)), (display_util.OK, set(["tag1", "tag2"])))

    @mock.patch("letsencrypt.display.util.FileDisplay.input")
    def test_checklist_miss_valid(self, mock_input):
        mock_input.side_effect = [
            (display_util.OK, "10"),
            (display_util.OK, "tag1 please"),
            (display_util.OK, "1")
        ]

        ret = self.displayer.checklist("msg", TAGS)
        self.assertEqual(ret, (display_util.OK, ["tag1"]))

    @mock.patch("letsencrypt.display.util.FileDisplay.input")
    def test_checklist_miss_quit(self, mock_input):
        mock_input.side_effect = [
            (display_util.OK, "10"),
            (display_util.CANCEL, "1")
        ]
        ret = self.displayer.checklist("msg", TAGS)
        self.assertEqual(ret, (display_util.CANCEL, []))

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
        text = self.displayer._wrap_lines(msg)

        self.assertEqual(text.count(os.linesep), 3)

    def test_get_valid_int_ans_valid(self):
        # pylint: disable=protected-access
        with mock.patch("__builtin__.raw_input", return_value="1"):
            self.assertEqual(
                self.displayer._get_valid_int_ans(1), (display_util.OK, 1))
        ans = "2"
        with mock.patch("__builtin__.raw_input", return_value=ans):
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
        for ans in answers:
            with mock.patch("__builtin__.raw_input", side_effect=ans):
                self.assertEqual(
                    self.displayer._get_valid_int_ans(3),
                    (display_util.CANCEL, -1))


class SeparateListInputTest(unittest.TestCase):
    """Test Module functions."""
    def setUp(self):
        self.exp = ["a", "b", "c", "test"]

    @classmethod
    def _call(cls, input_):
        from letsencrypt.display.util import separate_list_input
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
        from letsencrypt.display.util import _parens_around_char
        return _parens_around_char(label)

    def test_single_letter(self):
        self.assertEqual("(a)", self._call("a"))

    def test_multiple(self):
        self.assertEqual("(L)abel", self._call("Label"))
        self.assertEqual("(y)es please", self._call("yes please"))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
