"""Test :mod:`letsencrypt.client.display.util`."""
import os
import unittest

import mock

from letsencrypt.client.display import util as display_util


class DisplayT(unittest.TestCase):
    """Base class for both utility classes."""
    # pylint: disable=too-few-public-methods
    def setUp(self):
        self.choices = [("First", "Description1"), ("Second", "Description2")]
        self.tags = ["tag1", "tag2", "tag3"]
        self.tags_choices = [("1", "tag1"), ("2", "tag2"), ("3", "tag3")]


def visual(displayer, choices):
    """Visually test all of the display functions."""
    displayer.notification("Random notification!")
    displayer.menu("Question?", choices,
                   ok_label="O", cancel_label="Can", help_label="??")
    displayer.menu("Question?", [choice[1] for choice in choices],
                   ok_label="O", cancel_label="Can", help_label="??")
    displayer.input("Input Message")
    displayer.yesno("YesNo Message", yes_label="Yessir", no_label="Nosir")
    displayer.checklist("Checklist Message", [choice[0] for choice in choices])


class NcursesDisplayTest(DisplayT):
    """Test ncurses display.

    Since this is mostly a wrapper, it might be more helpful to test the actual
    dialog boxes. The test_visual function will actually display the various
    boxes but requires the user to do the verification. If something seems amiss
    please use the test_visual function to debug it, the automatic tests rely
    on too much mocking.

    """
    def setUp(self):
        super(NcursesDisplayTest, self).setUp()
        self.displayer = display_util.NcursesDisplay()

    @mock.patch("letsencrypt.client.display.util.dialog.Dialog.msgbox")
    def test_notification(self, mock_msgbox):
        """Kind of worthless... one liner."""
        self.displayer.notification("message")
        self.assertEqual(mock_msgbox.call_count, 1)

    @mock.patch("letsencrypt.client.display.util.dialog.Dialog.menu")
    def test_menu_tag_and_desc(self, mock_menu):
        mock_menu.return_value = (display_util.OK, "First")

        ret = self.displayer.menu("Message", self.choices)
        mock_menu.assert_called_with(
            "Message", choices=self.choices, ok_label="OK",
            cancel_label="Cancel",
            help_button=False, help_label="",
            width=display_util.WIDTH, height=display_util.HEIGHT)

        self.assertEqual(ret, (display_util.OK, 0))

    @mock.patch("letsencrypt.client.display.util.dialog.Dialog.menu")
    def test_menu_tag_and_desc_cancel(self, mock_menu):
        mock_menu.return_value = (display_util.CANCEL, "")

        ret = self.displayer.menu("Message", self.choices)


        mock_menu.assert_called_with(
            "Message", choices=self.choices, ok_label="OK",
            cancel_label="Cancel",
            help_button=False, help_label="",
            width=display_util.WIDTH, height=display_util.HEIGHT)

        self.assertEqual(ret, (display_util.CANCEL, -1))

    @mock.patch("letsencrypt.client.display.util.dialog.Dialog.menu")
    def test_menu_desc_only(self, mock_menu):
        mock_menu.return_value = (display_util.OK, "1")

        ret = self.displayer.menu("Message", self.tags, help_label="More Info")


        mock_menu.assert_called_with(
            "Message", choices=self.tags_choices, ok_label="OK",
            cancel_label="Cancel",
            help_button=True, help_label="More Info",
            width=display_util.WIDTH, height=display_util.HEIGHT)

        self.assertEqual(ret, (display_util.OK, 0))

    @mock.patch("letsencrypt.client.display.util.dialog.Dialog.menu")
    def test_menu_desc_only_cancel(self, mock_menu):
        mock_menu.return_value = (display_util.CANCEL, "")

        ret = self.displayer.menu("Message", self.tags, help_label="More Info")

        self.assertEqual(ret, (display_util.CANCEL, -1))

    @mock.patch("letsencrypt.client.display.util."
                "dialog.Dialog.inputbox")
    def test_input(self, mock_input):
        self.displayer.input("message")
        mock_input.assert_called_with("message")

    @mock.patch("letsencrypt.client.display.util.dialog.Dialog.yesno")
    def test_yesno(self, mock_yesno):
        mock_yesno.return_value = display_util.OK

        self.assertTrue(self.displayer.yesno("message"))

        mock_yesno.assert_called_with(
            "message", display_util.HEIGHT, display_util.WIDTH,
            yes_label="Yes", no_label="No")

    @mock.patch("letsencrypt.client.display.util."
                "dialog.Dialog.checklist")
    def test_checklist(self, mock_checklist):
        self.displayer.checklist("message", self.tags)

        choices = [
            (self.tags[0], "", False),
            (self.tags[1], "", False),
            (self.tags[2], "", False)
        ]
        mock_checklist.assert_called_with(
            "message", width=display_util.WIDTH, height=display_util.HEIGHT,
            choices=choices)

    # def test_visual(self):
    #    visual(self.displayer, self.choices)


class FileOutputDisplayTest(DisplayT):
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

    @mock.patch("letsencrypt.client.display.util."
                "FileDisplay._get_valid_int_ans")
    def test_menu(self, mock_ans):
        mock_ans.return_value = (display_util.OK, 1)
        ret = self.displayer.menu("message", self.choices)
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
        with mock.patch("__builtin__.raw_input", return_value="cancel"):
            self.assertFalse(self.displayer.yesno("message"))
        with mock.patch("__builtin__.raw_input", return_value="a"):
            self.assertTrue(self.displayer.yesno("msg", yes_label="Agree"))

    @mock.patch("letsencrypt.client.display.util.FileDisplay.input")
    def test_checklist_valid(self, mock_input):
        mock_input.return_value = (display_util.OK, "2 1")
        code, tag_list = self.displayer.checklist("msg", self.tags)
        self.assertEqual(
            (code, set(tag_list)), (display_util.OK, set(["tag1", "tag2"])))

    @mock.patch("letsencrypt.client.display.util.FileDisplay.input")
    def test_checklist_miss_valid(self, mock_input):
        mock_input.side_effect = [
            (display_util.OK, "10"),
            (display_util.OK, "tag1 please"),
            (display_util.OK, "1")
        ]

        ret = self.displayer.checklist("msg", self.tags)
        self.assertEqual(ret, (display_util.OK, ["tag1"]))

    @mock.patch("letsencrypt.client.display.util.FileDisplay.input")
    def test_checklist_miss_quit(self, mock_input):
        mock_input.side_effect = [
            (display_util.OK, "10"),
            (display_util.CANCEL, "1")
        ]
        ret = self.displayer.checklist("msg", self.tags)
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
                self.displayer._scrub_checklist_input(list_, self.tags))
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
                self.displayer._scrub_checklist_input(list_, self.tags), [])

    def test_print_menu(self):
        # pylint: disable=protected-access
        # This is purely cosmetic... just make sure there aren't any exceptions
        self.displayer._print_menu("msg", self.choices)
        self.displayer._print_menu("msg", self.tags)

    def test_wrap_lines(self):
        # pylint: disable=protected-access
        msg = ("This is just a weak test\n"
               "This function is only meant to be for easy viewing\n"
               "Test a really really really really really really really really "
               "really really really really really long line...")
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

    # def test_visual(self):
    #    self.displayer = display_util.FileDisplay(sys.stdout)
    #    visual(self.displayer, self.choices)


class SeparateListInputTest(unittest.TestCase):
    """Test Module functions."""
    def setUp(self):
        self.exp = ["a", "b", "c", "test"]

    @classmethod
    def _call(cls, input_):
        from letsencrypt.client.display.util import separate_list_input
        return separate_list_input(input_)

    def test_commas(self):
        actual = self._call("a,b,c,test")
        self.assertEqual(actual, self.exp)

    def test_spaces(self):
        actual = self._call("a b c test")
        self.assertEqual(actual, self.exp)

    def test_both(self):
        actual = self._call("a, b, c, test")
        self.assertEqual(actual, self.exp)

    def test_mess(self):
        actual = [self._call(" a , b    c \t test")]
        actual.append(self._call(",a, ,, , b c  test "))

        for act in actual:
            self.assertEqual(act, self.exp)


class PlaceParensTest(unittest.TestCase):
    @classmethod
    def _call(cls, label):  # pylint: disable=protected-access
        from letsencrypt.client.display.util import _parens_around_char
        return _parens_around_char(label)

    def test_single_letter(self):
        ret = self._call("a")
        self.assertEqual("(a)", ret)

    def test_multiple(self):
        ret = self._call("Label")
        self.assertEqual("(L)abel", ret)


if __name__ == "__main__":
    unittest.main()
