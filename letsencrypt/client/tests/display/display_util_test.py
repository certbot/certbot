import sys
import unittest

import mock

from letsencrypt.client.display import display_util


class DisplayT(unittest.TestCase):
    def setUp(self):
        self.choices = [("First", "Description1"), ("Second", "Description2")]
        self.tags = ["tag1", "tag2", "tag3"]


def test_visual(displayer, choices):
    """Visually test all of the display functions."""
    displayer.notification("Random notification!")
    displayer.menu("Question?", choices,
                        ok_label="O", cancel_label="Can", help_label="??")
    displayer.menu("Question?", [choice[1] for choice in choices],
                        ok_label="O", cancel_label="Can", help_label="??")
    displayer.input("Input Message")
    displayer.yesno(
        "Yes/No Message", yes_label="Yessir", no_label="Nosir")
    displayer.checklist(
        "Checklist Message", [choice[0] for choice in choices])


class NcursesDisplayTest(DisplayT):
    """Test ncurses display."""
    def setUp(self):
        super(NcursesDisplayTest, self).setUp()
        self.displayer = display_util.NcursesDisplay()

    @mock.patch("letsencrypt.client.display.display_util.dialog.Dialog.msgbox")
    def test_notification(self, mock_msgbox):
        """Kind of worthless... one liner."""
        self.displayer.notification("message")
        self.assertEqual(mock_msgbox.call_count, 1)

    @mock.patch("letsencrypt.client.display.display_util.dialog.Dialog.menu")
    def test_menu(self, mock_menu):
        pass

    def test_visual(self):
        test_visual(self.displayer, self.choices)


class FileOutputDisplayTest(DisplayT):
    """Test stdout display."""
    def setUp(self):
        super(FileOutputDisplayTest, self).setUp()
        self.displayer = display_util.FileDisplay(sys.stdout)

    def test_visual(self):
        test_visual(self.displayer, self.choices)


class SeparateListInputTest(unittest.TestCase):
    """Test Module functions."""
    def setUp(self):
        self.exp = ["a", "b", "c", "test"]

    @classmethod
    def _call(cls, input):
        from letsencrypt.client.display.display_util import separate_list_input
        return separate_list_input(input)

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
    def _call(cls, label):
        from letsencrypt.client.display.display_util import _parens_around_char
        return _parens_around_char(label)

    def test_single_letter(self):
        ret = self._call("a")
        self.assertEqual("(a)", ret)

    def test_multiple(self):
        ret = self._call("Label")
        self.assertEqual("(L)abel", ret)


if __name__ == "__main__":
    unittest.main()