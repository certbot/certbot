"""Test :mod:`certbot._internal.display.util`."""
import unittest

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


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
