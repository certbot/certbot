"""Test display.ops."""
import sys
import unittest

import mock
import zope.component

from letsencrypt.client.display import util as display_util


class ChooseAuthenticatorTest(unittest.TestCase):
    """Test choose_authenticator function."""
    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))
        self.mock_apache = mock.Mock()
        self.mock_stand = mock.Mock()
        self.mock_apache().more_info.return_value = "Apache Info"
        self.mock_stand().more_info.return_value = "Standalone Info"

        self.auths = [
            ("Apache Tag", self.mock_apache),
            ("Standalone Tag", self.mock_stand)
        ]

        self.errs = {self.mock_apache: "This is an error message."}

    @classmethod
    def _call(cls, auths, errs):
        from letsencrypt.client.display.ops import choose_authenticator
        return choose_authenticator(auths, errs)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_successful_choice(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 0)

        ret = self._call(self.auths, {})

        self.assertEqual(ret, self.mock_apache)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_more_info(self, mock_util):
        mock_util().menu.side_effect = [
            (display_util.HELP, 0),
            (display_util.HELP, 1),
            (display_util.OK, 1),
        ]

        ret = self._call(self.auths, self.errs)

        self.assertEqual(mock_util().notification.call_count, 2)
        self.assertEqual(ret, self.mock_stand)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_no_choice(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, 0)

        self.assertRaises(SystemExit, self._call, self.auths, {})


class GenHttpsNamesTest(unittest.TestCase):
    """Test _gen_https_names"""
    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    @classmethod
    def _call(cls, domains):
        from letsencrypt.client.display.ops import _gen_https_names
        return _gen_https_names(domains)

    def test_zero(self):
        self.assertEqual(self._call([]), "")

    def test_one(self):
        dom = "example.com"
        self.assertEqual(self._call([dom]), "https://%s" % dom)

    def test_two(self):
        doms = ["foo.bar.org", "bar.org"]
        self.assertEqual(
            self._call(doms),
            "https://{dom[0]} and https://{dom[1]}".format(dom=doms))

    def test_three(self):
        doms = ["a.org", "b.org", "c.org"]
        # We use an oxford comma
        self.assertEqual(
            self._call(doms),
            "https://{dom[0]}, https://{dom[1]}, and https://{dom[2]}".format(
                dom=doms))

    def test_four(self):
        doms = ["a.org", "b.org", "c.org", "d.org"]
        exp = ("https://{dom[0]}, https://{dom[1]}, https://{dom[2]}, "
               "and https://{dom[3]}".format(dom=doms))

        self.assertEqual(self._call(doms), exp)


class ChooseNamesTest(unittest.TestCase):
    """Test choose names."""
    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))
        self.mock_install = mock.MagicMock()

    @classmethod
    def _call(cls, installer):
        from letsencrypt.client.display.ops import choose_names
        return choose_names(installer)

    @mock.patch("letsencrypt.client.display.ops._choose_names_manually")
    def test_no_installer(self, mock_manual):
        self._call(None)
        self.assertEqual(mock_manual.call_count, 1)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_no_installer_cancel(self, mock_util):
        mock_util().input.return_value = (display_util.CANCEL, [])
        self.assertRaises(SystemExit, self._call, None)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_no_names_choose(self, mock_util):
        self.mock_install().get_all_names.return_value = set()
        mock_util().yesno.return_value = True
        domain = "example.com"
        mock_util().input.return_value = (display_util.OK, domain)

        actual_doms = self._call(self.mock_install)
        self.assertEqual(mock_util().input.call_count, 1)
        self.assertEqual(actual_doms, [domain])

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_no_names_quit(self, mock_util):
        self.mock_install().get_all_names.return_value = set()
        mock_util().yesno.return_value = False

        self.assertRaises(SystemExit, self._call, self.mock_install)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_filter_names_valid_return(self, mock_util):
        self.mock_install.get_all_names.return_value = set(["example.com"])
        mock_util().checklist.return_value = (display_util.OK, ["example.com"])

        names = self._call(self.mock_install)
        self.assertEqual(names, ["example.com"])
        self.assertEqual(mock_util().checklist.call_count, 1)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_filter_names_nothing_selected(self, mock_util):
        self.mock_install.get_all_names.return_value = set(["example.com"])
        mock_util().checklist.return_value = (display_util.OK, [])

        self.assertRaises(SystemExit, self._call, self.mock_install)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_filter_names_cancel(self, mock_util):
        self.mock_install.get_all_names.return_value = set(["example.com"])
        mock_util().checklist.return_value = (
            display_util.CANCEL, ["example.com"])

        self.assertRaises(SystemExit, self._call, self.mock_install)


class SuccessInstallationTest(unittest.TestCase):
    # pylint: disable=too-few-public-methods
    """Test the success installation message."""
    @classmethod
    def _call(cls, names):
        from letsencrypt.client.display.ops import success_installation
        success_installation(names)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_success_installation(self, mock_util):
        mock_util().notification.return_value = None
        names = ["example.com", "abc.com"]

        self._call(names)

        self.assertEqual(mock_util().notification.call_count, 1)
        arg = mock_util().notification.call_args_list[0][0][0]

        for name in names:
            self.assertTrue(name in arg)


if __name__ == "__main__":
    unittest.main()
