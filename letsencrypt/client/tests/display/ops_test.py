"""Test letsencrypt.client.display.ops."""
import os
import sys
import tempfile
import unittest

import mock
import zope.component

from letsencrypt.client import account
from letsencrypt.client import interfaces
from letsencrypt.client import le_util

from letsencrypt.client.display import util as display_util


class ChoosePluginTest(unittest.TestCase):
    """Tests for letsencrypt.client.display.ops.choose_plugin."""

    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))
        self.mock_apache = mock.Mock(
            name_with_description="a", misconfigured=True)
        self.mock_stand = mock.Mock(
            name_with_description="s", misconfigured=False)
        self.mock_stand.init().more_info.return_value = "standalone"
        self.plugins = [
            self.mock_apache,
            self.mock_stand,
        ]

    def _call(self):
        from letsencrypt.client.display.ops import choose_plugin
        return choose_plugin(self.plugins, "Question?")

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_successful_choice(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 0)
        self.assertEqual(self.mock_apache, self._call())

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_more_info(self, mock_util):
        mock_util().menu.side_effect = [
            (display_util.HELP, 0),
            (display_util.HELP, 1),
            (display_util.OK, 1),
        ]

        self.assertEqual(self.mock_stand, self._call())
        self.assertEqual(mock_util().notification.call_count, 2)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_no_choice(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, 0)
        self.assertTrue(self._call() is None)


class PickPluginTest(unittest.TestCase):
    """Tests for letsencrypt.client.display.ops.pick_plugin."""

    def setUp(self):
        self.config = mock.Mock()
        self.default = None
        self.reg = mock.MagicMock()
        self.question = "Question?"
        self.ifaces = []

    def _call(self):
        from letsencrypt.client.display.ops import pick_plugin
        return pick_plugin(self.config, self.default, self.reg,
                           self.question, self.ifaces)

    def test_default_provided(self):
        self.default = "foo"
        self._call()
        self.reg.filter.assert_called_once()

    def test_no_default(self):
        self._call()
        self.reg.filter.assert_called_once()

    def test_no_candidate(self):
        self.assertTrue(self._call() is None)

    def test_single(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        self.reg.ifaces().verify().available.return_value = {"bar": plugin_ep}
        self.assertEqual("foo", self._call())

    def test_multiple(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        self.reg.ifaces().verify().available.return_value = {
            "bar": plugin_ep,
            "baz": plugin_ep,
        }
        with mock.patch("letsencrypt.client.display"
                        ".ops.choose_plugin") as mock_choose:
            mock_choose.return_value = plugin_ep
            self.assertEqual("foo", self._call())
        mock_choose.assert_called_once_with(
            [plugin_ep, plugin_ep], self.question)


class ConveniencePickPluginTest(unittest.TestCase):
    """Tests for letsencrypt.client.display.ops.pick_*."""

    def _test(self, fun, ifaces):
        config = mock.Mock()
        default = mock.Mock()
        plugins = mock.Mock()

        with mock.patch("letsencrypt.client.display.ops.pick_plugin") as mock_p:
            mock_p.return_value = "foo"
            self.assertEqual("foo", fun(config, default, plugins, "Question?"))
        mock_p.assert_called_once_with(
            config, default, plugins, "Question?", ifaces)

    def test_authenticator(self):
        from letsencrypt.client.display.ops import pick_authenticator
        self._test(pick_authenticator, (interfaces.IAuthenticator,))

    def test_installer(self):
        from letsencrypt.client.display.ops import pick_installer
        self._test(pick_installer, (interfaces.IInstaller,))

    def test_configurator(self):
        from letsencrypt.client.display.ops import pick_configurator
        self._test(pick_configurator, (
            interfaces.IAuthenticator, interfaces.IInstaller))


class ChooseAccountTest(unittest.TestCase):
    """Test choose_account."""
    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

        self.accounts_dir = tempfile.mkdtemp("accounts")
        self.account_keys_dir = os.path.join(self.accounts_dir, "keys")
        os.makedirs(self.account_keys_dir, 0o700)

        self.config = mock.MagicMock(
            accounts_dir=self.accounts_dir,
            account_keys_dir=self.account_keys_dir,
            server="letsencrypt-demo.org")
        self.key = le_util.Key("keypath", "pem")

        self.acc1 = account.Account(self.config, self.key, "email1@g.com")
        self.acc2 = account.Account(
            self.config, self.key, "email2@g.com", "phone")
        self.acc1.save()
        self.acc2.save()

    @classmethod
    def _call(cls, accounts):
        from letsencrypt.client.display import ops
        return ops.choose_account(accounts)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_one(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 0)
        self.assertEqual(self._call([self.acc1]), self.acc1)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_two(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 1)
        self.assertEqual(self._call([self.acc1, self.acc2]), self.acc2)

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_cancel(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, 1)
        self.assertTrue(self._call([self.acc1, self.acc2]) is None)


class GenHttpsNamesTest(unittest.TestCase):
    """Test _gen_https_names."""
    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    @classmethod
    def _call(cls, domains):
        from letsencrypt.client.display.ops import _gen_https_names
        return _gen_https_names(domains)

    def test_zero(self):
        self.assertEqual(self._call([]), "")

    def test_one(self):
        doms = [
            "example.com",
            "asllkjsadfljasdf.c",
        ]
        for dom in doms:
            self.assertEqual(self._call([dom]), "https://%s" % dom)

    def test_two(self):
        domains_list = [
            ["foo.bar.org", "bar.org"],
            ["paypal.google.facebook.live.com", "*.zombo.example.com"],
        ]
        for doms in domains_list:
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
        self.assertEqual(self._call(None), [])

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

        self.assertEqual(self._call(self.mock_install), [])

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

        self.assertEqual(self._call(self.mock_install), [])

    @mock.patch("letsencrypt.client.display.ops.util")
    def test_filter_names_cancel(self, mock_util):
        self.mock_install.get_all_names.return_value = set(["example.com"])
        mock_util().checklist.return_value = (
            display_util.CANCEL, ["example.com"])

        self.assertEqual(self._call(self.mock_install), [])


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
