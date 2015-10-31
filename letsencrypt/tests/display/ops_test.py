"""Test letsencrypt.display.ops."""
import os
import sys
import tempfile
import unittest

import mock
import zope.component

from acme import jose
from acme import messages

from letsencrypt import account
from letsencrypt import interfaces

from letsencrypt.display import util as display_util

from letsencrypt.tests import test_util


KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class ChoosePluginTest(unittest.TestCase):
    """Tests for letsencrypt.display.ops.choose_plugin."""

    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))
        self.mock_apache = mock.Mock(
            description_with_name="a", misconfigured=True)
        self.mock_stand = mock.Mock(
            description_with_name="s", misconfigured=False)
        self.mock_stand.init().more_info.return_value = "standalone"
        self.plugins = [
            self.mock_apache,
            self.mock_stand,
        ]

    def _call(self):
        from letsencrypt.display.ops import choose_plugin
        return choose_plugin(self.plugins, "Question?")

    @mock.patch("letsencrypt.display.ops.util")
    def test_successful_choice(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 0)
        self.assertEqual(self.mock_apache, self._call())

    @mock.patch("letsencrypt.display.ops.util")
    def test_more_info(self, mock_util):
        mock_util().menu.side_effect = [
            (display_util.HELP, 0),
            (display_util.HELP, 1),
            (display_util.OK, 1),
        ]

        self.assertEqual(self.mock_stand, self._call())
        self.assertEqual(mock_util().notification.call_count, 2)

    @mock.patch("letsencrypt.display.ops.util")
    def test_no_choice(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, 0)
        self.assertTrue(self._call() is None)


class PickPluginTest(unittest.TestCase):
    """Tests for letsencrypt.display.ops.pick_plugin."""

    def setUp(self):
        self.config = mock.Mock()
        self.default = None
        self.reg = mock.MagicMock()
        self.question = "Question?"
        self.ifaces = []

    def _call(self):
        from letsencrypt.display.ops import pick_plugin
        return pick_plugin(self.config, self.default, self.reg,
                           self.question, self.ifaces)

    def test_default_provided(self):
        self.default = "foo"
        self._call()
        self.assertEqual(1, self.reg.filter.call_count)

    def test_no_default(self):
        self._call()
        self.assertEqual(1, self.reg.visible().ifaces.call_count)

    def test_no_candidate(self):
        self.assertTrue(self._call() is None)

    def test_single(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        plugin_ep.misconfigured = False

        self.reg.visible().ifaces().verify().available.return_value = {
            "bar": plugin_ep}
        self.assertEqual("foo", self._call())

    def test_single_misconfigured(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        plugin_ep.misconfigured = True

        self.reg.visible().ifaces().verify().available.return_value = {
            "bar": plugin_ep}
        self.assertTrue(self._call() is None)

    def test_multiple(self):
        plugin_ep = mock.MagicMock()
        plugin_ep.init.return_value = "foo"
        self.reg.visible().ifaces().verify().available.return_value = {
            "bar": plugin_ep,
            "baz": plugin_ep,
        }
        with mock.patch("letsencrypt.display.ops.choose_plugin") as mock_choose:
            mock_choose.return_value = plugin_ep
            self.assertEqual("foo", self._call())
        mock_choose.assert_called_once_with(
            [plugin_ep, plugin_ep], self.question)

    def test_choose_plugin_none(self):
        self.reg.visible().ifaces().verify().available.return_value = {
            "bar": None,
            "baz": None,
        }

        with mock.patch("letsencrypt.display.ops.choose_plugin") as mock_choose:
            mock_choose.return_value = None
            self.assertTrue(self._call() is None)


class ConveniencePickPluginTest(unittest.TestCase):
    """Tests for letsencrypt.display.ops.pick_*."""

    def _test(self, fun, ifaces):
        config = mock.Mock()
        default = mock.Mock()
        plugins = mock.Mock()

        with mock.patch("letsencrypt.display.ops.pick_plugin") as mock_p:
            mock_p.return_value = "foo"
            self.assertEqual("foo", fun(config, default, plugins, "Question?"))
        mock_p.assert_called_once_with(
            config, default, plugins, "Question?", ifaces)

    def test_authenticator(self):
        from letsencrypt.display.ops import pick_authenticator
        self._test(pick_authenticator, (interfaces.IAuthenticator,))

    def test_installer(self):
        from letsencrypt.display.ops import pick_installer
        self._test(pick_installer, (interfaces.IInstaller,))

    def test_configurator(self):
        from letsencrypt.display.ops import pick_configurator
        self._test(pick_configurator, (
            interfaces.IAuthenticator, interfaces.IInstaller))


class GetEmailTest(unittest.TestCase):
    """Tests for letsencrypt.display.ops.get_email."""

    def setUp(self):
        mock_display = mock.MagicMock()
        self.input = mock_display.input
        zope.component.provideUtility(mock_display, interfaces.IDisplay)

    @classmethod
    def _call(cls):
        from letsencrypt.display.ops import get_email
        return get_email()

    def test_cancel_none(self):
        self.input.return_value = (display_util.CANCEL, "foo@bar.baz")
        self.assertTrue(self._call() is None)

    def test_ok_safe(self):
        self.input.return_value = (display_util.OK, "foo@bar.baz")
        with mock.patch("letsencrypt.display.ops.le_util"
                        ".safe_email") as mock_safe_email:
            mock_safe_email.return_value = True
            self.assertTrue(self._call() is "foo@bar.baz")

    def test_ok_not_safe(self):
        self.input.return_value = (display_util.OK, "foo@bar.baz")
        with mock.patch("letsencrypt.display.ops.le_util"
                        ".safe_email") as mock_safe_email:
            mock_safe_email.side_effect = [False, True]
            self.assertTrue(self._call() is "foo@bar.baz")


class ChooseAccountTest(unittest.TestCase):
    """Tests for letsencrypt.display.ops.choose_account."""
    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

        self.accounts_dir = tempfile.mkdtemp("accounts")
        self.account_keys_dir = os.path.join(self.accounts_dir, "keys")
        os.makedirs(self.account_keys_dir, 0o700)

        self.config = mock.MagicMock(
            accounts_dir=self.accounts_dir,
            account_keys_dir=self.account_keys_dir,
            server="letsencrypt-demo.org")
        self.key = KEY

        self.acc1 = account.Account(messages.RegistrationResource(
            uri=None, new_authzr_uri=None, body=messages.Registration.from_data(
                email="email1@g.com")), self.key)
        self.acc2 = account.Account(messages.RegistrationResource(
            uri=None, new_authzr_uri=None, body=messages.Registration.from_data(
                email="email2@g.com", phone="phone")), self.key)

    @classmethod
    def _call(cls, accounts):
        from letsencrypt.display import ops
        return ops.choose_account(accounts)

    @mock.patch("letsencrypt.display.ops.util")
    def test_one(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 0)
        self.assertEqual(self._call([self.acc1]), self.acc1)

    @mock.patch("letsencrypt.display.ops.util")
    def test_two(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 1)
        self.assertEqual(self._call([self.acc1, self.acc2]), self.acc2)

    @mock.patch("letsencrypt.display.ops.util")
    def test_cancel(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, 1)
        self.assertTrue(self._call([self.acc1, self.acc2]) is None)


class GenSSLLabURLs(unittest.TestCase):
    """Loose test of _gen_ssl_lab_urls. URL can change easily in the future."""
    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    @classmethod
    def _call(cls, domains):
        from letsencrypt.display.ops import _gen_ssl_lab_urls
        return _gen_ssl_lab_urls(domains)

    def test_zero(self):
        self.assertEqual(self._call([]), [])

    def test_two(self):
        urls = self._call(["eff.org", "umich.edu"])
        self.assertTrue("eff.org" in urls[0])
        self.assertTrue("umich.edu" in urls[1])


class GenHttpsNamesTest(unittest.TestCase):
    """Test _gen_https_names."""
    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    @classmethod
    def _call(cls, domains):
        from letsencrypt.display.ops import _gen_https_names
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
        from letsencrypt.display.ops import choose_names
        return choose_names(installer)

    @mock.patch("letsencrypt.display.ops._choose_names_manually")
    def test_no_installer(self, mock_manual):
        self._call(None)
        self.assertEqual(mock_manual.call_count, 1)

    @mock.patch("letsencrypt.display.ops.util")
    def test_no_installer_cancel(self, mock_util):
        mock_util().input.return_value = (display_util.CANCEL, [])
        self.assertEqual(self._call(None), [])

    @mock.patch("letsencrypt.display.ops.util")
    def test_no_names_choose(self, mock_util):
        self.mock_install().get_all_names.return_value = set()
        mock_util().yesno.return_value = True
        domain = "example.com"
        mock_util().input.return_value = (display_util.OK, domain)

        actual_doms = self._call(self.mock_install)
        self.assertEqual(mock_util().input.call_count, 1)
        self.assertEqual(actual_doms, [domain])

    @mock.patch("letsencrypt.display.ops.util")
    def test_no_names_quit(self, mock_util):
        self.mock_install().get_all_names.return_value = set()
        mock_util().yesno.return_value = False

        self.assertEqual(self._call(self.mock_install), [])

    @mock.patch("letsencrypt.display.ops.util")
    def test_filter_names_valid_return(self, mock_util):
        self.mock_install.get_all_names.return_value = set(["example.com"])
        mock_util().checklist.return_value = (display_util.OK, ["example.com"])

        names = self._call(self.mock_install)
        self.assertEqual(names, ["example.com"])
        self.assertEqual(mock_util().checklist.call_count, 1)

    @mock.patch("letsencrypt.display.ops.util")
    def test_filter_names_nothing_selected(self, mock_util):
        self.mock_install.get_all_names.return_value = set(["example.com"])
        mock_util().checklist.return_value = (display_util.OK, [])

        self.assertEqual(self._call(self.mock_install), [])

    @mock.patch("letsencrypt.display.ops.util")
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
        from letsencrypt.display.ops import success_installation
        success_installation(names)

    @mock.patch("letsencrypt.display.ops.util")
    def test_success_installation(self, mock_util):
        mock_util().notification.return_value = None
        names = ["example.com", "abc.com"]

        self._call(names)

        self.assertEqual(mock_util().notification.call_count, 1)
        arg = mock_util().notification.call_args_list[0][0][0]

        for name in names:
            self.assertTrue(name in arg)


class SuccessRenewalTest(unittest.TestCase):
    # pylint: disable=too-few-public-methods
    """Test the success renewal message."""
    @classmethod
    def _call(cls, names):
        from letsencrypt.display.ops import success_renewal
        success_renewal(names)

    @mock.patch("letsencrypt.display.ops.util")
    def test_success_renewal(self, mock_util):
        mock_util().notification.return_value = None
        names = ["example.com", "abc.com"]

        self._call(names)

        self.assertEqual(mock_util().notification.call_count, 1)
        arg = mock_util().notification.call_args_list[0][0][0]

        for name in names:
            self.assertTrue(name in arg)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
