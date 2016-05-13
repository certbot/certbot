# coding=utf-8
"""Test certbot.display.ops."""
import os
import sys
import tempfile
import unittest

import mock
import zope.component

from acme import jose
from acme import messages

from certbot import account
from certbot import interfaces

from certbot.display import util as display_util

from certbot.tests import test_util


KEY = jose.JWKRSA.load(test_util.load_vector("rsa512_key.pem"))


class GetEmailTest(unittest.TestCase):
    """Tests for certbot.display.ops.get_email."""

    def setUp(self):
        mock_display = mock.MagicMock()
        self.input = mock_display.input
        zope.component.provideUtility(mock_display, interfaces.IDisplay)

    @classmethod
    def _call(cls, **kwargs):
        from certbot.display.ops import get_email
        return get_email(**kwargs)

    def test_cancel_none(self):
        self.input.return_value = (display_util.CANCEL, "foo@bar.baz")
        self.assertTrue(self._call() is None)

    def test_ok_safe(self):
        self.input.return_value = (display_util.OK, "foo@bar.baz")
        with mock.patch("certbot.display.ops.le_util.safe_email") as mock_safe_email:
            mock_safe_email.return_value = True
            self.assertTrue(self._call() is "foo@bar.baz")

    def test_ok_not_safe(self):
        self.input.return_value = (display_util.OK, "foo@bar.baz")
        with mock.patch("certbot.display.ops.le_util.safe_email") as mock_safe_email:
            mock_safe_email.side_effect = [False, True]
            self.assertTrue(self._call() is "foo@bar.baz")

    def test_more_and_invalid_flags(self):
        more_txt = "--register-unsafely-without-email"
        invalid_txt = "There seem to be problems"
        base_txt = "Enter email"
        self.input.return_value = (display_util.OK, "foo@bar.baz")
        with mock.patch("certbot.display.ops.le_util.safe_email") as mock_safe_email:
            mock_safe_email.return_value = True
            self._call()
            msg = self.input.call_args[0][0]
            self.assertTrue(more_txt not in msg)
            self.assertTrue(invalid_txt not in msg)
            self.assertTrue(base_txt in msg)
            self._call(more=True)
            msg = self.input.call_args[0][0]
            self.assertTrue(more_txt in msg)
            self.assertTrue(invalid_txt not in msg)
            self._call(more=True, invalid=True)
            msg = self.input.call_args[0][0]
            self.assertTrue(more_txt in msg)
            self.assertTrue(invalid_txt in msg)
            self.assertTrue(base_txt in msg)


class ChooseAccountTest(unittest.TestCase):
    """Tests for certbot.display.ops.choose_account."""
    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

        self.accounts_dir = tempfile.mkdtemp("accounts")
        self.account_keys_dir = os.path.join(self.accounts_dir, "keys")
        os.makedirs(self.account_keys_dir, 0o700)

        self.config = mock.MagicMock(
            accounts_dir=self.accounts_dir,
            account_keys_dir=self.account_keys_dir,
            server="certbot-demo.org")
        self.key = KEY

        self.acc1 = account.Account(messages.RegistrationResource(
            uri=None, new_authzr_uri=None, body=messages.Registration.from_data(
                email="email1@g.com")), self.key)
        self.acc2 = account.Account(messages.RegistrationResource(
            uri=None, new_authzr_uri=None, body=messages.Registration.from_data(
                email="email2@g.com", phone="phone")), self.key)

    @classmethod
    def _call(cls, accounts):
        from certbot.display import ops
        return ops.choose_account(accounts)

    @mock.patch("certbot.display.ops.z_util")
    def test_one(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 0)
        self.assertEqual(self._call([self.acc1]), self.acc1)

    @mock.patch("certbot.display.ops.z_util")
    def test_two(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 1)
        self.assertEqual(self._call([self.acc1, self.acc2]), self.acc2)

    @mock.patch("certbot.display.ops.z_util")
    def test_cancel(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, 1)
        self.assertTrue(self._call([self.acc1, self.acc2]) is None)


class GenSSLLabURLs(unittest.TestCase):
    """Loose test of _gen_ssl_lab_urls. URL can change easily in the future."""
    def setUp(self):
        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    @classmethod
    def _call(cls, domains):
        from certbot.display.ops import _gen_ssl_lab_urls
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
        from certbot.display.ops import _gen_https_names
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
        from certbot.display.ops import choose_names
        return choose_names(installer)

    @mock.patch("certbot.display.ops._choose_names_manually")
    def test_no_installer(self, mock_manual):
        self._call(None)
        self.assertEqual(mock_manual.call_count, 1)

    @mock.patch("certbot.display.ops.z_util")
    def test_no_installer_cancel(self, mock_util):
        mock_util().input.return_value = (display_util.CANCEL, [])
        self.assertEqual(self._call(None), [])

    @mock.patch("certbot.display.ops.z_util")
    def test_no_names_choose(self, mock_util):
        self.mock_install().get_all_names.return_value = set()
        mock_util().yesno.return_value = True
        domain = "example.com"
        mock_util().input.return_value = (display_util.OK, domain)

        actual_doms = self._call(self.mock_install)
        self.assertEqual(mock_util().input.call_count, 1)
        self.assertEqual(actual_doms, [domain])

    @mock.patch("certbot.display.ops.z_util")
    def test_no_names_quit(self, mock_util):
        self.mock_install().get_all_names.return_value = set()
        mock_util().yesno.return_value = False

        self.assertEqual(self._call(self.mock_install), [])

    @mock.patch("certbot.display.ops.z_util")
    def test_filter_names_valid_return(self, mock_util):
        self.mock_install.get_all_names.return_value = set(["example.com"])
        mock_util().checklist.return_value = (display_util.OK, ["example.com"])

        names = self._call(self.mock_install)
        self.assertEqual(names, ["example.com"])
        self.assertEqual(mock_util().checklist.call_count, 1)

    @mock.patch("certbot.display.ops.z_util")
    def test_filter_names_nothing_selected(self, mock_util):
        self.mock_install.get_all_names.return_value = set(["example.com"])
        mock_util().checklist.return_value = (display_util.OK, [])

        self.assertEqual(self._call(self.mock_install), [])

    @mock.patch("certbot.display.ops.z_util")
    def test_filter_names_cancel(self, mock_util):
        self.mock_install.get_all_names.return_value = set(["example.com"])
        mock_util().checklist.return_value = (
            display_util.CANCEL, ["example.com"])

        self.assertEqual(self._call(self.mock_install), [])

    def test_get_valid_domains(self):
        from certbot.display.ops import get_valid_domains
        all_valid = ["example.com", "second.example.com",
                     "also.example.com"]
        all_invalid = ["xn--ls8h.tld", "*.wildcard.com", "notFQDN",
                       "uniçodé.com"]
        two_valid = ["example.com", "xn--ls8h.tld", "also.example.com"]
        self.assertEqual(get_valid_domains(all_valid), all_valid)
        self.assertEqual(get_valid_domains(all_invalid), [])
        self.assertEqual(len(get_valid_domains(two_valid)), 2)

    @mock.patch("certbot.display.ops.z_util")
    def test_choose_manually(self, mock_util):
        from certbot.display.ops import _choose_names_manually
        # No retry
        mock_util().yesno.return_value = False
        # IDN and no retry
        mock_util().input.return_value = (display_util.OK,
                                          "uniçodé.com")
        self.assertEqual(_choose_names_manually(), [])
        # IDN exception with previous mocks
        with mock.patch(
                "certbot.display.ops.display_util.separate_list_input"
        ) as mock_sli:
            unicode_error = UnicodeEncodeError('mock', u'', 0, 1, 'mock')
            mock_sli.side_effect = unicode_error
            self.assertEqual(_choose_names_manually(), [])
        # Punycode and no retry
        mock_util().input.return_value = (display_util.OK,
                                          "xn--ls8h.tld")
        self.assertEqual(_choose_names_manually(), [])
        # non-FQDN and no retry
        mock_util().input.return_value = (display_util.OK,
                                          "notFQDN")
        self.assertEqual(_choose_names_manually(), [])
        # Two valid domains
        mock_util().input.return_value = (display_util.OK,
                                          ("example.com,"
                                           "valid.example.com"))
        self.assertEqual(_choose_names_manually(),
                         ["example.com", "valid.example.com"])
        # Three iterations
        mock_util().input.return_value = (display_util.OK,
                                          "notFQDN")
        yn = mock.MagicMock()
        yn.side_effect = [True, True, False]
        mock_util().yesno = yn
        _choose_names_manually()
        self.assertEqual(mock_util().yesno.call_count, 3)


class SuccessInstallationTest(unittest.TestCase):
    # pylint: disable=too-few-public-methods
    """Test the success installation message."""
    @classmethod
    def _call(cls, names):
        from certbot.display.ops import success_installation
        success_installation(names)

    @mock.patch("certbot.display.ops.z_util")
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
        from certbot.display.ops import success_renewal
        success_renewal(names, "renew")

    @mock.patch("certbot.display.ops.z_util")
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
