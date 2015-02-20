"""Test :mod:`letsencrypt.client.display.revocation`."""
import os
import pkg_resources
import sys
import unittest

import mock
import zope.component

from letsencrypt.client.display import util as display_util


class ChooseCertsTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.revoker import Cert
        base_package = "letsencrypt.client.tests"
        self.cert0 = Cert(pkg_resources.resource_filename(
            base_package, os.path.join("testdata", "cert.pem")))
        self.cert1 = Cert(pkg_resources.resource_filename(
            base_package, os.path.join("testdata", "cert-san.pem")))

        self.certs = [self.cert0, self.cert1]

        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    @classmethod
    def _call(cls, certs):
        from letsencrypt.client.display.revocation import choose_certs
        return choose_certs(certs)

    @mock.patch("letsencrypt.client.display.revocation.util")
    def test_revocation(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 0)

        choice = self._call(self.certs)

        self.assertTrue(self.certs[choice] == self.cert0)

    @mock.patch("letsencrypt.client.display.revocation.util")
    def test_cancel(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, -1)

        self.assertRaises(SystemExit, self._call, self.certs)

    @mock.patch("letsencrypt.client.display.revocation.util")
    def test_more_info(self, mock_util):
        mock_util().menu.side_effect = [
            (display_util.HELP, 1),
            (display_util.OK, 1),
        ]

        choice = self._call(self.certs)

        self.assertTrue(self.certs[choice] == self.cert1)
        self.assertEqual(mock_util().notification.call_count, 1)


class SuccessRevocationTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.revoker import Cert
        base_package = "letsencrypt.client.tests"
        self.cert = Cert(pkg_resources.resource_filename(
            base_package, os.path.join("testdata", "cert.pem")))

    @classmethod
    def _call(cls, cert):
        from letsencrypt.client.display.revocation import success_revocation
        success_revocation(cert)

    # Pretty trivial test... something is displayed...
    @mock.patch("letsencrypt.client.display.revocation.util")
    def test_success_revocation(self, mock_util):
        self._call(self.cert)

        self.assertEqual(mock_util().notification.call_count, 1)


class ConfirmRevocationTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.revoker import Cert
        self.cert = Cert(pkg_resources.resource_filename(
            "letsencrypt.client.tests", os.path.join("testdata", "cert.pem")))

    @classmethod
    def _call(cls, cert):
        from letsencrypt.client.display.revocation import confirm_revocation
        return confirm_revocation(cert)

    @mock.patch("letsencrypt.client.display.revocation.util")
    def test_confirm_revocation(self, mock_util):
        mock_util().yesno.return_value = True
        self.assertTrue(self._call(self.cert))

        mock_util().yesno.return_value = False
        self.assertFalse(self._call(self.cert))

if __name__ == "__main__":
    unittest.main()
