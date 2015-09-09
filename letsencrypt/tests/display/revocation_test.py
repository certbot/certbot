"""Test :mod:`letsencrypt.display.revocation`."""
import sys
import unittest

import mock
import zope.component

from letsencrypt.display import util as display_util

from letsencrypt.tests import test_util


class DisplayCertsTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.revoker import Cert
        self.cert0 = Cert(test_util.vector_path("cert.pem"))
        self.cert1 = Cert(test_util.vector_path("cert-san.pem"))

        self.certs = [self.cert0, self.cert1]

        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    @classmethod
    def _call(cls, certs):
        from letsencrypt.display.revocation import display_certs
        return display_certs(certs)

    @mock.patch("letsencrypt.display.revocation.util")
    def test_revocation(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 0)

        code, choice = self._call(self.certs)

        self.assertEqual(display_util.OK, code)
        self.assertEqual(self.certs[choice], self.cert0)

    @mock.patch("letsencrypt.display.revocation.util")
    def test_cancel(self, mock_util):
        mock_util().menu.return_value = (display_util.CANCEL, -1)

        code, _ = self._call(self.certs)
        self.assertEqual(display_util.CANCEL, code)


class MoreInfoCertTest(unittest.TestCase):
    # pylint: disable=too-few-public-methods
    @classmethod
    def _call(cls, cert):
        from letsencrypt.display.revocation import more_info_cert
        more_info_cert(cert)

    @mock.patch("letsencrypt.display.revocation.util")
    def test_more_info(self, mock_util):
        self._call(mock.MagicMock())

        self.assertEqual(mock_util().notification.call_count, 1)


class SuccessRevocationTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.revoker import Cert
        self.cert = Cert(test_util.vector_path("cert.pem"))

    @classmethod
    def _call(cls, cert):
        from letsencrypt.display.revocation import success_revocation
        success_revocation(cert)

    # Pretty trivial test... something is displayed...
    @mock.patch("letsencrypt.display.revocation.util")
    def test_success_revocation(self, mock_util):
        self._call(self.cert)

        self.assertEqual(mock_util().notification.call_count, 1)


class ConfirmRevocationTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.revoker import Cert
        self.cert = Cert(test_util.vector_path("cert.pem"))

    @classmethod
    def _call(cls, cert):
        from letsencrypt.display.revocation import confirm_revocation
        return confirm_revocation(cert)

    @mock.patch("letsencrypt.display.revocation.util")
    def test_confirm_revocation(self, mock_util):
        mock_util().yesno.return_value = True
        self.assertTrue(self._call(self.cert))

        mock_util().yesno.return_value = False
        self.assertFalse(self._call(self.cert))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
