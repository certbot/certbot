import os
import pkg_resources
import sys
import unittest

import mock
import zope.component

from letsencrypt.client.display import display_util


class ChooseCertsTest(unittest.TestCase):
    def setUp(self):
        from letsencrypt.client.revoker import Cert
        base_package = "letsencrypt.client.tests"
        self.cert1 = Cert(pkg_resources.resource_filename(
            base_package, os.path.join("testdata", "cert.pem")))
        self.cert2 = Cert(pkg_resources.resource_filename(
            base_package, os.path.join("testdata", "cert-san.pem")))

        self.certs = [self.cert1, self.cert2]

        zope.component.provideUtility(display_util.FileDisplay(sys.stdout))

    @classmethod
    def _call(cls, certs):
        from letsencrypt.client.display.revocation import choose_certs
        return choose_certs(certs)

    #@mock.patch("letsencrypt.client.display.revocation.util")
    def test_confirm_revocation(self):
        pass
        #mock_util().yesno.return_value = True
        self._call(self.certs)



if __name__ == "__main__":
    unittest.main()
