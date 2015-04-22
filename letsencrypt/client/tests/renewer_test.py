"""Tests for letsencrypt.client.renewer.py"""

import configobj
import datetime
import mock
import os
import tempfile
import pkg_resources
import pytz
import shutil
import unittest

ALL_FOUR = ("cert", "privkey", "chain", "fullchain")

class RenewableCertTests(unittest.TestCase):
    """Tests for the RenewableCert class as well as other functions
    within renewer.py."""
    def setUp(self):
        from letsencrypt.client import renewer
        self.tempdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tempdir, "live", "example.org"))
        os.makedirs(os.path.join(self.tempdir, "archive", "example.org"))
        os.makedirs(os.path.join(self.tempdir, "configs"))
        defaults = configobj.ConfigObj()
        defaults["live_dir"] = os.path.join(self.tempdir, "live")
        defaults["official_archive_dir"] = os.path.join(self.tempdir, "archive")
        defaults["renewal_configs_dir"] = os.path.join(self.tempdir, "configs")
        config = configobj.ConfigObj()
        config["cert"] = os.path.join(self.tempdir, "live", "example.org", "cert.pem")
        config["privkey"] = os.path.join(self.tempdir, "live", "example.org", "privkey.pem")
        config["chain"] = os.path.join(self.tempdir, "live", "example.org", "chain.pem")
        config["fullchain"] = os.path.join(self.tempdir, "live", "example.org", "fullchain.pem")
        config.filename = os.path.join(self.tempdir, "configs",
                                       "example.org.conf")
        self.defaults = defaults     # for main() test
        self.test_rc = renewer.RenewableCert(config, defaults)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_initialization(self):
        self.assertEqual(self.test_rc.lineagename, "example.org")
        self.assertEqual(self.test_rc.cert, os.path.join(self.tempdir, "live", "example.org", "cert.pem"))
        self.assertEqual(self.test_rc.privkey, os.path.join(self.tempdir, "live", "example.org", "privkey.pem"))
        self.assertEqual(self.test_rc.chain, os.path.join(self.tempdir, "live", "example.org", "chain.pem"))
        self.assertEqual(self.test_rc.fullchain, os.path.join(self.tempdir, "live", "example.org", "fullchain.pem"))

    def test_renewal_config_filename_not_ending_in_conf(self):
        """Test that the RenewableCert constructor will complain if
        the renewal configuration file doesn't end in ".conf"."""
        from letsencrypt.client import renewer
        defaults = configobj.ConfigObj()
        config = configobj.ConfigObj()
        config["cert"] = "/tmp/cert.pem"
        config["privkey"] = "/tmp/privkey.pem"
        config["chain"] = "/tmp/chain.pem"
        config["fullchain"] = "/tmp/fullchain.pem"
        config.filename = "/tmp/sillyfile"
        self.assertRaises(ValueError, renewer.RenewableCert, config, defaults)

    def test_consistent(self):
        oldcert = self.test_rc.cert
        self.test_rc.cert = "relative/path"
        # Absolute path for item requirement
        self.assertEqual(self.test_rc.consistent(), False)
        self.test_rc.cert = oldcert
        # Items must exist requirement
        self.assertEqual(self.test_rc.consistent(), False)
        # Items must be symlinks requirements
        with open(self.test_rc.cert, "w") as f:
            f.write("hello")
        with open(self.test_rc.privkey, "w") as f:
            f.write("hello")
        with open(self.test_rc.chain, "w") as f:
            f.write("hello")
        with open(self.test_rc.fullchain, "w") as f:
            f.write("hello")
        self.assertEqual(self.test_rc.consistent(), False)
        os.unlink(self.test_rc.cert)
        os.unlink(self.test_rc.privkey)
        os.unlink(self.test_rc.chain)
        os.unlink(self.test_rc.fullchain)
        # Items must point to desired place if they are relative
        os.symlink(os.path.join("..", "cert17.pem"), self.test_rc.cert)
        os.symlink(os.path.join("..", "privkey17.pem"), self.test_rc.privkey)
        os.symlink(os.path.join("..", "chain17.pem"), self.test_rc.chain)
        os.symlink(os.path.join("..", "fullchain17.pem"), self.test_rc.fullchain)
        self.assertEqual(self.test_rc.consistent(), False)
        os.unlink(self.test_rc.cert)
        os.unlink(self.test_rc.privkey)
        os.unlink(self.test_rc.chain)
        os.unlink(self.test_rc.fullchain)
        # Items must point to desired place if they are absolute
        os.symlink(os.path.join(self.tempdir, "cert17.pem"), self.test_rc.cert)
        os.symlink(os.path.join(self.tempdir, "privkey17.pem"), self.test_rc.privkey)
        os.symlink(os.path.join(self.tempdir, "chain17.pem"), self.test_rc.chain)
        os.symlink(os.path.join(self.tempdir, "fullchain17.pem"), self.test_rc.fullchain)
        self.assertEqual(self.test_rc.consistent(), False)
        os.unlink(self.test_rc.cert)
        os.unlink(self.test_rc.privkey)
        os.unlink(self.test_rc.chain)
        os.unlink(self.test_rc.fullchain)
        # Items must point to things that exist
        os.symlink(os.path.join("..", "..", "archive", "example.org", "cert17.pem"), self.test_rc.cert)
        os.symlink(os.path.join("..", "..", "archive", "example.org", "privkey17.pem"), self.test_rc.privkey)
        os.symlink(os.path.join("..", "..", "archive", "example.org", "chain17.pem"), self.test_rc.chain)
        os.symlink(os.path.join("..", "..", "archive", "example.org", "fullchain17.pem"), self.test_rc.fullchain)
        self.assertEqual(self.test_rc.consistent(), False)
        # This version should work
        with open(self.test_rc.cert, "w") as f:
            f.write("cert")
        with open(self.test_rc.privkey, "w") as f:
            f.write("privkey")
        with open(self.test_rc.chain, "w") as f:
            f.write("chain")
        with open(self.test_rc.fullchain, "w") as f:
            f.write("fullchain")
        self.assertEqual(self.test_rc.consistent(), True)
        # Items must point to things that follow the naming convention
        os.unlink(self.test_rc.fullchain)
        os.symlink(os.path.join("..", "..", "archive", "example.org", "fullchain_17.pem"), self.test_rc.fullchain)
        with open(self.test_rc.fullchain, "w") as f:
            f.write("wrongly-named fullchain")
        self.assertEqual(self.test_rc.consistent(), False)

    def test_current_target(self):
        # Relative path logic
        os.symlink(os.path.join("..", "..", "archive", "example.org", "cert17.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write("cert")
        self.assertTrue(os.path.samefile(self.test_rc.current_target("cert"), os.path.join(self.tempdir, "archive", "example.org", "cert17.pem")))
        # Absolute path logic
        os.unlink(self.test_rc.cert)
        os.symlink(os.path.join(self.tempdir, "archive", "example.org", "cert17.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write("cert")
        self.assertTrue(os.path.samefile(self.test_rc.current_target("cert"), os.path.join(self.tempdir, "archive", "example.org", "cert17.pem")))

    def test_current_version(self):
        for ver in (1, 5, 10, 20):
            os.symlink(os.path.join("..", "..", "archive", "example.org", "cert{0}.pem".format(ver)), self.test_rc.cert)
            with open(self.test_rc.cert, "w") as f:
                f.write("cert")
            os.unlink(self.test_rc.cert)
        os.symlink(os.path.join("..", "..", "archive", "example.org", "cert10.pem"), self.test_rc.cert)
        self.assertEqual(self.test_rc.current_version("cert"), 10)

    def test_no_current_version(self):
        self.assertEqual(self.test_rc.current_version("cert"), None)

    def test_latest_and_next_versions(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                where = self.test_rc.__getattribute__(kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org", "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
        self.assertEqual(self.test_rc.latest_common_version(), 5)
        self.assertEqual(self.test_rc.next_free_version(), 6)
        # Having one kind of file of a later version doesn't change the
        # result
        os.unlink(self.test_rc.privkey)
        os.symlink(os.path.join("..", "..", "archive", "example.org", "privkey7.pem"), self.test_rc.privkey)
        with open(self.test_rc.privkey, "w") as f:
            f.write("privkey")
        self.assertEqual(self.test_rc.latest_common_version(), 5)
        # ... although it does change the next free version
        self.assertEqual(self.test_rc.next_free_version(), 8)
        # Nor does having three out of four change the result
        os.unlink(self.test_rc.cert)
        os.symlink(os.path.join("..", "..", "archive", "example.org", "cert7.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write("cert")
        os.unlink(self.test_rc.fullchain)
        os.symlink(os.path.join("..", "..", "archive", "example.org", "fullchain7.pem"), self.test_rc.fullchain)
        with open(self.test_rc.fullchain, "w") as f:
            f.write("fullchain")
        self.assertEqual(self.test_rc.latest_common_version(), 5)
        # If we have everything from a much later version, it does change
        # the result
        ver = 17
        for kind in ALL_FOUR:
            where = self.test_rc.__getattribute__(kind)
            if os.path.islink(where):
                os.unlink(where)
            os.symlink(os.path.join("..", "..", "archive", "example.org", "{0}{1}.pem".format(kind, ver)), where)
            with open(where, "w") as f:
                f.write(kind)
        self.assertEqual(self.test_rc.latest_common_version(), 17)
        self.assertEqual(self.test_rc.next_free_version(), 18)

    def test_update_link_to(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                where = self.test_rc.__getattribute__(kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org", "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
                self.assertEqual(ver, self.test_rc.current_version(kind))
        self.test_rc.update_link_to("cert", 3)
        self.test_rc.update_link_to("privkey", 2)
        self.assertEqual(3, self.test_rc.current_version("cert"))
        self.assertEqual(2, self.test_rc.current_version("privkey"))
        self.assertEqual(5, self.test_rc.current_version("chain"))
        self.assertEqual(5, self.test_rc.current_version("fullchain"))
        # Currently we are allowed to update to a version that doesn't
        # exist
        self.test_rc.update_link_to("chain", 3000)
        # However, current_version doesn't allow querying the resulting
        # version (because it's a broken link).
        self.assertEqual(os.path.basename(os.readlink(self.test_rc.chain)),
                         "chain3000.pem")

    def test_version(self):
        os.symlink(os.path.join("..", "..", "archive", "example.org", "cert12.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write("cert")
        # TODO: We should probably test that the directory is still the
        #       same, but it's tricky because we can get an absolute
        #       path out when we put a relative path in.
        self.assertEqual("cert8.pem",
                         os.path.basename(self.test_rc.version("cert", 8)))

    def test_update_all_links_to(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                where = self.test_rc.__getattribute__(kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org", "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
                self.assertEqual(ver, self.test_rc.current_version(kind))
        self.assertEqual(self.test_rc.latest_common_version(), 5)
        for ver in range(1, 6):
            self.test_rc.update_all_links_to(ver)
            for kind in ALL_FOUR:
                self.assertEqual(ver, self.test_rc.current_version(kind))
            self.assertEqual(self.test_rc.latest_common_version(), 5)

    def test_has_pending_deployment(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                where = self.test_rc.__getattribute__(kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org", "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
                self.assertEqual(ver, self.test_rc.current_version(kind))
        for ver in range(1, 6):
            self.test_rc.update_all_links_to(ver)
            for kind in ALL_FOUR:
                self.assertEqual(ver, self.test_rc.current_version(kind))
            if ver < 5:
                self.assertTrue(self.test_rc.has_pending_deployment())
            else:
                self.assertFalse(self.test_rc.has_pending_deployment())

    def test_notbefore(self):
        test_cert = pkg_resources.resource_string(
            "letsencrypt.client.tests", "testdata/cert.pem")
        os.symlink(os.path.join("..", "..", "archive", "example.org", "cert12.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        for result in (self.test_rc.notbefore(), self.test_rc.notbefore(12)):
            self.assertEqual(result, datetime.datetime.utcfromtimestamp(1418337285).replace(tzinfo=pytz.UTC))
            self.assertEqual(result.utcoffset(), datetime.timedelta(0))
        # 2014-12-11 22:34:45+00:00 = Unix time 1418337285

    def test_notafter(self):
        test_cert = pkg_resources.resource_string(
            "letsencrypt.client.tests", "testdata/cert.pem")
        os.symlink(os.path.join("..", "..", "archive", "example.org", "cert12.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        for result in (self.test_rc.notafter(), self.test_rc.notafter(12)):
            self.assertEqual(result, datetime.datetime.utcfromtimestamp(1418942085).replace(tzinfo=pytz.UTC))
            self.assertEqual(result.utcoffset(), datetime.timedelta(0))
        # 2014-12-18 22:34:45+00:00 = Unix time 1418942085

    @mock.patch("letsencrypt.client.renewer.datetime")
    def test_should_autodeploy(self, mock_datetime):
        # Autodeployment turned off
        self.test_rc.configuration["autodeploy"] = "0"
        self.assertFalse(self.test_rc.should_autodeploy())
        self.test_rc.configuration["autodeploy"] = "1"
        # No pending deployment
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                where = self.test_rc.__getattribute__(kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org", "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
        self.assertFalse(self.test_rc.should_autodeploy())
        test_cert = pkg_resources.resource_string(
            "letsencrypt.client.tests", "testdata/cert.pem")
        mock_datetime.timedelta = datetime.timedelta
        # 2014-12-13 12:00:00+00:00 (about 5 days prior to expiry)
        mock_datetime.datetime.utcnow.return_value = datetime.datetime.utcfromtimestamp(1418472000)
        self.test_rc.update_all_links_to(3)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        self.test_rc.configuration["deploy_before_expiry"] = "2 months"
        self.assertTrue(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "1 week"
        self.assertTrue(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "4 days"
        self.assertFalse(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "2 days"
        self.assertFalse(self.test_rc.should_autodeploy())
        # 2009-05-01 12:00:00+00:00 (about 5 years prior to expiry)
        mock_datetime.datetime.utcnow.return_value = datetime.datetime.utcfromtimestamp(1241179200)
        self.test_rc.configuration["deploy_before_expiry"] = "8 hours"
        self.assertFalse(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "2 days"
        self.assertFalse(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "40 days"
        self.assertFalse(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "9 months"
        self.assertFalse(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "7 years"
        self.assertTrue(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "11 years 2 months"
        self.assertTrue(self.test_rc.should_autodeploy())
        # 2015-01-01 (after expiry has already happened)
        mock_datetime.datetime.utcnow.return_value = datetime.datetime.utcfromtimestamp(1420070400)
        self.test_rc.configuration["deploy_before_expiry"] = "0 seconds"
        self.assertTrue(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "10 seconds"
        self.assertTrue(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "10 minutes"
        self.assertTrue(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "10 weeks"
        self.assertTrue(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "10 months"
        self.assertTrue(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "10 years"
        self.assertTrue(self.test_rc.should_autodeploy())
        self.test_rc.configuration["deploy_before_expiry"] = "300 months"
        self.assertTrue(self.test_rc.should_autodeploy())

    @mock.patch("letsencrypt.client.renewer.datetime")
    @mock.patch("letsencrypt.client.renewer.RenewableCert.ocsp_revoked")
    def test_should_autorenew(self, mock_ocsp, mock_datetime):
        # Autorenewal turned off
        self.test_rc.configuration["autorenew"] = "0"
        self.assertFalse(self.test_rc.should_autorenew())
        self.test_rc.configuration["autorenew"] = "1"
        for kind in ALL_FOUR:
            where = self.test_rc.__getattribute__(kind)
            os.symlink(os.path.join("..", "..", "archive", "example.org", "{0}12.pem".format(kind)), where)
            with open(where, "w") as f:
                f.write(kind)
        test_cert = pkg_resources.resource_string(
            "letsencrypt.client.tests", "testdata/cert.pem")
        # Mandatory renewal on the basis of OCSP revocation
        mock_ocsp.return_value = True
        self.assertTrue(self.test_rc.should_autorenew())
        mock_ocsp.return_value = False
        # On the basis of expiry time
        mock_datetime.timedelta = datetime.timedelta
        # 2014-12-13 12:00:00+00:00 (about 5 days prior to expiry)
        mock_datetime.datetime.utcnow.return_value = datetime.datetime.utcfromtimestamp(1418472000)
        self.test_rc.update_all_links_to(12)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        self.test_rc.configuration["renew_before_expiry"] = "2 months"
        self.assertTrue(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "1 week"
        self.assertTrue(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "4 days"
        self.assertFalse(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "2 days"
        self.assertFalse(self.test_rc.should_autorenew())
        # 2009-05-01 12:00:00+00:00 (about 5 years prior to expiry)
        mock_datetime.datetime.utcnow.return_value = datetime.datetime.utcfromtimestamp(1241179200)
        self.test_rc.configuration["renew_before_expiry"] = "8 hours"
        self.assertFalse(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "2 days"
        self.assertFalse(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "40 days"
        self.assertFalse(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "9 months"
        self.assertFalse(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "7 years"
        self.assertTrue(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "11 years 2 months"
        self.assertTrue(self.test_rc.should_autorenew())
        # 2015-01-01 (after expiry has already happened)
        mock_datetime.datetime.utcnow.return_value = datetime.datetime.utcfromtimestamp(1420070400)
        self.test_rc.configuration["renew_before_expiry"] = "0 seconds"
        self.assertTrue(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "10 seconds"
        self.assertTrue(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "10 minutes"
        self.assertTrue(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "10 weeks"
        self.assertTrue(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "10 months"
        self.assertTrue(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "10 years"
        self.assertTrue(self.test_rc.should_autorenew())
        self.test_rc.configuration["renew_before_expiry"] = "300 months"
        self.assertTrue(self.test_rc.should_autorenew())

    def test_save_successor(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                where = self.test_rc.__getattribute__(kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org", "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
        self.test_rc.update_all_links_to(3)
        self.assertEqual(6, self.test_rc.save_successor(3, "new cert", "new chain"))
        with open(self.test_rc.version("cert", 6)) as f:
            self.assertEqual(f.read(), "new cert")
        with open(self.test_rc.version("chain", 6)) as f:
            self.assertEqual(f.read(), "new chain")
        with open(self.test_rc.version("fullchain", 6)) as f:
            self.assertEqual(f.read(), "new cert" + "new chain")
        # version 6 of the key should be a link back to version 3
        self.assertFalse(os.path.islink(self.test_rc.version("privkey", 3)))
        self.assertTrue(os.path.islink(self.test_rc.version("privkey", 6)))
        # Let's try two more updates
        self.assertEqual(7, self.test_rc.save_successor(6, "again", "newer chain"))
        self.assertEqual(8, self.test_rc.save_successor(7, "hello", "other chain"))
        # All of the subsequent versions should link directly to the original
        # privkey.
        self.assertTrue(os.path.islink(self.test_rc.version("privkey", 6)))
        self.assertTrue(os.path.islink(self.test_rc.version("privkey", 7)))
        self.assertTrue(os.path.islink(self.test_rc.version("privkey", 8)))
        self.assertEqual(os.path.basename(os.readlink(self.test_rc.version("privkey", 6))), "privkey3.pem")
        self.assertEqual(os.path.basename(os.readlink(self.test_rc.version("privkey", 7))), "privkey3.pem")
        self.assertEqual(os.path.basename(os.readlink(self.test_rc.version("privkey", 8))), "privkey3.pem")
        for kind in ALL_FOUR:
            self.assertEqual(self.test_rc.available_versions(kind), range(1, 9))
            self.assertEqual(self.test_rc.current_version(kind), 3)
        # Test updating from latest version rather than old version
        self.test_rc.update_all_links_to(8)
        self.assertEqual(9, self.test_rc.save_successor(8, "last", "attempt"))
        for kind in ALL_FOUR:
            self.assertEqual(self.test_rc.available_versions(kind), range(1, 10))
            self.assertEqual(self.test_rc.current_version(kind), 8)
        with open(self.test_rc.version("fullchain", 9)) as f:
            self.assertEqual(f.read(), "last" + "attempt")

    def test_new_lineage(self):
        """Test for new_lineage() class method."""
        from letsencrypt.client import renewer
        config_dir = self.defaults["renewal_configs_dir"]
        archive_dir = self.defaults["official_archive_dir"]
        live_dir = self.defaults["live_dir"]
        result = renewer.RenewableCert.new_lineage("the-lineage.com", "cert",
                                                   "privkey", "chain",
                                                   self.defaults)
        # This consistency check tests most relevant properties about the
        # newly created cert lineage.
        self.assertTrue(result.consistent())
        self.assertTrue(os.path.exists(os.path.join(config_dir,
                                                    "the-lineage.com.conf")))
        with open(result.fullchain) as f:
            self.assertEqual(f.read(), "cert" + "chain")
        # Let's do it again and make sure it makes a different lineage
        result = renewer.RenewableCert.new_lineage("the-lineage.com", "cert2",
                                                   "privkey2", "chain2",
                                                   self.defaults)
        print os.listdir(config_dir)
        self.assertTrue(os.path.exists(
            os.path.join(config_dir, "the-lineage.com-0001.conf")))
        # Now trigger the detection of already existing files
        os.mkdir(os.path.join(live_dir, "the-lineage.com-0002"))
        self.assertRaises(ValueError, renewer.RenewableCert.new_lineage,
                          "the-lineage.com", "cert3", "privkey3", "chain3",
                          self.defaults)
        os.mkdir(os.path.join(archive_dir, "other-example.com"))
        self.assertRaises(ValueError, renewer.RenewableCert.new_lineage,
                          "other-example.com", "cert4", "privkey4", "chain4",
                          self.defaults)

    @mock.patch("letsencrypt.client.renewer.le_util.unique_lineage_name")
    def test_invalid_config_filename(self, mock_uln):
        from letsencrypt.client import renewer
        mock_uln.return_value = "this_does_not_end_with_dot_conf", "yikes"
        self.assertRaises(ValueError, renewer.RenewableCert.new_lineage,
                          "example.com", "cert", "privkey", "chain",
                          self.defaults)

    def test_bad_kind(self):
        self.assertRaises(ValueError, self.test_rc.current_target, "elephant")
        self.assertRaises(ValueError, self.test_rc.current_version, "elephant")
        self.assertRaises(ValueError, self.test_rc.version, "elephant", 17)
        self.assertRaises(ValueError, self.test_rc.available_versions, "elephant")
        self.assertRaises(ValueError, self.test_rc.newest_available_version, "elephant")
        self.assertRaises(ValueError, self.test_rc.update_link_to, "elephant", 17)

    def test_ocsp_revoked(self):
        # XXX: This is currently hardcoded to False due to a lack of an
        #      OCSP server to test against.
        self.assertEqual(self.test_rc.ocsp_revoked(), False)

    def test_parse_time_interval(self):
        from letsencrypt.client import renewer
        # XXX: I'm not sure if intervals related to years and months
        #      take account of the current date (if so, some of these
        #      may fail in the future, like in leap years or even in
        #      months of different lengths!)
        self.assertEqual(renewer.parse_time_interval(""),
                         datetime.timedelta(0))
        self.assertEqual(renewer.parse_time_interval("1 hour"),
                         datetime.timedelta(0, 3600))
        self.assertEqual(renewer.parse_time_interval("17 days"),
                         datetime.timedelta(17))
        # Days are assumed if no unit is specified.
        self.assertEqual(renewer.parse_time_interval("23"),
                         datetime.timedelta(23))
        self.assertEqual(renewer.parse_time_interval("1 month"),
                         datetime.timedelta(31))
        self.assertEqual(renewer.parse_time_interval("7 weeks"),
                         datetime.timedelta(49))
        self.assertEqual(renewer.parse_time_interval("1 year 1 day"),
                         datetime.timedelta(366))
        self.assertEqual(renewer.parse_time_interval("1 year-1 day"),
                         datetime.timedelta(364))
        self.assertEqual(renewer.parse_time_interval("4 years"),
                         datetime.timedelta(1461))

    @mock.patch("letsencrypt.client.renewer.notify")
    @mock.patch("letsencrypt.client.renewer.RenewableCert")
    @mock.patch("letsencrypt.client.renewer.renew")
    def test_main(self, mock_renew, mock_rc, mock_notify):
        """Test for main() function."""
        from letsencrypt.client import renewer
        mock_rc_instance = mock.MagicMock()
        mock_rc_instance.should_autodeploy.return_value = True
        mock_rc_instance.should_autorenew.return_value = True
        mock_rc_instance.latest_common_version.return_value = 10
        mock_rc.return_value = mock_rc_instance
        with open(os.path.join(self.defaults["renewal_configs_dir"], "README"), "w") as f:
            f.write("This is a README file to make sure that the renewer is")
            f.write("able to correctly ignore files that don't end in .conf.")
        with open(os.path.join(self.defaults["renewal_configs_dir"], "example.org.conf"), "w") as f:
            # This isn't actually parsed in this test; we have a separate
            # test_initialization that tests the initialization, assuming
            # that configobj can correctly parse the config file.
            f.write("cert = cert.pem\nprivkey = privkey.pem\n")
            f.write("chain = chain.pem\nfullchain = fullchain.pem\n")
        with open(os.path.join(self.defaults["renewal_configs_dir"], "example.com.conf"), "w") as f:
            f.write("cert = cert.pem\nprivkey = privkey.pem\n")
            f.write("chain = chain.pem\nfullchain = fullchain.pem\n")
        renewer.main(self.defaults)
        self.assertEqual(mock_rc.call_count, 2)
        self.assertEqual(mock_rc_instance.update_all_links_to.call_count, 2)
        self.assertEqual(mock_notify.notify.call_count, 4)
        self.assertEqual(mock_renew.call_count, 2)
        # If we have instances that don't need any work done, no work should
        # be done (call counts associated with processing deployments or
        # renewals should not increase).
        mock_happy_instance = mock.MagicMock()
        mock_happy_instance.should_autodeploy.return_value = False
        mock_happy_instance.should_autorenew.return_value = False
        mock_happy_instance.latest_common_version.return_value = 10
        mock_rc.return_value = mock_happy_instance
        renewer.main(self.defaults)
        self.assertEqual(mock_rc.call_count, 4)
        self.assertEqual(mock_happy_instance.update_all_links_to.call_count, 0)
        self.assertEqual(mock_notify.notify.call_count, 4)
        self.assertEqual(mock_renew.call_count, 2)

if __name__ == "__main__":
    unittest.main()
