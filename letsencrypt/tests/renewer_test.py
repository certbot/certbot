"""Tests for letsencrypt/renewer.py"""

import configobj
import datetime
import mock
import os
import tempfile
import pkg_resources
import pytz
import shutil
import unittest

from letsencrypt.storage import ALL_FOUR

def unlink_all(rc_object):
    """Unlink all four items associated with this RenewableCert.
    (Helper function.)"""
    for kind in ALL_FOUR:
        os.unlink(rc_object.__getattribute__(kind))

def fill_with_sample_data(rc_object):
    """Put dummy data into all four files of this RenewableCert.
    (Helper function.)"""
    for kind in ALL_FOUR:
        with open(rc_object.__getattribute__(kind), "w") as f:
            f.write(kind)

class RenewableCertTests(unittest.TestCase):
    # pylint: disable=too-many-public-methods
    """Tests for the RenewableCert class as well as other functions
    within renewer.py."""
    def setUp(self):
        from letsencrypt import storage
        self.tempdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tempdir, "live", "example.org"))
        os.makedirs(os.path.join(self.tempdir, "archive", "example.org"))
        os.makedirs(os.path.join(self.tempdir, "configs"))
        defaults = configobj.ConfigObj()
        defaults["live_dir"] = os.path.join(self.tempdir, "live")
        defaults["official_archive_dir"] = os.path.join(self.tempdir,
                                                        "archive")
        defaults["renewal_configs_dir"] = os.path.join(self.tempdir,
                                                       "configs")
        config = configobj.ConfigObj()
        for kind in ALL_FOUR:
            config[kind] = os.path.join(self.tempdir, "live", "example.org",
                                        kind + ".pem")
        config.filename = os.path.join(self.tempdir, "configs",
                                       "example.org.conf")
        self.defaults = defaults     # for main() test
        self.test_rc = storage.RenewableCert(config, defaults)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_initialization(self):
        self.assertEqual(self.test_rc.lineagename, "example.org")
        self.assertEqual(self.test_rc.cert, os.path.join(self.tempdir, "live",
                                                         "example.org",
                                                         "cert.pem"))
        self.assertEqual(self.test_rc.privkey, os.path.join(self.tempdir,
                                                            "live",
                                                            "example.org",
                                                            "privkey.pem"))
        self.assertEqual(self.test_rc.chain, os.path.join(self.tempdir,
                                                          "live",
                                                          "example.org",
                                                          "chain.pem"))
        self.assertEqual(self.test_rc.fullchain, os.path.join(self.tempdir,
                                                              "live",
                                                              "example.org",
                                                              "fullchain.pem"))

    def test_renewal_bad_config(self):
        """Test that the RenewableCert constructor will complain if
        the renewal configuration file doesn't end in ".conf" or if it
        isn't a ConfigObj."""
        from letsencrypt import storage
        defaults = configobj.ConfigObj()
        config = configobj.ConfigObj()
        for kind in ALL_FOUR:
            config["cert"] = "/tmp/" + kind + ".pem"
        config.filename = "/tmp/sillyfile"
        self.assertRaises(ValueError, storage.RenewableCert, config, defaults)
        self.assertRaises(TypeError, storage.RenewableCert, "fun", defaults)

    def test_renewal_incomplete_config(self):
        """Test that the RenewableCert constructor will complain if
        the renewal configuration file is missing a required file element."""
        from letsencrypt import storage
        defaults = configobj.ConfigObj()
        config = configobj.ConfigObj()
        config["cert"] = "/tmp/cert.pem"
        # Here the required privkey is missing.
        config["chain"] = "/tmp/chain.pem"
        config["fullchain"] = "/tmp/fullchain.pem"
        config.filename = "/tmp/genuineconfig.conf"
        self.assertRaises(ValueError, storage.RenewableCert, config, defaults)

    def test_consistent(self): # pylint: disable=too-many-statements
        oldcert = self.test_rc.cert
        self.test_rc.cert = "relative/path"
        # Absolute path for item requirement
        self.assertEqual(self.test_rc.consistent(), False)
        self.test_rc.cert = oldcert
        # Items must exist requirement
        self.assertEqual(self.test_rc.consistent(), False)
        # Items must be symlinks requirements
        fill_with_sample_data(self.test_rc)
        self.assertEqual(self.test_rc.consistent(), False)
        unlink_all(self.test_rc)
        # Items must point to desired place if they are relative
        for kind in ALL_FOUR:
            os.symlink(os.path.join("..", kind + "17.pem"),
                       self.test_rc.__getattribute__(kind))
        self.assertEqual(self.test_rc.consistent(), False)
        unlink_all(self.test_rc)
        # Items must point to desired place if they are absolute
        for kind in ALL_FOUR:
            os.symlink(os.path.join(self.tempdir, kind + "17.pem"),
                       self.test_rc.__getattribute__(kind))
        self.assertEqual(self.test_rc.consistent(), False)
        unlink_all(self.test_rc)
        # Items must point to things that exist
        for kind in ALL_FOUR:
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    kind + "17.pem"),
                       self.test_rc.__getattribute__(kind))
        self.assertEqual(self.test_rc.consistent(), False)
        # This version should work
        fill_with_sample_data(self.test_rc)
        self.assertEqual(self.test_rc.consistent(), True)
        # Items must point to things that follow the naming convention
        os.unlink(self.test_rc.fullchain)
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "fullchain_17.pem"), self.test_rc.fullchain)
        with open(self.test_rc.fullchain, "w") as f:
            f.write("wrongly-named fullchain")
        self.assertEqual(self.test_rc.consistent(), False)

    def test_current_target(self):
        # Relative path logic
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "cert17.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write("cert")
        self.assertTrue(os.path.samefile(self.test_rc.current_target("cert"),
                                         os.path.join(self.tempdir, "archive",
                                                      "example.org",
                                                      "cert17.pem")))
        # Absolute path logic
        os.unlink(self.test_rc.cert)
        os.symlink(os.path.join(self.tempdir, "archive", "example.org",
                                "cert17.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write("cert")
        self.assertTrue(os.path.samefile(self.test_rc.current_target("cert"),
                                         os.path.join(self.tempdir, "archive",
                                                      "example.org",
                                                      "cert17.pem")))

    def test_current_version(self):
        for ver in (1, 5, 10, 20):
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    "cert{0}.pem".format(ver)),
                       self.test_rc.cert)
            with open(self.test_rc.cert, "w") as f:
                f.write("cert")
            os.unlink(self.test_rc.cert)
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "cert10.pem"), self.test_rc.cert)
        self.assertEqual(self.test_rc.current_version("cert"), 10)

    def test_no_current_version(self):
        self.assertEqual(self.test_rc.current_version("cert"), None)

    def test_latest_and_next_versions(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                where = self.test_rc.__getattribute__(kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org",
                                        "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
        self.assertEqual(self.test_rc.latest_common_version(), 5)
        self.assertEqual(self.test_rc.next_free_version(), 6)
        # Having one kind of file of a later version doesn't change the
        # result
        os.unlink(self.test_rc.privkey)
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "privkey7.pem"), self.test_rc.privkey)
        with open(self.test_rc.privkey, "w") as f:
            f.write("privkey")
        self.assertEqual(self.test_rc.latest_common_version(), 5)
        # ... although it does change the next free version
        self.assertEqual(self.test_rc.next_free_version(), 8)
        # Nor does having three out of four change the result
        os.unlink(self.test_rc.cert)
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "cert7.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write("cert")
        os.unlink(self.test_rc.fullchain)
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "fullchain7.pem"), self.test_rc.fullchain)
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
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    "{0}{1}.pem".format(kind, ver)), where)
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
                os.symlink(os.path.join("..", "..", "archive", "example.org",
                                        "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
                self.assertEqual(ver, self.test_rc.current_version(kind))
        self.test_rc.update_link_to("cert", 3)
        self.test_rc.update_link_to("privkey", 2)
        self.assertEqual(3, self.test_rc.current_version("cert"))
        self.assertEqual(2, self.test_rc.current_version("privkey"))
        self.assertEqual(5, self.test_rc.current_version("chain"))
        self.assertEqual(5, self.test_rc.current_version("fullchain"))
        # Currently we are allowed to update to a version that doesn't exist
        self.test_rc.update_link_to("chain", 3000)
        # However, current_version doesn't allow querying the resulting
        # version (because it's a broken link).
        self.assertEqual(os.path.basename(os.readlink(self.test_rc.chain)),
                         "chain3000.pem")

    def test_version(self):
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "cert12.pem"), self.test_rc.cert)
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
                os.symlink(os.path.join("..", "..", "archive", "example.org",
                                        "{0}{1}.pem".format(kind, ver)), where)
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
                os.symlink(os.path.join("..", "..", "archive", "example.org",
                                        "{0}{1}.pem".format(kind, ver)), where)
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
            "letsencrypt.tests", "testdata/cert.pem")
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "cert12.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        desired_time = datetime.datetime.utcfromtimestamp(1418337285)
        desired_time = desired_time.replace(tzinfo=pytz.UTC)
        for result in (self.test_rc.notbefore(), self.test_rc.notbefore(12)):
            self.assertEqual(result, desired_time)
            self.assertEqual(result.utcoffset(), datetime.timedelta(0))
        # 2014-12-11 22:34:45+00:00 = Unix time 1418337285

    def test_notafter(self):
        test_cert = pkg_resources.resource_string(
            "letsencrypt.tests", "testdata/cert.pem")
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "cert12.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        desired_time = datetime.datetime.utcfromtimestamp(1418942085)
        desired_time = desired_time.replace(tzinfo=pytz.UTC)
        for result in (self.test_rc.notafter(), self.test_rc.notafter(12)):
            self.assertEqual(result, desired_time)
            self.assertEqual(result.utcoffset(), datetime.timedelta(0))
        # 2014-12-18 22:34:45+00:00 = Unix time 1418942085

    @mock.patch("letsencrypt.storage.datetime")
    def test_time_interval_judgments(self, mock_datetime):
        """Test should_autodeploy() and should_autorenew() on the basis
        of expiry time windows."""
        test_cert = pkg_resources.resource_string(
            "letsencrypt.tests", "testdata/cert.pem")
        for kind in ALL_FOUR:
            where = self.test_rc.__getattribute__(kind)
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    "{0}12.pem".format(kind)), where)
            with open(where, "w") as f:
                f.write(kind)
            os.unlink(where)
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    "{0}11.pem".format(kind)), where)
            with open(where, "w") as f:
                f.write(kind)
        self.test_rc.update_all_links_to(12)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        self.test_rc.update_all_links_to(11)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)

        mock_datetime.timedelta = datetime.timedelta
        # 2014-12-13 12:00:00+00:00 (about 5 days prior to expiry)
        sometime = datetime.datetime.utcfromtimestamp(1418472000)
        mock_datetime.datetime.utcnow.return_value = sometime
        # Times that should result in autorenewal/autodeployment
        for when in ("2 months", "1 week"):
            self.test_rc.configuration["deploy_before_expiry"] = when
            self.test_rc.configuration["renew_before_expiry"] = when
            self.assertTrue(self.test_rc.should_autodeploy())
            self.assertTrue(self.test_rc.should_autorenew())
        # Times that should not
        for when in ("4 days", "2 days"):
            self.test_rc.configuration["deploy_before_expiry"] = when
            self.test_rc.configuration["renew_before_expiry"] = when
            self.assertFalse(self.test_rc.should_autodeploy())
            self.assertFalse(self.test_rc.should_autorenew())
        # 2009-05-01 12:00:00+00:00 (about 5 years prior to expiry)
        sometime = datetime.datetime.utcfromtimestamp(1241179200)
        mock_datetime.datetime.utcnow.return_value = sometime
        # Times that should result in autorenewal/autodeployment
        for when in ("7 years", "11 years 2 months"):
            self.test_rc.configuration["deploy_before_expiry"] = when
            self.test_rc.configuration["renew_before_expiry"] = when
            self.assertTrue(self.test_rc.should_autodeploy())
            self.assertTrue(self.test_rc.should_autorenew())
        # Times that should not
        for when in ("8 hours", "2 days", "40 days", "9 months"):
            self.test_rc.configuration["deploy_before_expiry"] = when
            self.test_rc.configuration["renew_before_expiry"] = when
            self.assertFalse(self.test_rc.should_autodeploy())
            self.assertFalse(self.test_rc.should_autorenew())
        # 2015-01-01 (after expiry has already happened, so all intervals
        #             should result in autorenewal/autodeployment)
        sometime = datetime.datetime.utcfromtimestamp(1420070400)
        mock_datetime.datetime.utcnow.return_value = sometime
        for when in ("0 seconds", "10 seconds", "10 minutes", "10 weeks",
                     "10 months", "10 years", "300 months"):
            self.test_rc.configuration["deploy_before_expiry"] = when
            self.test_rc.configuration["renew_before_expiry"] = when
            self.assertTrue(self.test_rc.should_autodeploy())
            self.assertTrue(self.test_rc.should_autorenew())

    def test_should_autodeploy(self):
        """Test should_autodeploy() on the basis of reasons other than
        expiry time window."""
        # pylint: disable=too-many-statements
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
                os.symlink(os.path.join("..", "..", "archive", "example.org",
                                        "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
        self.assertFalse(self.test_rc.should_autodeploy())

    @mock.patch("letsencrypt.storage.RenewableCert.ocsp_revoked")
    def test_should_autorenew(self, mock_ocsp):
        """Test should_autorenew on the basis of reasons other than
        expiry time window."""
        # pylint: disable=too-many-statements
        # Autorenewal turned off
        self.test_rc.configuration["autorenew"] = "0"
        self.assertFalse(self.test_rc.should_autorenew())
        self.test_rc.configuration["autorenew"] = "1"
        for kind in ALL_FOUR:
            where = self.test_rc.__getattribute__(kind)
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    "{0}12.pem".format(kind)), where)
            with open(where, "w") as f:
                f.write(kind)
        # Mandatory renewal on the basis of OCSP revocation
        mock_ocsp.return_value = True
        self.assertTrue(self.test_rc.should_autorenew())
        mock_ocsp.return_value = False

    def test_save_successor(self):
        for ver in range(1, 6):
            for kind in ALL_FOUR:
                where = self.test_rc.__getattribute__(kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org",
                                        "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
        self.test_rc.update_all_links_to(3)
        self.assertEqual(6, self.test_rc.save_successor(3, "new cert", None,
                                                        "new chain"))
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
        self.assertEqual(7, self.test_rc.save_successor(6, "again", None,
                                                        "newer chain"))
        self.assertEqual(8, self.test_rc.save_successor(7, "hello", None,
                                                        "other chain"))
        # All of the subsequent versions should link directly to the original
        # privkey.
        self.assertTrue(os.path.islink(self.test_rc.version("privkey", 6)))
        self.assertTrue(os.path.islink(self.test_rc.version("privkey", 7)))
        self.assertTrue(os.path.islink(self.test_rc.version("privkey", 8)))
        self.assertEqual(
            os.path.basename(os.readlink(self.test_rc.version("privkey", 6))),
            "privkey3.pem")
        self.assertEqual(
            os.path.basename(os.readlink(self.test_rc.version("privkey", 7))),
            "privkey3.pem")
        self.assertEqual(
            os.path.basename(os.readlink(self.test_rc.version("privkey", 8))),
            "privkey3.pem")
        for kind in ALL_FOUR:
            self.assertEqual(self.test_rc.available_versions(kind), range(1, 9))
            self.assertEqual(self.test_rc.current_version(kind), 3)
        # Test updating from latest version rather than old version
        self.test_rc.update_all_links_to(8)
        self.assertEqual(9, self.test_rc.save_successor(8, "last", None,
                                                        "attempt"))
        for kind in ALL_FOUR:
            self.assertEqual(self.test_rc.available_versions(kind),
                             range(1, 10))
            self.assertEqual(self.test_rc.current_version(kind), 8)
        with open(self.test_rc.version("fullchain", 9)) as f:
            self.assertEqual(f.read(), "last" + "attempt")
        # Test updating when providing a new privkey.  The key should
        # be saved in a new file rather than creating a new symlink.
        self.assertEqual(10, self.test_rc.save_successor(9, "with", "a",
                                                         "key"))
        self.assertTrue(os.path.exists(self.test_rc.version("privkey", 10)))
        self.assertFalse(os.path.islink(self.test_rc.version("privkey", 10)))

    def test_new_lineage(self):
        """Test for new_lineage() class method."""
        from letsencrypt import storage
        config_dir = self.defaults["renewal_configs_dir"]
        archive_dir = self.defaults["official_archive_dir"]
        live_dir = self.defaults["live_dir"]
        result = storage.RenewableCert.new_lineage("the-lineage.com", "cert",
                                                   "privkey", "chain", None,
                                                   self.defaults)
        # This consistency check tests most relevant properties about the
        # newly created cert lineage.
        self.assertTrue(result.consistent())
        self.assertTrue(os.path.exists(os.path.join(config_dir,
                                                    "the-lineage.com.conf")))
        with open(result.fullchain) as f:
            self.assertEqual(f.read(), "cert" + "chain")
        # Let's do it again and make sure it makes a different lineage
        result = storage.RenewableCert.new_lineage("the-lineage.com", "cert2",
                                                   "privkey2", "chain2", None,
                                                   self.defaults)
        self.assertTrue(os.path.exists(
            os.path.join(config_dir, "the-lineage.com-0001.conf")))
        # Now trigger the detection of already existing files
        os.mkdir(os.path.join(live_dir, "the-lineage.com-0002"))
        self.assertRaises(ValueError, storage.RenewableCert.new_lineage,
                          "the-lineage.com", "cert3", "privkey3", "chain3",
                          None, self.defaults)
        os.mkdir(os.path.join(archive_dir, "other-example.com"))
        self.assertRaises(ValueError, storage.RenewableCert.new_lineage,
                          "other-example.com", "cert4", "privkey4", "chain4",
                          None, self.defaults)
        # Make sure it can accept renewal parameters
        params = {"stuff": "properties of stuff", "great": "awesome"}
        result = storage.RenewableCert.new_lineage("the-lineage.com", "cert2",
                                                   "privkey2", "chain2",
                                                   params, self.defaults)
        # TODO: Conceivably we could test that the renewal parameters actually
        #       got saved

    def test_new_lineage_nonexistent_dirs(self):
        """Test that directories can be created if they don't exist."""
        from letsencrypt import storage
        config_dir = self.defaults["renewal_configs_dir"]
        archive_dir = self.defaults["official_archive_dir"]
        live_dir = self.defaults["live_dir"]
        shutil.rmtree(config_dir)
        shutil.rmtree(archive_dir)
        shutil.rmtree(live_dir)
        storage.RenewableCert.new_lineage("the-lineage.com", "cert2",
                                          "privkey2", "chain2",
                                          None, self.defaults)
        self.assertTrue(os.path.exists(
            os.path.join(config_dir, "the-lineage.com.conf")))
        self.assertTrue(os.path.exists(
            os.path.join(live_dir, "the-lineage.com", "privkey.pem")))
        self.assertTrue(os.path.exists(
            os.path.join(archive_dir, "the-lineage.com", "privkey1.pem")))

    @mock.patch("letsencrypt.storage.le_util.unique_lineage_name")
    def test_invalid_config_filename(self, mock_uln):
        from letsencrypt import storage
        mock_uln.return_value = "this_does_not_end_with_dot_conf", "yikes"
        self.assertRaises(ValueError, storage.RenewableCert.new_lineage,
                          "example.com", "cert", "privkey", "chain",
                          None, self.defaults)

    def test_bad_kind(self):
        self.assertRaises(ValueError, self.test_rc.current_target, "elephant")
        self.assertRaises(ValueError, self.test_rc.current_version, "elephant")
        self.assertRaises(ValueError, self.test_rc.version, "elephant", 17)
        self.assertRaises(ValueError, self.test_rc.available_versions,
                          "elephant")
        self.assertRaises(ValueError, self.test_rc.newest_available_version,
                          "elephant")
        self.assertRaises(ValueError, self.test_rc.update_link_to,
                          "elephant", 17)

    def test_ocsp_revoked(self):
        # XXX: This is currently hardcoded to False due to a lack of an
        #      OCSP server to test against.
        self.assertEqual(self.test_rc.ocsp_revoked(), False)

    def test_parse_time_interval(self):
        from letsencrypt import storage
        # XXX: I'm not sure if intervals related to years and months
        #      take account of the current date (if so, some of these
        #      may fail in the future, like in leap years or even in
        #      months of different lengths!)
        intended = {"": 0, "17 days": 17, "23": 23, "1 month": 31,
                    "7 weeks": 49, "1 year 1 day": 366, "1 year-1 day": 364,
                    "4 years": 1461}
        for time in intended:
            self.assertEqual(storage.parse_time_interval(time),
                             datetime.timedelta(intended[time]))

    @mock.patch("letsencrypt.renewer.plugins_disco")
    @mock.patch("letsencrypt.client.determine_account")
    @mock.patch("letsencrypt.client.Client")
    def test_renew(self, mock_c, mock_da, mock_pd):
        """Tests for renew()."""
        from letsencrypt import renewer

        test_cert = pkg_resources.resource_string(
            "letsencrypt.tests", "testdata/cert-san.pem")
        for kind in ALL_FOUR:
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    kind + "1.pem"),
                       self.test_rc.__getattribute__(kind))
        fill_with_sample_data(self.test_rc)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)

        # Fails because renewalparams are missing
        self.assertFalse(renewer.renew(self.test_rc, 1))
        self.test_rc.configfile["renewalparams"] = {"some": "stuff"}
        # Fails because there's no authenticator specified
        self.assertFalse(renewer.renew(self.test_rc, 1))
        self.test_rc.configfile["renewalparams"]["rsa_key_size"] = "2048"
        self.test_rc.configfile["renewalparams"]["server"] = "acme.example.com"
        self.test_rc.configfile["renewalparams"]["authenticator"] = "fake"
        mock_auth = mock.MagicMock()
        mock_pd.PluginsRegistry.find_all.return_value = {"apache": mock_auth}
        # Fails because "fake" != "apache"
        self.assertFalse(renewer.renew(self.test_rc, 1))
        self.test_rc.configfile["renewalparams"]["authenticator"] = "apache"
        mock_client = mock.MagicMock()
        mock_client.obtain_certificate.return_value = ("cert", "key", "chain")
        mock_c.return_value = mock_client
        self.assertEqual(2, renewer.renew(self.test_rc, 1))
        # TODO: We could also make several assertions about calls that should
        #       have been made to the mock functions here.
        self.assertEqual(mock_da.call_count, 1)
        mock_client.obtain_certificate.return_value = (None, None, None)
        # This should fail because the renewal itself appears to fail
        self.assertEqual(False, renewer.renew(self.test_rc, 1))


    @mock.patch("letsencrypt.renewer.notify")
    @mock.patch("letsencrypt.storage.RenewableCert")
    @mock.patch("letsencrypt.renewer.renew")
    def test_main(self, mock_renew, mock_rc, mock_notify):
        """Test for main() function."""
        from letsencrypt import renewer
        mock_rc_instance = mock.MagicMock()
        mock_rc_instance.should_autodeploy.return_value = True
        mock_rc_instance.should_autorenew.return_value = True
        mock_rc_instance.latest_common_version.return_value = 10
        mock_rc.return_value = mock_rc_instance
        with open(os.path.join(self.defaults["renewal_configs_dir"],
                               "README"), "w") as f:
            f.write("This is a README file to make sure that the renewer is")
            f.write("able to correctly ignore files that don't end in .conf.")
        with open(os.path.join(self.defaults["renewal_configs_dir"],
                               "example.org.conf"), "w") as f:
            # This isn't actually parsed in this test; we have a separate
            # test_initialization that tests the initialization, assuming
            # that configobj can correctly parse the config file.
            f.write("cert = cert.pem\nprivkey = privkey.pem\n")
            f.write("chain = chain.pem\nfullchain = fullchain.pem\n")
        with open(os.path.join(self.defaults["renewal_configs_dir"],
                               "example.com.conf"), "w") as f:
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

    def test_bad_config_file(self):
        from letsencrypt import renewer
        with open(os.path.join(self.defaults["renewal_configs_dir"],
                               "bad.conf"), "w") as f:
            f.write("incomplete = configfile\n")
        renewer.main(self.defaults)
        # The ValueError is caught inside and nothing happens.

if __name__ == "__main__":
    unittest.main()
