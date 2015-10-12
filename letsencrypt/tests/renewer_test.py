"""Tests for letsencrypt.renewer."""
import datetime
import os
import tempfile
import shutil
import unittest

import configobj
import mock
import pytz

from letsencrypt import configuration
from letsencrypt import errors
from letsencrypt.storage import ALL_FOUR

from letsencrypt.tests import test_util


CERT = test_util.load_cert('cert.pem')


def unlink_all(rc_object):
    """Unlink all four items associated with this RenewableCert."""
    for kind in ALL_FOUR:
        os.unlink(getattr(rc_object, kind))


def fill_with_sample_data(rc_object):
    """Put dummy data into all four files of this RenewableCert."""
    for kind in ALL_FOUR:
        with open(getattr(rc_object, kind), "w") as f:
            f.write(kind)


class BaseRenewableCertTest(unittest.TestCase):
    """Base class for setting up Renewable Cert tests.

    .. note:: It may be required to write out self.config for
    your test.  Check :class:`.cli_test.DuplicateCertTest` for an example.

    """
    def setUp(self):
        from letsencrypt import storage
        self.tempdir = tempfile.mkdtemp()

        self.cli_config = configuration.RenewerConfiguration(
            namespace=mock.MagicMock(
                config_dir=self.tempdir,
                work_dir=self.tempdir,
                logs_dir=self.tempdir,
                no_simple_http_tls=False,
            )
        )

        # TODO: maybe provide RenewerConfiguration.make_dirs?
        # TODO: main() should create those dirs, c.f. #902
        os.makedirs(os.path.join(self.tempdir, "live", "example.org"))
        os.makedirs(os.path.join(self.tempdir, "archive", "example.org"))
        os.makedirs(os.path.join(self.tempdir, "renewal"))

        config = configobj.ConfigObj()
        for kind in ALL_FOUR:
            config[kind] = os.path.join(self.tempdir, "live", "example.org",
                                        kind + ".pem")
        config.filename = os.path.join(self.tempdir, "renewal",
                                       "example.org.conf")
        self.config = config

        self.defaults = configobj.ConfigObj()
        self.test_rc = storage.RenewableCert(
            self.config, self.defaults, self.cli_config)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _write_out_ex_kinds(self):
        for kind in ALL_FOUR:
            where = getattr(self.test_rc, kind)
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    "{0}12.pem".format(kind)), where)
            with open(where, "w") as f:
                f.write(kind)
            os.unlink(where)
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    "{0}11.pem".format(kind)), where)
            with open(where, "w") as f:
                f.write(kind)


class RenewableCertTests(BaseRenewableCertTest):
    # pylint: disable=too-many-public-methods
    """Tests for letsencrypt.renewer.*."""

    def test_initialization(self):
        self.assertEqual(self.test_rc.lineagename, "example.org")
        for kind in ALL_FOUR:
            self.assertEqual(
                getattr(self.test_rc, kind), os.path.join(
                    self.tempdir, "live", "example.org", kind + ".pem"))

    def test_renewal_bad_config(self):
        """Test that the RenewableCert constructor will complain if
        the renewal configuration file doesn't end in ".conf" or if it
        isn't a ConfigObj."""
        from letsencrypt import storage
        defaults = configobj.ConfigObj()
        config = configobj.ConfigObj()
        # These files don't exist and aren't created here; the point of the test
        # is to confirm that the constructor rejects them outright because of
        # the configfile's name.
        for kind in ALL_FOUR:
            config["cert"] = "nonexistent_" + kind + ".pem"
        config.filename = "nonexistent_sillyfile"
        self.assertRaises(
            errors.CertStorageError, storage.RenewableCert, config, defaults)
        self.assertRaises(TypeError, storage.RenewableCert, "fun", defaults)

    def test_renewal_incomplete_config(self):
        """Test that the RenewableCert constructor will complain if
        the renewal configuration file is missing a required file element."""
        from letsencrypt import storage
        defaults = configobj.ConfigObj()
        config = configobj.ConfigObj()
        config["cert"] = "imaginary_cert.pem"
        # Here the required privkey is missing.
        config["chain"] = "imaginary_chain.pem"
        config["fullchain"] = "imaginary_fullchain.pem"
        config.filename = "imaginary_config.conf"
        self.assertRaises(
            errors.CertStorageError, storage.RenewableCert, config, defaults)

    def test_consistent(self):
        # pylint: disable=too-many-statements,protected-access
        oldcert = self.test_rc.cert
        self.test_rc.cert = "relative/path"
        # Absolute path for item requirement
        self.assertFalse(self.test_rc._consistent())
        self.test_rc.cert = oldcert
        # Items must exist requirement
        self.assertFalse(self.test_rc._consistent())
        # Items must be symlinks requirements
        fill_with_sample_data(self.test_rc)
        self.assertFalse(self.test_rc._consistent())
        unlink_all(self.test_rc)
        # Items must point to desired place if they are relative
        for kind in ALL_FOUR:
            os.symlink(os.path.join("..", kind + "17.pem"),
                       getattr(self.test_rc, kind))
        self.assertFalse(self.test_rc._consistent())
        unlink_all(self.test_rc)
        # Items must point to desired place if they are absolute
        for kind in ALL_FOUR:
            os.symlink(os.path.join(self.tempdir, kind + "17.pem"),
                       getattr(self.test_rc, kind))
        self.assertFalse(self.test_rc._consistent())
        unlink_all(self.test_rc)
        # Items must point to things that exist
        for kind in ALL_FOUR:
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    kind + "17.pem"),
                       getattr(self.test_rc, kind))
        self.assertFalse(self.test_rc._consistent())
        # This version should work
        fill_with_sample_data(self.test_rc)
        self.assertTrue(self.test_rc._consistent())
        # Items must point to things that follow the naming convention
        os.unlink(self.test_rc.fullchain)
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "fullchain_17.pem"), self.test_rc.fullchain)
        with open(self.test_rc.fullchain, "w") as f:
            f.write("wrongly-named fullchain")
        self.assertFalse(self.test_rc._consistent())

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
        for ver in xrange(1, 6):
            for kind in ALL_FOUR:
                where = getattr(self.test_rc, kind)
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
            where = getattr(self.test_rc, kind)
            if os.path.islink(where):
                os.unlink(where)
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    "{0}{1}.pem".format(kind, ver)), where)
            with open(where, "w") as f:
                f.write(kind)
        self.assertEqual(self.test_rc.latest_common_version(), 17)
        self.assertEqual(self.test_rc.next_free_version(), 18)

    def test_update_link_to(self):
        for ver in xrange(1, 6):
            for kind in ALL_FOUR:
                where = getattr(self.test_rc, kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org",
                                        "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
                self.assertEqual(ver, self.test_rc.current_version(kind))
        # pylint: disable=protected-access
        self.test_rc._update_link_to("cert", 3)
        self.test_rc._update_link_to("privkey", 2)
        self.assertEqual(3, self.test_rc.current_version("cert"))
        self.assertEqual(2, self.test_rc.current_version("privkey"))
        self.assertEqual(5, self.test_rc.current_version("chain"))
        self.assertEqual(5, self.test_rc.current_version("fullchain"))
        # Currently we are allowed to update to a version that doesn't exist
        self.test_rc._update_link_to("chain", 3000)
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
        for ver in xrange(1, 6):
            for kind in ALL_FOUR:
                where = getattr(self.test_rc, kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org",
                                        "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
                self.assertEqual(ver, self.test_rc.current_version(kind))
        self.assertEqual(self.test_rc.latest_common_version(), 5)
        for ver in xrange(1, 6):
            self.test_rc.update_all_links_to(ver)
            for kind in ALL_FOUR:
                self.assertEqual(ver, self.test_rc.current_version(kind))
            self.assertEqual(self.test_rc.latest_common_version(), 5)

    def test_has_pending_deployment(self):
        for ver in xrange(1, 6):
            for kind in ALL_FOUR:
                where = getattr(self.test_rc, kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org",
                                        "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
                self.assertEqual(ver, self.test_rc.current_version(kind))
        for ver in xrange(1, 6):
            self.test_rc.update_all_links_to(ver)
            for kind in ALL_FOUR:
                self.assertEqual(ver, self.test_rc.current_version(kind))
            if ver < 5:
                self.assertTrue(self.test_rc.has_pending_deployment())
            else:
                self.assertFalse(self.test_rc.has_pending_deployment())

    def test_names(self):
        # Trying the current version
        test_cert = test_util.load_vector("cert-san.pem")
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "cert12.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        self.assertEqual(self.test_rc.names(),
                         ["example.com", "www.example.com"])

        # Trying a non-current version
        test_cert = test_util.load_vector("cert.pem")
        os.unlink(self.test_rc.cert)
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "cert15.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        self.assertEqual(self.test_rc.names(12),
                         ["example.com", "www.example.com"])

    def _test_notafterbefore(self, function, timestamp):
        test_cert = test_util.load_vector("cert.pem")
        os.symlink(os.path.join("..", "..", "archive", "example.org",
                                "cert12.pem"), self.test_rc.cert)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        desired_time = datetime.datetime.utcfromtimestamp(timestamp)
        desired_time = desired_time.replace(tzinfo=pytz.UTC)
        for result in (function(), function(12)):
            self.assertEqual(result, desired_time)
            self.assertEqual(result.utcoffset(), datetime.timedelta(0))

    def test_notbefore(self):
        self._test_notafterbefore(self.test_rc.notbefore, 1418337285)
        # 2014-12-11 22:34:45+00:00 = Unix time 1418337285

    def test_notafter(self):
        self._test_notafterbefore(self.test_rc.notafter, 1418942085)
        # 2014-12-18 22:34:45+00:00 = Unix time 1418942085

    @mock.patch("letsencrypt.storage.datetime")
    def test_time_interval_judgments(self, mock_datetime):
        """Test should_autodeploy() and should_autorenew() on the basis
        of expiry time windows."""
        test_cert = test_util.load_vector("cert.pem")
        self._write_out_ex_kinds()

        self.test_rc.update_all_links_to(12)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)
        self.test_rc.update_all_links_to(11)
        with open(self.test_rc.cert, "w") as f:
            f.write(test_cert)

        mock_datetime.timedelta = datetime.timedelta

        for (current_time, interval, result) in [
                # 2014-12-13 12:00:00+00:00 (about 5 days prior to expiry)
                # Times that should result in autorenewal/autodeployment
                (1418472000, "2 months", True), (1418472000, "1 week", True),
                # Times that should not
                (1418472000, "4 days", False), (1418472000, "2 days", False),
                # 2009-05-01 12:00:00+00:00 (about 5 years prior to expiry)
                # Times that should result in autorenewal/autodeployment
                (1241179200, "7 years", True),
                (1241179200, "11 years 2 months", True),
                # Times that should not
                (1241179200, "8 hours", False), (1241179200, "2 days", False),
                (1241179200, "40 days", False), (1241179200, "9 months", False),
                # 2015-01-01 (after expiry has already happened, so all
                #            intervals should cause autorenewal/autodeployment)
                (1420070400, "0 seconds", True),
                (1420070400, "10 seconds", True),
                (1420070400, "10 minutes", True),
                (1420070400, "10 weeks", True), (1420070400, "10 months", True),
                (1420070400, "10 years", True), (1420070400, "99 months", True),
        ]:
            sometime = datetime.datetime.utcfromtimestamp(current_time)
            mock_datetime.datetime.utcnow.return_value = sometime
            self.test_rc.configuration["deploy_before_expiry"] = interval
            self.test_rc.configuration["renew_before_expiry"] = interval
            self.assertEqual(self.test_rc.should_autodeploy(), result)
            self.assertEqual(self.test_rc.should_autorenew(), result)

    def test_autodeployment_is_enabled(self):
        self.assertTrue(self.test_rc.autodeployment_is_enabled())
        self.test_rc.configuration["autodeploy"] = "1"
        self.assertTrue(self.test_rc.autodeployment_is_enabled())

        self.test_rc.configuration["autodeploy"] = "0"
        self.assertFalse(self.test_rc.autodeployment_is_enabled())

    def test_should_autodeploy(self):
        """Test should_autodeploy() on the basis of reasons other than
        expiry time window."""
        # pylint: disable=too-many-statements
        # Autodeployment turned off
        self.test_rc.configuration["autodeploy"] = "0"
        self.assertFalse(self.test_rc.should_autodeploy())
        self.test_rc.configuration["autodeploy"] = "1"
        # No pending deployment
        for ver in xrange(1, 6):
            for kind in ALL_FOUR:
                where = getattr(self.test_rc, kind)
                if os.path.islink(where):
                    os.unlink(where)
                os.symlink(os.path.join("..", "..", "archive", "example.org",
                                        "{0}{1}.pem".format(kind, ver)), where)
                with open(where, "w") as f:
                    f.write(kind)
        self.assertFalse(self.test_rc.should_autodeploy())

    def test_autorenewal_is_enabled(self):
        self.assertTrue(self.test_rc.autorenewal_is_enabled())
        self.test_rc.configuration["autorenew"] = "1"
        self.assertTrue(self.test_rc.autorenewal_is_enabled())

        self.test_rc.configuration["autorenew"] = "0"
        self.assertFalse(self.test_rc.autorenewal_is_enabled())

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
            where = getattr(self.test_rc, kind)
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    "{0}12.pem".format(kind)), where)
            with open(where, "w") as f:
                f.write(kind)
        # Mandatory renewal on the basis of OCSP revocation
        mock_ocsp.return_value = True
        self.assertTrue(self.test_rc.should_autorenew())
        mock_ocsp.return_value = False

    def test_save_successor(self):
        for ver in xrange(1, 6):
            for kind in ALL_FOUR:
                where = getattr(self.test_rc, kind)
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
        for i in (6, 7, 8):
            self.assertTrue(os.path.islink(self.test_rc.version("privkey", i)))
            self.assertEqual("privkey3.pem", os.path.basename(os.readlink(
                self.test_rc.version("privkey", i))))

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
        result = storage.RenewableCert.new_lineage(
            "the-lineage.com", "cert", "privkey", "chain", None,
            self.defaults, self.cli_config)
        # This consistency check tests most relevant properties about the
        # newly created cert lineage.
        # pylint: disable=protected-access
        self.assertTrue(result._consistent())
        self.assertTrue(os.path.exists(os.path.join(
            self.cli_config.renewal_configs_dir, "the-lineage.com.conf")))
        with open(result.fullchain) as f:
            self.assertEqual(f.read(), "cert" + "chain")
        # Let's do it again and make sure it makes a different lineage
        result = storage.RenewableCert.new_lineage(
            "the-lineage.com", "cert2", "privkey2", "chain2", None,
            self.defaults, self.cli_config)
        self.assertTrue(os.path.exists(os.path.join(
            self.cli_config.renewal_configs_dir, "the-lineage.com-0001.conf")))
        # Now trigger the detection of already existing files
        os.mkdir(os.path.join(
            self.cli_config.live_dir, "the-lineage.com-0002"))
        self.assertRaises(errors.CertStorageError,
                          storage.RenewableCert.new_lineage,
                          "the-lineage.com", "cert3", "privkey3", "chain3",
                          None, self.defaults, self.cli_config)
        os.mkdir(os.path.join(self.cli_config.archive_dir, "other-example.com"))
        self.assertRaises(errors.CertStorageError,
                          storage.RenewableCert.new_lineage,
                          "other-example.com", "cert4", "privkey4", "chain4",
                          None, self.defaults, self.cli_config)
        # Make sure it can accept renewal parameters
        params = {"stuff": "properties of stuff", "great": "awesome"}
        result = storage.RenewableCert.new_lineage(
            "the-lineage.com", "cert2", "privkey2", "chain2",
            params, self.defaults, self.cli_config)
        # TODO: Conceivably we could test that the renewal parameters actually
        #       got saved

    def test_new_lineage_nonexistent_dirs(self):
        """Test that directories can be created if they don't exist."""
        from letsencrypt import storage
        shutil.rmtree(self.cli_config.renewal_configs_dir)
        shutil.rmtree(self.cli_config.archive_dir)
        shutil.rmtree(self.cli_config.live_dir)

        storage.RenewableCert.new_lineage(
            "the-lineage.com", "cert2", "privkey2", "chain2",
            None, self.defaults, self.cli_config)
        self.assertTrue(os.path.exists(
            os.path.join(
                self.cli_config.renewal_configs_dir, "the-lineage.com.conf")))
        self.assertTrue(os.path.exists(os.path.join(
            self.cli_config.live_dir, "the-lineage.com", "privkey.pem")))
        self.assertTrue(os.path.exists(os.path.join(
            self.cli_config.archive_dir, "the-lineage.com", "privkey1.pem")))

    @mock.patch("letsencrypt.storage.le_util.unique_lineage_name")
    def test_invalid_config_filename(self, mock_uln):
        from letsencrypt import storage
        mock_uln.return_value = "this_does_not_end_with_dot_conf", "yikes"
        self.assertRaises(errors.CertStorageError,
                          storage.RenewableCert.new_lineage,
                          "example.com", "cert", "privkey", "chain",
                          None, self.defaults, self.cli_config)

    def test_bad_kind(self):
        self.assertRaises(
            errors.CertStorageError, self.test_rc.current_target, "elephant")
        self.assertRaises(
            errors.CertStorageError, self.test_rc.current_version, "elephant")
        self.assertRaises(
            errors.CertStorageError, self.test_rc.version, "elephant", 17)
        self.assertRaises(
            errors.CertStorageError,
            self.test_rc.available_versions, "elephant")
        self.assertRaises(
            errors.CertStorageError,
            self.test_rc.newest_available_version, "elephant")
        # pylint: disable=protected-access
        self.assertRaises(
            errors.CertStorageError,
            self.test_rc._update_link_to, "elephant", 17)

    def test_ocsp_revoked(self):
        # XXX: This is currently hardcoded to False due to a lack of an
        #      OCSP server to test against.
        self.assertFalse(self.test_rc.ocsp_revoked())

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
    @mock.patch("letsencrypt.account.AccountFileStorage")
    @mock.patch("letsencrypt.client.Client")
    def test_renew(self, mock_c, mock_acc_storage, mock_pd):
        from letsencrypt import renewer

        test_cert = test_util.load_vector("cert-san.pem")
        for kind in ALL_FOUR:
            os.symlink(os.path.join("..", "..", "archive", "example.org",
                                    kind + "1.pem"),
                       getattr(self.test_rc, kind))
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
        self.test_rc.configfile["renewalparams"]["dvsni_port"] = "4430"
        self.test_rc.configfile["renewalparams"]["simple_http_port"] = "1234"
        self.test_rc.configfile["renewalparams"]["account"] = "abcde"
        mock_auth = mock.MagicMock()
        mock_pd.PluginsRegistry.find_all.return_value = {"apache": mock_auth}
        # Fails because "fake" != "apache"
        self.assertFalse(renewer.renew(self.test_rc, 1))
        self.test_rc.configfile["renewalparams"]["authenticator"] = "apache"
        mock_client = mock.MagicMock()
        # pylint: disable=star-args
        mock_client.obtain_certificate.return_value = (
            mock.MagicMock(body=CERT), [CERT], mock.Mock(pem="key"),
            mock.sentinel.csr)
        mock_c.return_value = mock_client
        self.assertEqual(2, renewer.renew(self.test_rc, 1))
        # TODO: We could also make several assertions about calls that should
        #       have been made to the mock functions here.
        mock_acc_storage().load.assert_called_once_with(account_id="abcde")
        mock_client.obtain_certificate.return_value = (
            mock.sentinel.certr, [], mock.sentinel.key, mock.sentinel.csr)
        # This should fail because the renewal itself appears to fail
        self.assertFalse(renewer.renew(self.test_rc, 1))

    def _common_cli_args(self):
        return [
            "--config-dir", self.cli_config.config_dir,
            "--work-dir", self.cli_config.work_dir,
            "--logs-dir", self.cli_config.logs_dir,
        ]

    @mock.patch("letsencrypt.renewer.notify")
    @mock.patch("letsencrypt.storage.RenewableCert")
    @mock.patch("letsencrypt.renewer.renew")
    def test_main(self, mock_renew, mock_rc, mock_notify):
        from letsencrypt import renewer
        mock_rc_instance = mock.MagicMock()
        mock_rc_instance.should_autodeploy.return_value = True
        mock_rc_instance.should_autorenew.return_value = True
        mock_rc_instance.latest_common_version.return_value = 10
        mock_rc.return_value = mock_rc_instance
        with open(os.path.join(self.cli_config.renewal_configs_dir,
                               "README"), "w") as f:
            f.write("This is a README file to make sure that the renewer is")
            f.write("able to correctly ignore files that don't end in .conf.")
        with open(os.path.join(self.cli_config.renewal_configs_dir,
                               "example.org.conf"), "w") as f:
            # This isn't actually parsed in this test; we have a separate
            # test_initialization that tests the initialization, assuming
            # that configobj can correctly parse the config file.
            f.write("cert = cert.pem\nprivkey = privkey.pem\n")
            f.write("chain = chain.pem\nfullchain = fullchain.pem\n")
        with open(os.path.join(self.cli_config.renewal_configs_dir,
                               "example.com.conf"), "w") as f:
            f.write("cert = cert.pem\nprivkey = privkey.pem\n")
            f.write("chain = chain.pem\nfullchain = fullchain.pem\n")
        renewer.main(self.defaults, cli_args=self._common_cli_args())
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
        renewer.main(self.defaults, cli_args=self._common_cli_args())
        self.assertEqual(mock_rc.call_count, 4)
        self.assertEqual(mock_happy_instance.update_all_links_to.call_count, 0)
        self.assertEqual(mock_notify.notify.call_count, 4)
        self.assertEqual(mock_renew.call_count, 2)

    def test_bad_config_file(self):
        from letsencrypt import renewer
        with open(os.path.join(self.cli_config.renewal_configs_dir,
                               "bad.conf"), "w") as f:
            f.write("incomplete = configfile\n")
        renewer.main(self.defaults, cli_args=self._common_cli_args())
        # The errors.CertStorageError is caught inside and nothing happens.


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
