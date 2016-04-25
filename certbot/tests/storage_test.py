"""Tests for certbot.storage."""
# pylint disable=protected-access
import datetime
import os
import shutil
import tempfile
import unittest

import configobj
import mock
import pytz

from certbot import configuration
from certbot import errors
from certbot.storage import ALL_FOUR

from certbot.tests import test_util


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
        from certbot import storage
        self.tempdir = tempfile.mkdtemp()

        self.cli_config = configuration.RenewerConfiguration(
            namespace=mock.MagicMock(
                config_dir=self.tempdir,
                work_dir=self.tempdir,
                logs_dir=self.tempdir,
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
        config.write()
        self.config = config

        # We also create a file that isn't a renewal config in the same
        # location to test that logic that reads in all-and-only renewal
        # configs will ignore it and NOT attempt to parse it.
        junk = open(os.path.join(self.tempdir, "renewal", "IGNORE.THIS"), "w")
        junk.write("This file should be ignored!")
        junk.close()

        self.defaults = configobj.ConfigObj()

        with mock.patch("certbot.storage.RenewableCert._check_symlinks") as check:
            check.return_value = True
            self.test_rc = storage.RenewableCert(config.filename, self.cli_config)

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
    """Tests for certbot.storage."""

    def test_initialization(self):
        self.assertEqual(self.test_rc.lineagename, "example.org")
        for kind in ALL_FOUR:
            self.assertEqual(
                getattr(self.test_rc, kind), os.path.join(
                    self.tempdir, "live", "example.org", kind + ".pem"))

    def test_renewal_bad_config(self):
        """Test that the RenewableCert constructor will complain if
        the renewal configuration file doesn't end in ".conf"

        """
        from certbot import storage
        broken = os.path.join(self.tempdir, "broken.conf")
        with open(broken, "w") as f:
            f.write("[No closing bracket for you!")
        self.assertRaises(errors.CertStorageError, storage.RenewableCert,
                          broken, self.cli_config)
        os.unlink(broken)
        self.assertRaises(errors.CertStorageError, storage.RenewableCert,
                          "fun", self.cli_config)

    def test_renewal_incomplete_config(self):
        """Test that the RenewableCert constructor will complain if
        the renewal configuration file is missing a required file element."""
        from certbot import storage
        config = configobj.ConfigObj()
        config["cert"] = "imaginary_cert.pem"
        # Here the required privkey is missing.
        config["chain"] = "imaginary_chain.pem"
        config["fullchain"] = "imaginary_fullchain.pem"
        config.filename = os.path.join(self.tempdir, "imaginary_config.conf")
        config.write()
        self.assertRaises(errors.CertStorageError, storage.RenewableCert,
                          config.filename, self.cli_config)

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

    def test_update_all_links_to_success(self):
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

    def test_update_all_links_to_partial_failure(self):
        def unlink_or_raise(path, real_unlink=os.unlink):
            # pylint: disable=missing-docstring
            basename = os.path.basename(path)
            if "fullchain" in basename and basename.startswith("prev"):
                raise ValueError
            else:
                real_unlink(path)

        self._write_out_ex_kinds()
        with mock.patch("certbot.storage.os.unlink") as mock_unlink:
            mock_unlink.side_effect = unlink_or_raise
            self.assertRaises(ValueError, self.test_rc.update_all_links_to, 12)

        for kind in ALL_FOUR:
            self.assertEqual(self.test_rc.current_version(kind), 12)

    def test_update_all_links_to_full_failure(self):
        def unlink_or_raise(path, real_unlink=os.unlink):
            # pylint: disable=missing-docstring
            if "fullchain" in os.path.basename(path):
                raise ValueError
            else:
                real_unlink(path)

        self._write_out_ex_kinds()
        with mock.patch("certbot.storage.os.unlink") as mock_unlink:
            mock_unlink.side_effect = unlink_or_raise
            self.assertRaises(ValueError, self.test_rc.update_all_links_to, 12)

        for kind in ALL_FOUR:
            self.assertEqual(self.test_rc.current_version(kind), 11)

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

        # Trying missing cert
        os.unlink(self.test_rc.cert)
        self.assertRaises(errors.CertStorageError, self.test_rc.names)

    @mock.patch("certbot.storage.datetime")
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

    @mock.patch("certbot.storage.RenewableCert.ocsp_revoked")
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

    @mock.patch("certbot.storage.relevant_values")
    def test_save_successor(self, mock_rv):
        # Mock relevant_values() to claim that all values are relevant here
        # (to avoid instantiating parser)
        mock_rv.side_effect = lambda x: x

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
        self.assertEqual(
            6, self.test_rc.save_successor(3, "new cert", None,
                                           "new chain", self.cli_config))
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
        self.assertEqual(
            7, self.test_rc.save_successor(6, "again", None,
                                           "newer chain", self.cli_config))
        self.assertEqual(
            8, self.test_rc.save_successor(7, "hello", None,
                                           "other chain", self.cli_config))
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
        self.assertEqual(
            9, self.test_rc.save_successor(8, "last", None,
                                           "attempt", self.cli_config))
        for kind in ALL_FOUR:
            self.assertEqual(self.test_rc.available_versions(kind),
                             range(1, 10))
            self.assertEqual(self.test_rc.current_version(kind), 8)
        with open(self.test_rc.version("fullchain", 9)) as f:
            self.assertEqual(f.read(), "last" + "attempt")
        temp_config_file = os.path.join(self.cli_config.renewal_configs_dir,
                                        self.test_rc.lineagename) + ".conf.new"
        with open(temp_config_file, "w") as f:
            f.write("We previously crashed while writing me :(")
        # Test updating when providing a new privkey.  The key should
        # be saved in a new file rather than creating a new symlink.
        self.assertEqual(
            10, self.test_rc.save_successor(9, "with", "a",
                                            "key", self.cli_config))
        self.assertTrue(os.path.exists(self.test_rc.version("privkey", 10)))
        self.assertFalse(os.path.islink(self.test_rc.version("privkey", 10)))
        self.assertFalse(os.path.exists(temp_config_file))

    @mock.patch("certbot.cli.helpful_parser")
    def test_relevant_values(self, mock_parser):
        """Test that relevant_values() can reject an irrelevant value."""
        # pylint: disable=protected-access
        from certbot import storage
        mock_parser.verb = "certonly"
        mock_parser.args = ["--standalone"]
        mock_action = mock.Mock(dest="rsa_key_size", default=2048)
        mock_parser.parser._actions = [mock_action]
        self.assertEqual(storage.relevant_values({"hello": "there"}), {})

    @mock.patch("certbot.cli.helpful_parser")
    def test_relevant_values_default(self, mock_parser):
        """Test that relevant_values() can reject a default value."""
        # pylint: disable=protected-access
        from certbot import storage
        mock_parser.verb = "certonly"
        mock_parser.args = ["--standalone"]
        mock_action = mock.Mock(dest="rsa_key_size", default=2048)
        mock_parser.parser._actions = [mock_action]
        self.assertEqual(storage.relevant_values({"rsa_key_size": 2048}), {})

    @mock.patch("certbot.cli.helpful_parser")
    def test_relevant_values_nondefault(self, mock_parser):
        """Test that relevant_values() can retain a non-default value."""
        # pylint: disable=protected-access
        from certbot import storage
        mock_parser.verb = "certonly"
        mock_parser.args = ["--standalone"]
        mock_action = mock.Mock(dest="rsa_key_size", default=2048)
        mock_parser.parser._actions = [mock_action]
        self.assertEqual(storage.relevant_values({"rsa_key_size": 12}),
                         {"rsa_key_size": 12})

    @mock.patch("certbot.storage.relevant_values")
    def test_new_lineage(self, mock_rv):
        """Test for new_lineage() class method."""
        # Mock relevant_values to say everything is relevant here (so we
        # don't have to mock the parser to help it decide!)
        mock_rv.side_effect = lambda x: x

        from certbot import storage
        result = storage.RenewableCert.new_lineage(
            "the-lineage.com", "cert", "privkey", "chain", self.cli_config)
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
            "the-lineage.com", "cert2", "privkey2", "chain2", self.cli_config)
        self.assertTrue(os.path.exists(os.path.join(
            self.cli_config.renewal_configs_dir, "the-lineage.com-0001.conf")))
        # Now trigger the detection of already existing files
        os.mkdir(os.path.join(
            self.cli_config.live_dir, "the-lineage.com-0002"))
        self.assertRaises(errors.CertStorageError,
                          storage.RenewableCert.new_lineage, "the-lineage.com",
                          "cert3", "privkey3", "chain3", self.cli_config)
        os.mkdir(os.path.join(self.cli_config.archive_dir, "other-example.com"))
        self.assertRaises(errors.CertStorageError,
                          storage.RenewableCert.new_lineage,
                          "other-example.com", "cert4",
                          "privkey4", "chain4", self.cli_config)
        # Make sure it can accept renewal parameters
        result = storage.RenewableCert.new_lineage(
            "the-lineage.com", "cert2", "privkey2", "chain2", self.cli_config)
        # TODO: Conceivably we could test that the renewal parameters actually
        #       got saved

    @mock.patch("certbot.storage.relevant_values")
    def test_new_lineage_nonexistent_dirs(self, mock_rv):
        """Test that directories can be created if they don't exist."""
        # Mock relevant_values to say everything is relevant here (so we
        # don't have to mock the parser to help it decide!)
        mock_rv.side_effect = lambda x: x

        from certbot import storage
        shutil.rmtree(self.cli_config.renewal_configs_dir)
        shutil.rmtree(self.cli_config.archive_dir)
        shutil.rmtree(self.cli_config.live_dir)

        storage.RenewableCert.new_lineage(
            "the-lineage.com", "cert2", "privkey2", "chain2", self.cli_config)
        self.assertTrue(os.path.exists(
            os.path.join(
                self.cli_config.renewal_configs_dir, "the-lineage.com.conf")))
        self.assertTrue(os.path.exists(os.path.join(
            self.cli_config.live_dir, "the-lineage.com", "privkey.pem")))
        self.assertTrue(os.path.exists(os.path.join(
            self.cli_config.archive_dir, "the-lineage.com", "privkey1.pem")))

    @mock.patch("certbot.storage.le_util.unique_lineage_name")
    def test_invalid_config_filename(self, mock_uln):
        from certbot import storage
        mock_uln.return_value = "this_does_not_end_with_dot_conf", "yikes"
        self.assertRaises(errors.CertStorageError,
                          storage.RenewableCert.new_lineage, "example.com",
                          "cert", "privkey", "chain", self.cli_config)

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

    def test_add_time_interval(self):
        from certbot import storage

        # this month has 30 days, and the next year is a leap year
        time_1 = pytz.UTC.fromutc(datetime.datetime(2003, 11, 20, 11, 59, 21))

        # this month has 31 days, and the next year is not a leap year
        time_2 = pytz.UTC.fromutc(datetime.datetime(2012, 10, 18, 21, 31, 16))

        # in different time zone (GMT+8)
        time_3 = pytz.timezone('Asia/Shanghai').fromutc(
            datetime.datetime(2015, 10, 26, 22, 25, 41))

        intended = {
            (time_1, ""): time_1,
            (time_2, ""): time_2,
            (time_3, ""): time_3,
            (time_1, "17 days"): time_1 + datetime.timedelta(17),
            (time_2, "17 days"): time_2 + datetime.timedelta(17),
            (time_1, "30"): time_1 + datetime.timedelta(30),
            (time_2, "30"): time_2 + datetime.timedelta(30),
            (time_1, "7 weeks"): time_1 + datetime.timedelta(49),
            (time_2, "7 weeks"): time_2 + datetime.timedelta(49),
            # 1 month is always 30 days, no matter which month it is
            (time_1, "1 month"): time_1 + datetime.timedelta(30),
            (time_2, "1 month"): time_2 + datetime.timedelta(31),
            # 1 year could be 365 or 366 days, depends on the year
            (time_1, "1 year"): time_1 + datetime.timedelta(366),
            (time_2, "1 year"): time_2 + datetime.timedelta(365),
            (time_1, "1 year 1 day"): time_1 + datetime.timedelta(367),
            (time_2, "1 year 1 day"): time_2 + datetime.timedelta(366),
            (time_1, "1 year-1 day"): time_1 + datetime.timedelta(365),
            (time_2, "1 year-1 day"): time_2 + datetime.timedelta(364),
            (time_1, "4 years"): time_1 + datetime.timedelta(1461),
            (time_2, "4 years"): time_2 + datetime.timedelta(1461),
        }

        for parameters, excepted in intended.items():
            base_time, interval = parameters
            self.assertEqual(storage.add_time_interval(base_time, interval),
                             excepted)

    def test_missing_cert(self):
        from certbot import storage
        self.assertRaises(errors.CertStorageError,
                          storage.RenewableCert,
                          self.config.filename, self.cli_config)
        os.symlink("missing", self.config[ALL_FOUR[0]])
        self.assertRaises(errors.CertStorageError,
                          storage.RenewableCert,
                          self.config.filename, self.cli_config)

    def test_write_renewal_config(self):
        # Mostly tested by the process of creating and updating lineages,
        # but we can test that this successfully creates files, removes
        # unneeded items, and preserves comments.
        temp = os.path.join(self.tempdir, "sample-file")
        temp2 = os.path.join(self.tempdir, "sample-file.new")
        with open(temp, "w") as f:
            f.write("[renewalparams]\nuseful = value # A useful value\n"
                    "useless = value # Not needed\n")
        target = {}
        for x in ALL_FOUR:
            target[x] = "somewhere"
        relevant_data = {"useful": "new_value"}
        from certbot import storage
        storage.write_renewal_config(temp, temp2, target, relevant_data)
        with open(temp2, "r") as f:
            content = f.read()
        # useful value was updated
        assert "useful = new_value" in content
        # associated comment was preserved
        assert "A useful value" in content
        # useless value was deleted
        assert "useless" not in content

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
