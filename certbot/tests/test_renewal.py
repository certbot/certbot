import os
import mock
import shutil
import unittest
import tempfile

from certbot import configuration
from certbot import renewal
from certbot import storage
from certbot import constants

from certbot.tests import test_util

class RenewalTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.config_dir = os.path.join(self.tmp_dir, 'config')

    def _make_lineage(self, testfile):
        """Creates a lineage defined by testfile.

        This creates the archive, live, and renewal directories if
        necessary and creates a simple lineage.

        :param str testfile: configuration file to base the lineage on

        :returns: path to the renewal conf file for the created lineage
        :rtype: str

        """
        lineage_name = testfile[:-len('.conf')]

        conf_dir = os.path.join(
            self.config_dir, constants.RENEWAL_CONFIGS_DIR)
        archive_dir = os.path.join(
            self.config_dir, constants.ARCHIVE_DIR, lineage_name)
        live_dir = os.path.join(
            self.config_dir, constants.LIVE_DIR, lineage_name)

        for directory in (archive_dir, conf_dir, live_dir,):
            if not os.path.exists(directory):
                os.makedirs(directory)

        sample_archive = test_util.vector_path('sample-archive')
        for kind in os.listdir(sample_archive):
            shutil.copyfile(os.path.join(sample_archive, kind),
                            os.path.join(archive_dir, kind))

        for kind in storage.ALL_FOUR:
            os.symlink(os.path.join(archive_dir, '{0}1.pem'.format(kind)),
                       os.path.join(live_dir, '{0}.pem'.format(kind)))

        conf_path = os.path.join(self.config_dir, conf_dir, testfile)
        with open(test_util.vector_path(testfile)) as src:
            with open(conf_path, 'w') as dst:
                dst.writelines(
                    line.replace('MAGICDIR', self.config_dir) for line in src)

        return conf_path


    @mock.patch("certbot.cli.set_by_cli")
    def test_ancient_webroot_renewal_conf(self, mock_set_by_cli):
        mock_set_by_cli.return_value = False
        rc_path = self._make_lineage('sample-renewal-ancient.conf')
        args = mock.MagicMock(account=None, email=None, webroot_path=None)
        config = configuration.NamespaceConfig(args)
        lineage = storage.RenewableCert(
                rc_path, configuration.RenewerConfiguration(config))
        renewalparams = lineage.configuration["renewalparams"]
        # pylint: disable=protected-access
        renewal._restore_webroot_config(config, renewalparams)
        self.assertEqual(config.webroot_path, ["/var/www/"])
