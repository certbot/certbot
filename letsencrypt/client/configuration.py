"""Let's Encrypt user-supplied configuration."""
import os
import zope.interface

from letsencrypt.client import constants
from letsencrypt.client import interfaces


class NamespaceConfig(object):
    """Configuration wrapper around :class:`argparse.Namespace`.

    For more documentation, including available attributes, please see
    :class:`letsencrypt.client.interfaces.IConfig`. However, note that
    the following attributes are dynamically resolved using
    :attr:`~letsencrypt.client.interfaces.IConfig.work_dir` and relative
    paths defined in :py:mod:`letsencrypt.client.constants`:

      - ``temp_checkpoint_dir``
      - ``in_progress_dir``
      - ``cert_key_backup``
      - ``rec_token_dir``

    :ivar namespace: Namespace typically produced by
        :meth:`argparse.ArgumentParser.parse_args`.
    :type namespace: :class:`argparse.Namespace`

    """
    zope.interface.implements(interfaces.IConfig)

    def __init__(self, namespace):
        self.namespace = namespace

    def __getattr__(self, name):
        return getattr(self.namespace, name)

    @property
    def config_dir(self): # pylint: disable=missing-docstring
        return constants.CONFIG_DIR

    @property
    def work_dir(self): # pylint: disable=missing-docstring
        return constants.WORK_DIR

    @property
    def backup_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(
            constants.WORK_DIR, constants.BACKUP_DIR)

    @property
    def key_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(
            constants.CONFIG_DIR, constants.KEY_DIR)
        
    @property
    def cert_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(
            constants.CONFIG_DIR, constants.CERT_DIR)
        
    @property
    def cert_path(self):  # pylint: disable=missing-docstring
        return os.path.join(
            constants.CONFIG_DIR, constants.CERT_DIR, constants.CERT_NAME)
        
    @property
    def chain_path(self):  # pylint: disable=missing-docstring
        return os.path.join(
            constants.CONFIG_DIR, constants.CERT_DIR, constants.CHAIN_NAME)

    @property
    def temp_checkpoint_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(
            constants.WORK_DIR, constants.TEMP_CHECKPOINT_DIR)

    @property
    def in_progress_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(constants.WORK_DIR, constants.IN_PROGRESS_DIR)

    @property
    def cert_key_backup(self):  # pylint: disable=missing-docstring
        return os.path.join(
            constants.WORK_DIR, constants.CERT_KEY_BACKUP_DIR,
            self.namespace.server.partition(":")[0])

    # TODO: This should probably include the server name
    @property
    def rec_token_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(constants.WORK_DIR, constants.REC_TOKEN_DIR)

    @property
    def apache_server_root(self):  # pylint: disable=missing-docstring
        return constants.APACHE_SERVER_ROOT

    @property
    def apache_mod_ssl_conf(self):  # pylint: disable=missing-docstring
        return constants.APACHE_MOD_SSL_CONF

    @property
    def apache_ctl(self):  # pylint: disable=missing-docstring
        return constants.APACHE_CTL

    @property
    def apache_enmod(self):  # pylint: disable=missing-docstring
        return constants.APACHE_ENMOD
        
    @property
    def apache_init_script(self):  # pylint: disable=missing-docstring
        return constants.APACHE_INIT_SCRIPT

    @property
    def le_vhost_ext(self):  # pylint: disable=missing-docstring
        return constants.LE_VHOST_EXT

    @property
    def rollback(self):  # pylint: disable=missing-docstring
        return constants.ROLLBACK
