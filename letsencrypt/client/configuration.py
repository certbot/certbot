"""Let's Encrypt user-supplied configuration."""
import os
import urlparse

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
    def temp_checkpoint_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(
            self.namespace.work_dir, constants.TEMP_CHECKPOINT_DIR)

    @property
    def in_progress_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(self.namespace.work_dir, constants.IN_PROGRESS_DIR)

    @property
    def server_path(self):
        """File path based on ``server``."""
        parsed = urlparse.urlparse(self.namespace.server)
        return (parsed.netloc + parsed.path).replace('/', os.path.sep)

    @property
    def cert_key_backup(self):  # pylint: disable=missing-docstring
        return os.path.join(
            self.namespace.work_dir, constants.CERT_KEY_BACKUP_DIR,
            self.server_path)

    @property
    def accounts_dir(self):  #pylint: disable=missing-docstring
        return os.path.join(
            self.namespace.config_dir, constants.ACCOUNTS_DIR, self.server_path)

    @property
    def account_keys_dir(self):  #pylint: disable=missing-docstring
        return os.path.join(
            self.namespace.config_dir, constants.ACCOUNTS_DIR,
            self.server_path, constants.ACCOUNT_KEYS_DIR)

    # TODO: This should probably include the server name
    @property
    def rec_token_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(self.namespace.work_dir, constants.REC_TOKEN_DIR)
