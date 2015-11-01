"""Let's Encrypt user-supplied configuration."""
import os
import urlparse

import zope.interface

from acme import challenges

from letsencrypt import constants
from letsencrypt import errors
from letsencrypt import interfaces


class NamespaceConfig(object):
    """Configuration wrapper around :class:`argparse.Namespace`.

    For more documentation, including available attributes, please see
    :class:`letsencrypt.interfaces.IConfig`. However, note that
    the following attributes are dynamically resolved using
    :attr:`~letsencrypt.interfaces.IConfig.work_dir` and relative
    paths defined in :py:mod:`letsencrypt.constants`:

      - `accounts_dir`
      - `csr_dir`
      - `in_progress_dir`
      - `key_dir`
      - `renewer_config_file`
      - `temp_checkpoint_dir`

    :ivar namespace: Namespace typically produced by
        :meth:`argparse.ArgumentParser.parse_args`.
    :type namespace: :class:`argparse.Namespace`

    """
    zope.interface.implements(interfaces.IConfig)

    def __init__(self, namespace):
        self.namespace = namespace

        if self.simple_http_port == self.dvsni_port:
            raise errors.Error(
                "Trying to run SimpleHTTP and DVSNI "
                "on the same port ({0})".format(self.dvsni_port))

    def __getattr__(self, name):
        return getattr(self.namespace, name)

    @property
    def server_path(self):
        """File path based on ``server``."""
        parsed = urlparse.urlparse(self.namespace.server)
        return (parsed.netloc + parsed.path).replace('/', os.path.sep)

    @property
    def accounts_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(
            self.namespace.config_dir, constants.ACCOUNTS_DIR, self.server_path)

    @property
    def backup_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(self.namespace.work_dir, constants.BACKUP_DIR)

    @property
    def csr_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(self.namespace.config_dir, constants.CSR_DIR)

    @property
    def in_progress_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(self.namespace.work_dir, constants.IN_PROGRESS_DIR)

    @property
    def key_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(self.namespace.config_dir, constants.KEY_DIR)

    @property
    def temp_checkpoint_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(
            self.namespace.work_dir, constants.TEMP_CHECKPOINT_DIR)

    @property
    def simple_http_port(self):  # pylint: disable=missing-docstring
        if self.namespace.simple_http_port is not None:
            return self.namespace.simple_http_port
        else:
            return challenges.SimpleHTTPResponse.PORT


class RenewerConfiguration(object):
    """Configuration wrapper for renewer."""

    def __init__(self, namespace):
        self.namespace = namespace

    def __getattr__(self, name):
        return getattr(self.namespace, name)

    @property
    def archive_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(self.namespace.config_dir, constants.ARCHIVE_DIR)

    @property
    def live_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(self.namespace.config_dir, constants.LIVE_DIR)

    @property
    def renewal_configs_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(
            self.namespace.config_dir, constants.RENEWAL_CONFIGS_DIR)

    @property
    def renewer_config_file(self):  # pylint: disable=missing-docstring
        return os.path.join(
            self.namespace.config_dir, constants.RENEWER_CONFIG_FILENAME)
