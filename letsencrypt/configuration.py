"""Let's Encrypt user-supplied configuration."""
import os
import urlparse
import re

import zope.interface

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

        self.namespace.config_dir = os.path.abspath(self.namespace.config_dir)
        self.namespace.work_dir = os.path.abspath(self.namespace.work_dir)
        self.namespace.logs_dir = os.path.abspath(self.namespace.logs_dir)

        # Check command line parameters sanity, and error out in case of problem.
        check_config_sanity(self)

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


def check_config_sanity(config):
    """Validate command line options and display error message if
    requirements are not met.

    :param config: IConfig instance holding user configuration
    :type args: :class:`letsencrypt.interfaces.IConfig`

    """
    # Port check
    if config.http01_port == config.tls_sni_01_port:
        raise errors.ConfigurationError(
            "Trying to run http-01 and tls-sni-01 "
            "on the same port ({0})".format(config.tls_sni_01_port))

    # Domain checks
    if config.namespace.domains is not None:
        _check_config_domain_sanity(config.namespace.domains)


def _check_config_domain_sanity(domains):
    """Helper method for check_config_sanity which validates
    domain flag values and errors out if the requirements are not met.

    :param domains: List of domains
    :type domains: `list` of `string`
    :raises ConfigurationError: for invalid domains and cases where Let's
                                Encrypt currently will not issue certificates

    """
    # Check if there's a wildcard domain
    if any(d.startswith("*.") for d in domains):
        raise errors.ConfigurationError(
            "Wildcard domains are not supported")
    # Punycode
    if any("xn--" in d for d in domains):
        raise errors.ConfigurationError(
            "Punycode domains are not supported")
    # FQDN checks from
    # http://www.mkyong.com/regular-expressions/domain-name-regular-expression-example/
    #  Characters used, domain parts < 63 chars, tld > 1 < 64 chars
    #  first and last char is not "-"
    fqdn = re.compile("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,63}$")
    if any(True for d in domains if not fqdn.match(d)):
        raise errors.ConfigurationError("Requested domain is not a FQDN")
