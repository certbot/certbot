"""Certbot user-supplied configuration."""
import copy
import os

from six.moves.urllib import parse  # pylint: disable=import-error
import zope.interface

from certbot import constants
from certbot import errors
from certbot import interfaces
from certbot import util


@zope.interface.implementer(interfaces.IConfig)
class NamespaceConfig(object):
    """Configuration wrapper around :class:`argparse.Namespace`.

    For more documentation, including available attributes, please see
    :class:`certbot.interfaces.IConfig`. However, note that
    the following attributes are dynamically resolved using
    :attr:`~certbot.interfaces.IConfig.work_dir` and relative
    paths defined in :py:mod:`certbot.constants`:

      - `accounts_dir`
      - `csr_dir`
      - `in_progress_dir`
      - `key_dir`
      - `temp_checkpoint_dir`

    And the following paths are dynamically resolved using
    :attr:`~certbot.interfaces.IConfig.config_dir` and relative
    paths defined in :py:mod:`certbot.constants`:

      - `default_archive_dir`
      - `live_dir`
      - `renewal_configs_dir`

    :ivar namespace: Namespace typically produced by
        :meth:`argparse.ArgumentParser.parse_args`.
    :type namespace: :class:`argparse.Namespace`

    """

    def __init__(self, namespace):
        object.__setattr__(self, 'namespace', namespace)

        self.namespace.config_dir = os.path.abspath(self.namespace.config_dir)
        self.namespace.work_dir = os.path.abspath(self.namespace.work_dir)
        self.namespace.logs_dir = os.path.abspath(self.namespace.logs_dir)

        # Check command line parameters sanity, and error out in case of problem.
        check_config_sanity(self)

    def __getattr__(self, name):
        return getattr(self.namespace, name)

    def __setattr__(self, name, value):
        setattr(self.namespace, name, value)

    @property
    def server_path(self):
        """File path based on ``server``."""
        parsed = parse.urlparse(self.namespace.server)
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

    def __deepcopy__(self, _memo):
        # Work around https://bugs.python.org/issue1515 for py26 tests :( :(
        # https://travis-ci.org/letsencrypt/letsencrypt/jobs/106900743#L3276
        new_ns = copy.deepcopy(self.namespace)
        return type(self)(new_ns)

    @property
    def default_archive_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(self.namespace.config_dir, constants.ARCHIVE_DIR)

    @property
    def live_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(self.namespace.config_dir, constants.LIVE_DIR)

    @property
    def renewal_configs_dir(self):  # pylint: disable=missing-docstring
        return os.path.join(
            self.namespace.config_dir, constants.RENEWAL_CONFIGS_DIR)

    @property
    def renewal_hooks_dir(self):
        """Path to directory with hooks to run with the renew subcommand."""
        return os.path.join(self.namespace.config_dir,
                            constants.RENEWAL_HOOKS_DIR)

    @property
    def renewal_pre_hooks_dir(self):
        """Path to the pre-hook directory for the renew subcommand."""
        return os.path.join(self.renewal_hooks_dir,
                            constants.RENEWAL_PRE_HOOKS_DIR)

    @property
    def renewal_deploy_hooks_dir(self):
        """Path to the deploy-hook directory for the renew subcommand."""
        return os.path.join(self.renewal_hooks_dir,
                            constants.RENEWAL_DEPLOY_HOOKS_DIR)

    @property
    def renewal_post_hooks_dir(self):
        """Path to the post-hook directory for the renew subcommand."""
        return os.path.join(self.renewal_hooks_dir,
                            constants.RENEWAL_POST_HOOKS_DIR)


def check_config_sanity(config):
    """Validate command line options and display error message if
    requirements are not met.

    :param config: IConfig instance holding user configuration
    :type args: :class:`certbot.interfaces.IConfig`

    """
    # Port check
    if config.http01_port == config.tls_sni_01_port:
        raise errors.ConfigurationError(
            "Trying to run http-01 and tls-sni-01 "
            "on the same port ({0})".format(config.tls_sni_01_port))

    # Domain checks
    if config.namespace.domains is not None:
        for domain in config.namespace.domains:
            # This may be redundant, but let's be paranoid
            util.enforce_domain_sanity(domain)
