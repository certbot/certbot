"""Certbot user-supplied configuration."""
import argparse
import copy
from typing import Any
from typing import List
from typing import Optional
from urllib import parse

from certbot import errors
from certbot import util
from certbot._internal import constants
from certbot.compat import misc
from certbot.compat import os


class NamespaceConfig:
    """Configuration wrapper around :class:`argparse.Namespace`.

    Please note that the following attributes are dynamically resolved using
    :attr:`~certbot.configuration.NamespaceConfig.work_dir` and relative
    paths defined in :py:mod:`certbot._internal.constants`:

      - `accounts_dir`
      - `csr_dir`
      - `in_progress_dir`
      - `key_dir`
      - `temp_checkpoint_dir`

    And the following paths are dynamically resolved using
    :attr:`~certbot.configuration.NamespaceConfig.config_dir` and relative
    paths defined in :py:mod:`certbot._internal.constants`:

      - `default_archive_dir`
      - `live_dir`
      - `renewal_configs_dir`

    :ivar namespace: Namespace typically produced by
        :meth:`argparse.ArgumentParser.parse_args`.
    :type namespace: :class:`argparse.Namespace`

    """

    def __init__(self, namespace: argparse.Namespace) -> None:
        self.namespace: argparse.Namespace
        # Avoid recursion loop because of the delegation defined in __setattr__
        object.__setattr__(self, 'namespace', namespace)

        self.namespace.config_dir = os.path.abspath(self.namespace.config_dir)
        self.namespace.work_dir = os.path.abspath(self.namespace.work_dir)
        self.namespace.logs_dir = os.path.abspath(self.namespace.logs_dir)

        # Check command line parameters sanity, and error out in case of problem.
        _check_config_sanity(self)

    # Delegate any attribute not explicitly defined to the underlying namespace object.

    def __getattr__(self, name: str) -> Any:
        return getattr(self.namespace, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self.namespace, name, value)

    @property
    def server(self) -> str:
        """ACME Directory Resource URI."""
        return self.namespace.server

    @server.setter
    def server(self, server_: str) -> None:
        self.namespace.server = server_

    @property
    def email(self) -> Optional[str]:
        """Email used for registration and recovery contact.

        Use comma to register multiple emails,
        ex: u1@example.com,u2@example.com. (default: Ask).
        """
        return self.namespace.email

    @email.setter
    def email(self, mail: str) -> None:
        self.namespace.email = mail

    @property
    def ecdsa_account_key(self) -> bool:
        """
        Whether or not to use an ECDSA account key for the registration.

        (default: False).
        """
        return self.namespace.ecdsa_account_key

    @property
    def rsa_key_size(self) -> int:
        """Size of the RSA key."""
        return self.namespace.rsa_key_size

    @rsa_key_size.setter
    def rsa_key_size(self, ksize: int) -> None:
        """Set the rsa_key_size property"""
        self.namespace.rsa_key_size = ksize

    @property
    def elliptic_curve(self) -> str:
        """The SECG elliptic curve name to use.

        Please see RFC 8446 for supported values.
        """
        return self.namespace.elliptic_curve

    @elliptic_curve.setter
    def elliptic_curve(self, ecurve: str) -> None:
        """Set the elliptic_curve property"""
        self.namespace.elliptic_curve = ecurve

    @property
    def key_type(self) -> str:
        """Type of generated private key.

        Only *ONE* per invocation can be provided at this time.
        """
        return self.namespace.key_type

    @key_type.setter
    def key_type(self, ktype: str) -> None:
        """Set the key_type property"""
        self.namespace.key_type = ktype

    @property
    def must_staple(self) -> bool:
        """Adds the OCSP Must-Staple extension to the certificate.

        Autoconfigures OCSP Stapling for supported setups
        (Apache version >= 2.3.3 ).
        """
        return self.namespace.must_staple

    @property
    def config_dir(self) -> str:
        """Configuration directory."""
        return self.namespace.config_dir

    @property
    def work_dir(self) -> str:
        """Working directory."""
        return self.namespace.work_dir

    @property
    def accounts_dir(self) -> str:
        """Directory where all account information is stored."""
        return self.accounts_dir_for_server_path(self.server_path)

    @property
    def backup_dir(self) -> str:
        """Configuration backups directory."""
        return os.path.join(self.namespace.work_dir, constants.BACKUP_DIR)

    @property
    def csr_dir(self) -> str:
        """Directory where new Certificate Signing Requests (CSRs) are saved."""
        return os.path.join(self.namespace.config_dir, constants.CSR_DIR)

    @property
    def in_progress_dir(self) -> str:
        """Directory used before a permanent checkpoint is finalized."""
        return os.path.join(self.namespace.work_dir, constants.IN_PROGRESS_DIR)

    @property
    def key_dir(self) -> str:
        """Keys storage."""
        return os.path.join(self.namespace.config_dir, constants.KEY_DIR)

    @property
    def temp_checkpoint_dir(self) -> str:
        """Temporary checkpoint directory."""
        return os.path.join(
            self.namespace.work_dir, constants.TEMP_CHECKPOINT_DIR)

    @property
    def no_verify_ssl(self) -> bool:
        """Disable verification of the ACME server's certificate."""
        return self.namespace.no_verify_ssl

    @property
    def http01_port(self) -> int:
        """Port used in the http-01 challenge.

        This only affects the port Certbot listens on.
        A conforming ACME server will still attempt to connect on port 80.
        """
        return self.namespace.http01_port

    @property
    def http01_address(self) -> str:
        """The address the server listens to during http-01 challenge."""
        return self.namespace.http01_address

    @property
    def https_port(self) -> int:
        """Port used to serve HTTPS.

        This affects which port Nginx will listen on after a LE certificate
        is installed.
        """
        return self.namespace.https_port

    @property
    def pref_challs(self) -> List[str]:
        """List of user specified preferred challenges.

        Sorted with the most preferred challenge listed first.
        """
        return self.namespace.pref_challs

    @property
    def allow_subset_of_names(self) -> bool:
        """Allow only a subset of names to be authorized to perform validations.

        When performing domain validation, do not consider it a failure
        if authorizations can not be obtained for a strict subset of
        the requested domains. This may be useful for allowing renewals for
        multiple domains to succeed even if some domains no longer point
        at this system.
        """
        return self.namespace.allow_subset_of_names

    @property
    def strict_permissions(self) -> bool:
        """Enable strict permissions checks.

        Require that all configuration files are owned by the current
        user; only needed if your config is somewhere unsafe like /tmp/.
        """
        return self.namespace.strict_permissions

    @property
    def disable_renew_updates(self) -> bool:
        """Disable renewal updates.

        If updates provided by installer enhancements when Certbot is being run
        with \"renew\" verb should be disabled.
        """
        return self.namespace.disable_renew_updates

    @property
    def preferred_chain(self) -> Optional[str]:
        """Set the preferred certificate chain.

        If the CA offers multiple certificate chains, prefer the chain whose
        topmost certificate was issued from this Subject Common Name.
        If no match, the default offered chain will be used.
        """
        return self.namespace.preferred_chain

    @property
    def server_path(self) -> str:
        """File path based on ``server``."""
        parsed = parse.urlparse(self.namespace.server)
        return (parsed.netloc + parsed.path).replace('/', os.path.sep)

    def accounts_dir_for_server_path(self, server_path: str) -> str:
        """Path to accounts directory based on server_path"""
        server_path = misc.underscores_for_unsupported_characters_in_path(server_path)
        return os.path.join(
            self.namespace.config_dir, constants.ACCOUNTS_DIR, server_path)

    @property
    def default_archive_dir(self) -> str:  # pylint: disable=missing-function-docstring
        return os.path.join(self.namespace.config_dir, constants.ARCHIVE_DIR)

    @property
    def live_dir(self) -> str:  # pylint: disable=missing-function-docstring
        return os.path.join(self.namespace.config_dir, constants.LIVE_DIR)

    @property
    def renewal_configs_dir(self) -> str:  # pylint: disable=missing-function-docstring
        return os.path.join(
            self.namespace.config_dir, constants.RENEWAL_CONFIGS_DIR)

    @property
    def renewal_hooks_dir(self) -> str:
        """Path to directory with hooks to run with the renew subcommand."""
        return os.path.join(self.namespace.config_dir,
                            constants.RENEWAL_HOOKS_DIR)

    @property
    def renewal_pre_hooks_dir(self) -> str:
        """Path to the pre-hook directory for the renew subcommand."""
        return os.path.join(self.renewal_hooks_dir,
                            constants.RENEWAL_PRE_HOOKS_DIR)

    @property
    def renewal_deploy_hooks_dir(self) -> str:
        """Path to the deploy-hook directory for the renew subcommand."""
        return os.path.join(self.renewal_hooks_dir,
                            constants.RENEWAL_DEPLOY_HOOKS_DIR)

    @property
    def renewal_post_hooks_dir(self) -> str:
        """Path to the post-hook directory for the renew subcommand."""
        return os.path.join(self.renewal_hooks_dir,
                            constants.RENEWAL_POST_HOOKS_DIR)

    @property
    def issuance_timeout(self) -> int:
        """This option specifies how long (in seconds) Certbot will wait
        for the server to issue a certificate.
        """
        return self.namespace.issuance_timeout

    # Magic methods

    def __deepcopy__(self, _memo: Any) -> 'NamespaceConfig':
        # Work around https://bugs.python.org/issue1515 for py26 tests :( :(
        # https://travis-ci.org/letsencrypt/letsencrypt/jobs/106900743#L3276
        new_ns = copy.deepcopy(self.namespace)
        return type(self)(new_ns)


def _check_config_sanity(config: NamespaceConfig) -> None:
    """Validate command line options and display error message if
    requirements are not met.

    :param config: NamespaceConfig instance holding user configuration
    :type args: :class:`certbot.configuration.NamespaceConfig`

    """
    # Port check
    if config.http01_port == config.https_port:
        raise errors.ConfigurationError(
            "Trying to run http-01 and https-port "
            "on the same port ({0})".format(config.https_port))

    # Domain checks
    if config.namespace.domains is not None:
        for domain in config.namespace.domains:
            # This may be redundant, but let's be paranoid
            util.enforce_domain_sanity(domain)
