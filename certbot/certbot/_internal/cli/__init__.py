"""Certbot command line argument & config processing."""
# pylint: disable=too-many-lines
import argparse
import logging  # noqa
import logging.handlers
import sys  # noqa
from typing import Any
from typing import List
from typing import Optional
from typing import Type

import certbot
from certbot._internal import constants
from certbot._internal.cli.cli_constants import ARGPARSE_PARAMS_TO_REMOVE
from certbot._internal.cli.cli_constants import cli_command
from certbot._internal.cli.cli_constants import COMMAND_OVERVIEW
from certbot._internal.cli.cli_constants import DEPRECATED_OPTIONS
from certbot._internal.cli.cli_constants import EXIT_ACTIONS
from certbot._internal.cli.cli_constants import HELP_AND_VERSION_USAGE
from certbot._internal.cli.cli_constants import SHORT_USAGE
from certbot._internal.cli.cli_constants import VAR_MODIFIERS
from certbot._internal.cli.cli_constants import ZERO_ARG_ACTIONS
from certbot._internal.cli.cli_utils import _Default
from certbot._internal.cli.cli_utils import _DeployHookAction
from certbot._internal.cli.cli_utils import _DomainsAction
from certbot._internal.cli.cli_utils import _EncodeReasonAction
from certbot._internal.cli.cli_utils import _PrefChallAction
from certbot._internal.cli.cli_utils import _RenewHookAction
from certbot._internal.cli.cli_utils import _user_agent_comment_type
from certbot._internal.cli.cli_utils import add_domains
from certbot._internal.cli.cli_utils import CaseInsensitiveList
from certbot._internal.cli.cli_utils import config_help
from certbot._internal.cli.cli_utils import CustomHelpFormatter
from certbot._internal.cli.cli_utils import flag_default
from certbot._internal.cli.cli_utils import HelpfulArgumentGroup
from certbot._internal.cli.cli_utils import nonnegative_int
from certbot._internal.cli.cli_utils import parse_preferred_challenges
from certbot._internal.cli.cli_utils import read_file
from certbot._internal.cli.group_adder import _add_all_groups
from certbot._internal.cli.helpful import HelpfulArgumentParser
from certbot._internal.cli.paths_parser import _paths_parser
from certbot._internal.cli.plugins_parsing import _plugins_parsing
from certbot._internal.cli.subparsers import _create_subparsers
from certbot._internal.cli.verb_help import VERB_HELP
from certbot._internal.cli.verb_help import VERB_HELP_MAP
from certbot._internal.plugins import disco as plugins_disco
import certbot._internal.plugins.selection as plugin_selection
from certbot.plugins import enhancements

logger = logging.getLogger(__name__)


# Global, to save us from a lot of argument passing within the scope of this module
helpful_parser: Optional[HelpfulArgumentParser] = None


def prepare_and_parse_args(plugins: plugins_disco.PluginsRegistry, args: List[str],
                           detect_defaults: bool = False) -> argparse.Namespace:
    """Returns parsed command line arguments.

    :param .PluginsRegistry plugins: available plugins
    :param list args: command line arguments with the program name removed

    :returns: parsed command line arguments
    :rtype: argparse.Namespace

    """

    helpful = HelpfulArgumentParser(args, plugins, detect_defaults)
    _add_all_groups(helpful)

    # --help is automatically provided by argparse
    helpful.add(
        None, "-v", "--verbose", dest="verbose_count", action="count",
        default=flag_default("verbose_count"), help="This flag can be used "
        "multiple times to incrementally increase the verbosity of output, "
        "e.g. -vvv.")
    # This is for developers to set the level in the cli.ini, and overrides
    # the --verbose flag
    helpful.add(
        None, "--verbose-level", dest="verbose_level",
        default=flag_default("verbose_level"), help=argparse.SUPPRESS)
    helpful.add(
        None, "-t", "--text", dest="text_mode", action="store_true",
        default=flag_default("text_mode"), help=argparse.SUPPRESS)
    helpful.add(
        None, "--max-log-backups", type=nonnegative_int,
        default=flag_default("max_log_backups"),
        help="Specifies the maximum number of backup logs that should "
             "be kept by Certbot's built in log rotation. Setting this "
             "flag to 0 disables log rotation entirely, causing "
             "Certbot to always append to the same log file.")
    helpful.add(
        None, "--preconfigured-renewal", dest="preconfigured_renewal",
        action="store_true", default=flag_default("preconfigured_renewal"),
        help=argparse.SUPPRESS
    )
    helpful.add(
        [None, "automation", "run", "certonly", "enhance"],
        "-n", "--non-interactive", "--noninteractive",
        dest="noninteractive_mode", action="store_true",
        default=flag_default("noninteractive_mode"),
        help="Run without ever asking for user input. This may require "
              "additional command line flags; the client will try to explain "
              "which ones are required if it finds one missing")
    helpful.add(
        [None, "certonly", "register"],
        "--ecdsa-account-key",
        dest="ecdsa_account_key", action="store_true",
        default=flag_default("ecdsa_account_key"),
        help="Create an ECDSA key for the account registration",
    )
    helpful.add(
        [None, "register", "run", "certonly", "enhance"],
        constants.FORCE_INTERACTIVE_FLAG, action="store_true",
        default=flag_default("force_interactive"),
        help="Force Certbot to be interactive even if it detects it's not "
             "being run in a terminal. This flag cannot be used with the "
             "renew subcommand.")
    helpful.add(
        [None, "run", "certonly", "certificates", "enhance"],
        "-d", "--domains", "--domain", dest="domains",
        metavar="DOMAIN", action=_DomainsAction,
        default=flag_default("domains"),
        help="Domain names to apply. For multiple domains you can use "
             "multiple -d flags or enter a comma separated list of domains "
             "as a parameter. The first domain provided will be the "
             "subject CN of the certificate, and all domains will be "
             "Subject Alternative Names on the certificate. "
             "The first domain will also be used in "
             "some software user interfaces and as the file paths for the "
             "certificate and related material unless otherwise "
             "specified or you already have a certificate with the same "
             "name. In the case of a name collision it will append a number "
             "like 0001 to the file path name. (default: Ask)")
    helpful.add(
        [None, "run", "certonly", "register"],
        "--eab-kid", dest="eab_kid",
        metavar="EAB_KID",
        help="Key Identifier for External Account Binding"
    )
    helpful.add(
        [None, "run", "certonly", "register"],
        "--eab-hmac-key", dest="eab_hmac_key",
        metavar="EAB_HMAC_KEY",
        help="HMAC key for External Account Binding"
    )
    helpful.add(
        [None, "run", "certonly", "manage", "delete", "certificates",
         "renew", "enhance"], "--cert-name", dest="certname",
        metavar="CERTNAME", default=flag_default("certname"),
        help="Certificate name to apply. This name is used by Certbot for housekeeping "
             "and in file paths; it doesn't affect the content of the certificate itself. "
             "To see certificate names, run 'certbot certificates'. "
             "When creating a new certificate, specifies the new certificate's name. "
             "(default: the first provided domain or the name of an existing "
             "certificate on your system for the same domains)")
    helpful.add(
        [None, "testing", "renew", "certonly"],
        "--dry-run", action="store_true", dest="dry_run",
        default=flag_default("dry_run"),
        help="Perform a test run of the client, obtaining test (invalid) certificates"
             " but not saving them to disk. This can currently only be used"
             " with the 'certonly' and 'renew' subcommands. \nNote: Although --dry-run"
             " tries to avoid making any persistent changes on a system, it "
             " is not completely side-effect free: if used with webserver authenticator plugins"
             " like apache and nginx, it makes and then reverts temporary config changes"
             " in order to obtain test certificates, and reloads webservers to deploy and then"
             " roll back those changes.  It also calls --pre-hook and --post-hook commands"
             " if they are defined because they may be necessary to accurately simulate"
             " renewal. --deploy-hook commands are not called.")
    helpful.add(
        ["register", "automation"], "--register-unsafely-without-email", action="store_true",
        default=flag_default("register_unsafely_without_email"),
        help="Specifying this flag enables registering an account with no "
             "email address. This is strongly discouraged, because you will be "
             "unable to receive notice about impending expiration or "
             "revocation of your certificates or problems with your Certbot "
             "installation that will lead to failure to renew.")
    helpful.add(
        ["register", "update_account", "unregister", "automation"], "-m", "--email",
        default=flag_default("email"),
        help=config_help("email"))
    helpful.add(["register", "update_account", "automation"], "--eff-email", action="store_true",
                default=flag_default("eff_email"), dest="eff_email",
                help="Share your e-mail address with EFF")
    helpful.add(["register", "update_account", "automation"], "--no-eff-email",
                action="store_false", default=flag_default("eff_email"), dest="eff_email",
                help="Don't share your e-mail address with EFF")
    helpful.add(
        ["automation", "certonly", "run"],
        "--keep-until-expiring", "--keep", "--reinstall",
        dest="reinstall", action="store_true", default=flag_default("reinstall"),
        help="If the requested certificate matches an existing certificate, always keep the "
             "existing one until it is due for renewal (for the "
             "'run' subcommand this means reinstall the existing certificate). (default: Ask)")
    helpful.add(
        "automation", "--expand", action="store_true", default=flag_default("expand"),
        help="If an existing certificate is a strict subset of the requested names, "
             "always expand and replace it with the additional names. (default: Ask)")
    helpful.add(
        "automation", "--version", action="version",
        version="%(prog)s {0}".format(certbot.__version__),
        help="show program's version number and exit")
    helpful.add(
        ["automation", "renew"],
        "--force-renewal", "--renew-by-default", dest="renew_by_default",
        action="store_true", default=flag_default("renew_by_default"),
        help="If a certificate "
             "already exists for the requested domains, renew it now, "
             "regardless of whether it is near expiry. (Often "
             "--keep-until-expiring is more appropriate). Also implies "
             "--expand.")
    helpful.add(
        "automation", "--renew-with-new-domains", dest="renew_with_new_domains",
        action="store_true", default=flag_default("renew_with_new_domains"),
        help="If a "
             "certificate already exists for the requested certificate name "
             "but does not match the requested domains, renew it now, "
             "regardless of whether it is near expiry.")
    helpful.add(
        "automation", "--reuse-key", dest="reuse_key",
        action="store_true", default=flag_default("reuse_key"),
        help="When renewing, use the same private key as the existing "
             "certificate.")
    helpful.add(
        "automation", "--no-reuse-key", dest="reuse_key",
        action="store_false", default=flag_default("reuse_key"),
        help="When renewing, do not use the same private key as the existing "
             "certificate. Not reusing private keys is the default behavior of "
             "Certbot. This option may be used to unset --reuse-key on an "
             "existing certificate.")

    helpful.add(
        ["automation", "renew", "certonly"],
        "--allow-subset-of-names", action="store_true",
        default=flag_default("allow_subset_of_names"),
        help="When performing domain validation, do not consider it a failure "
             "if authorizations can not be obtained for a strict subset of "
             "the requested domains. This may be useful for allowing renewals for "
             "multiple domains to succeed even if some domains no longer point "
             "at this system. This option cannot be used with --csr.")
    helpful.add(
        "automation", "--agree-tos", dest="tos", action="store_true",
        default=flag_default("tos"),
        help="Agree to the ACME Subscriber Agreement (default: Ask)")
    helpful.add(
        ["unregister", "automation"], "--account", metavar="ACCOUNT_ID",
        default=flag_default("account"),
        help="Account ID to use")
    helpful.add(
        "automation", "--duplicate", dest="duplicate", action="store_true",
        default=flag_default("duplicate"),
        help="Allow making a certificate lineage that duplicates an existing one "
             "(both can be renewed in parallel)")
    helpful.add(
        ["automation", "renew", "certonly", "run"],
        "-q", "--quiet", dest="quiet", action="store_true",
        default=flag_default("quiet"),
        help="Silence all output except errors. Useful for automation via cron."
             " Implies --non-interactive.")
    # overwrites server, handled in HelpfulArgumentParser.parse_args()
    helpful.add(["testing", "revoke", "run"], "--test-cert", "--staging",
        dest="staging", action="store_true", default=flag_default("staging"),
        help="Use the staging server to obtain or revoke test (invalid) certificates; equivalent"
             " to --server " + constants.STAGING_URI)
    helpful.add(
        "testing", "--debug", action="store_true", default=flag_default("debug"),
        help="Show tracebacks in case of errors")
    helpful.add(
        [None, "certonly", "run"], "--debug-challenges", action="store_true",
        default=flag_default("debug_challenges"),
        help="After setting up challenges, wait for user input before "
             "submitting to CA. When used in combination with the `-v` "
             "option, the challenge URLs or FQDNs and their expected "
             "return values are shown.")
    helpful.add(
        "testing", "--no-verify-ssl", action="store_true",
        help=config_help("no_verify_ssl"),
        default=flag_default("no_verify_ssl"))
    helpful.add(
        ["testing", "standalone", "manual"], "--http-01-port", type=int,
        dest="http01_port",
        default=flag_default("http01_port"), help=config_help("http01_port"))
    helpful.add(
        ["testing", "standalone"], "--http-01-address",
        dest="http01_address",
        default=flag_default("http01_address"), help=config_help("http01_address"))
    helpful.add(
        ["testing", "nginx"], "--https-port", type=int,
        default=flag_default("https_port"),
        help=config_help("https_port"))
    helpful.add(
        "testing", "--break-my-certs", action="store_true",
        default=flag_default("break_my_certs"),
        help="Be willing to replace or renew valid certificates with invalid "
             "(testing/staging) certificates")
    helpful.add(
        "security", "--rsa-key-size", type=int, metavar="N",
        default=flag_default("rsa_key_size"), help=config_help("rsa_key_size"))
    helpful.add(
        "security", "--key-type", choices=['rsa', 'ecdsa'], type=str,
        default=flag_default("key_type"), help=config_help("key_type"))
    helpful.add(
        "security", "--elliptic-curve", type=str, choices=[
            'secp256r1',
            'secp384r1',
            'secp521r1',
        ], metavar="N",
        default=flag_default("elliptic_curve"), help=config_help("elliptic_curve"))
    helpful.add(
        "security", "--must-staple", action="store_true",
        dest="must_staple", default=flag_default("must_staple"),
        help=config_help("must_staple"))
    helpful.add(
        ["security", "enhance"],
        "--redirect", action="store_true", dest="redirect",
        default=flag_default("redirect"),
        help="Automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost. (default: redirect enabled for install and run, "
             "disabled for enhance)")
    helpful.add(
        "security", "--no-redirect", action="store_false", dest="redirect",
        default=flag_default("redirect"),
        help="Do not automatically redirect all HTTP traffic to HTTPS for the newly "
             "authenticated vhost. (default: redirect enabled for install and run, "
             "disabled for enhance)")
    helpful.add(
        ["security", "enhance"],
        "--hsts", action="store_true", dest="hsts", default=flag_default("hsts"),
        help="Add the Strict-Transport-Security header to every HTTP response."
             " Forcing browser to always use SSL for the domain."
             " Defends against SSL Stripping.")
    helpful.add(
        "security", "--no-hsts", action="store_false", dest="hsts",
        default=flag_default("hsts"), help=argparse.SUPPRESS)
    helpful.add(
        ["security", "enhance"],
        "--uir", action="store_true", dest="uir", default=flag_default("uir"),
        help='Add the "Content-Security-Policy: upgrade-insecure-requests"'
             ' header to every HTTP response. Forcing the browser to use'
             ' https:// for every http:// resource.')
    helpful.add(
        "security", "--no-uir", action="store_false", dest="uir", default=flag_default("uir"),
        help=argparse.SUPPRESS)
    helpful.add(
        "security", "--staple-ocsp", action="store_true", dest="staple",
        default=flag_default("staple"),
        help="Enables OCSP Stapling. A valid OCSP response is stapled to"
        " the certificate that the server offers during TLS.")
    helpful.add(
        "security", "--no-staple-ocsp", action="store_false", dest="staple",
        default=flag_default("staple"), help=argparse.SUPPRESS)
    helpful.add(
        "security", "--strict-permissions", action="store_true",
        default=flag_default("strict_permissions"),
        help="Require that all configuration files are owned by the current "
             "user; only needed if your config is somewhere unsafe like /tmp/")
    helpful.add(
        [None, "certonly", "renew", "run"],
        "--preferred-chain", dest="preferred_chain",
        default=flag_default("preferred_chain"), help=config_help("preferred_chain")
    )
    helpful.add(
        ["manual", "standalone", "certonly", "renew"],
        "--preferred-challenges", dest="pref_challs",
        action=_PrefChallAction, default=flag_default("pref_challs"),
        help='A sorted, comma delimited list of the preferred challenge to '
             'use during authorization with the most preferred challenge '
             'listed first (Eg, "dns" or "http,dns"). '
             'Not all plugins support all challenges. See '
             'https://certbot.eff.org/docs/using.html#plugins for details. '
             'ACME Challenges are versioned, but if you pick "http" rather '
             'than "http-01", Certbot will select the latest version '
             'automatically.')
    helpful.add(
        [None, "certonly", "run"], "--issuance-timeout", type=nonnegative_int,
        dest="issuance_timeout",
        default=flag_default("issuance_timeout"),
        help=config_help("issuance_timeout"))
    helpful.add(
        "renew", "--pre-hook",
        help="Command to be run in a shell before obtaining any certificates."
        " Intended primarily for renewal, where it can be used to temporarily"
        " shut down a webserver that might conflict with the standalone"
        " plugin. This will only be called if a certificate is actually to be"
        " obtained/renewed. When renewing several certificates that have"
        " identical pre-hooks, only the first will be executed.")
    helpful.add(
        "renew", "--post-hook",
        help="Command to be run in a shell after attempting to obtain/renew"
        " certificates. Can be used to deploy renewed certificates, or to"
        " restart any servers that were stopped by --pre-hook. This is only"
        " run if an attempt was made to obtain/renew a certificate. If"
        " multiple renewed certificates have identical post-hooks, only"
        " one will be run.")
    helpful.add("renew", "--renew-hook",
                action=_RenewHookAction, help=argparse.SUPPRESS)
    helpful.add(
        "renew", "--no-random-sleep-on-renew", action="store_false",
        default=flag_default("random_sleep_on_renew"), dest="random_sleep_on_renew",
        help=argparse.SUPPRESS)
    helpful.add(
        "renew", "--deploy-hook", action=_DeployHookAction,
        help='Command to be run in a shell once for each successfully'
        ' issued certificate. For this command, the shell variable'
        ' $RENEWED_LINEAGE will point to the config live subdirectory'
        ' (for example, "/etc/letsencrypt/live/example.com") containing'
        ' the new certificates and keys; the shell variable'
        ' $RENEWED_DOMAINS will contain a space-delimited list of'
        ' renewed certificate domains (for example, "example.com'
        ' www.example.com"')
    helpful.add(
        "renew", "--disable-hook-validation",
        action="store_false", dest="validate_hooks",
        default=flag_default("validate_hooks"),
        help="Ordinarily the commands specified for"
        " --pre-hook/--post-hook/--deploy-hook will be checked for"
        " validity, to see if the programs being run are in the $PATH,"
        " so that mistakes can be caught early, even when the hooks"
        " aren't being run just yet. The validation is rather"
        " simplistic and fails if you use more advanced shell"
        " constructs, so you can use this switch to disable it."
        " (default: False)")
    helpful.add(
        "renew", "--no-directory-hooks", action="store_false",
        default=flag_default("directory_hooks"), dest="directory_hooks",
        help="Disable running executables found in Certbot's hook directories"
        " during renewal. (default: False)")
    helpful.add(
        "renew", "--disable-renew-updates", action="store_true",
        default=flag_default("disable_renew_updates"), dest="disable_renew_updates",
        help="Disable automatic updates to your server configuration that"
        " would otherwise be done by the selected installer plugin, and triggered"
        " when the user executes \"certbot renew\", regardless of if the certificate"
        " is renewed. This setting does not apply to important TLS configuration"
        " updates.")
    helpful.add(
        "renew", "--no-autorenew", action="store_false",
        default=flag_default("autorenew"), dest="autorenew",
        help="Disable auto renewal of certificates.")

    # Deprecated arguments
    helpful.add_deprecated_argument("--os-packages-only", 0)
    helpful.add_deprecated_argument("--no-self-upgrade", 0)
    helpful.add_deprecated_argument("--no-bootstrap", 0)
    helpful.add_deprecated_argument("--no-permissions-check", 0)

    # Populate the command line parameters for new style enhancements
    enhancements.populate_cli(helpful.add)

    _create_subparsers(helpful)
    _paths_parser(helpful)
    # _plugins_parsing should be the last thing to act upon the main
    # parser (--help should display plugin-specific options last)
    _plugins_parsing(helpful, plugins)

    if not detect_defaults:
        global helpful_parser # pylint: disable=global-statement
        helpful_parser = helpful
    return helpful.parse_args()


def set_by_cli(var: str) -> bool:
    """
    Return True if a particular config variable has been set by the user
    (CLI or config file) including if the user explicitly set it to the
    default.  Returns False if the variable was assigned a default value.
    """
    # We should probably never actually hit this code. But if we do,
    # a deprecated option has logically never been set by the CLI.
    if var in DEPRECATED_OPTIONS:
        return False

    detector = set_by_cli.detector  # type: ignore
    if detector is None and helpful_parser is not None:
        # Setup on first run: `detector` is a weird version of config in which
        # the default value of every attribute is wrangled to be boolean-false
        plugins = plugins_disco.PluginsRegistry.find_all()
        # reconstructed_args == sys.argv[1:], or whatever was passed to main()
        reconstructed_args = helpful_parser.args + [helpful_parser.verb]

        detector = set_by_cli.detector = prepare_and_parse_args(  # type: ignore
            plugins, reconstructed_args, detect_defaults=True)
        # propagate plugin requests: eg --standalone modifies config.authenticator
        detector.authenticator, detector.installer = (
            plugin_selection.cli_plugin_requests(detector))

    if not isinstance(getattr(detector, var), _Default):
        logger.debug("Var %s=%s (set by user).", var, getattr(detector, var))
        return True

    for modifier in VAR_MODIFIERS.get(var, []):
        if set_by_cli(modifier):
            logger.debug("Var %s=%s (set by user).",
                var, VAR_MODIFIERS.get(var, []))
            return True

    return False


# static housekeeping var
# functions attributed are not supported by mypy
# https://github.com/python/mypy/issues/2087
set_by_cli.detector = None  # type: ignore


def has_default_value(option: str, value: Any) -> bool:
    """Does option have the default value?

    If the default value of option is not known, False is returned.

    :param str option: configuration variable being considered
    :param value: value of the configuration variable named option

    :returns: True if option has the default value, otherwise, False
    :rtype: bool

    """
    if helpful_parser is not None:
        return (option in helpful_parser.defaults and
                helpful_parser.defaults[option] == value)
    return False


def option_was_set(option: str, value: Any) -> bool:
    """Was option set by the user or does it differ from the default?

    :param str option: configuration variable being considered
    :param value: value of the configuration variable named option

    :returns: True if the option was set, otherwise, False
    :rtype: bool

    """
    # If an option is deprecated, it was effectively not set by the user.
    if option in DEPRECATED_OPTIONS:
        return False
    return set_by_cli(option) or not has_default_value(option, value)


def argparse_type(variable: Any) -> Type:
    """Return our argparse type function for a config variable (default: str)"""
    # pylint: disable=protected-access
    if helpful_parser is not None:
        for action in helpful_parser.parser._actions:
            if action.type is not None and action.dest == variable:
                return action.type
    return str
