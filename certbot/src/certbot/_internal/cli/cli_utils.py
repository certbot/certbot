"""Certbot command line util function"""
import argparse
import copy
import glob
import inspect
from typing import Any
from typing import Iterable
from typing import Optional
from typing import Sequence
from typing import TYPE_CHECKING
from typing import Union

from acme import challenges
from certbot import configuration
from certbot import errors
from certbot._internal import constants
from certbot._internal import san
from certbot.compat import os

if TYPE_CHECKING:
    from certbot._internal.cli import helpful


def read_file(filename: str, mode: str = "rb") -> tuple[str, Any]:
    """Returns the given file's contents.

    :param str filename: path to file
    :param str mode: open mode (see `open`)

    :returns: absolute path of filename and its contents
    :rtype: tuple

    :raises argparse.ArgumentTypeError: File does not exist or is not readable.

    """
    try:
        filename = os.path.abspath(filename)
        with open(filename, mode) as the_file:
            contents = the_file.read()
        return filename, contents
    except OSError as exc:
        raise argparse.ArgumentTypeError(exc.strerror)


def flag_default(name: str) -> Any:
    """Default value for CLI flag."""
    # XXX: this is an internal housekeeping notion of defaults before
    # argparse has been set up; it is not accurate for all flags.  Call it
    # with caution.  Plugin defaults are missing, and some things are using
    # defaults defined in this file, not in constants.py :(
    return copy.deepcopy(constants.CLI_DEFAULTS[name])


def config_help(name: str, hidden: bool = False) -> Optional[str]:
    """Extract the help message for a `configuration.NamespaceConfig` property docstring."""
    if hidden:
        return argparse.SUPPRESS
    return inspect.getdoc(getattr(configuration.NamespaceConfig, name))


class HelpfulArgumentGroup:
    """Emulates an argparse group for use with HelpfulArgumentParser.

    This class is used in the add_group method of HelpfulArgumentParser.
    Command line arguments can be added to the group, but help
    suppression and default detection is applied by
    HelpfulArgumentParser when necessary.

    """
    def __init__(self, helpful_arg_parser: "helpful.HelpfulArgumentParser", topic: str) -> None:
        self._parser = helpful_arg_parser
        self._topic = topic

    def add_argument(self, *args: Any, **kwargs: Any) -> None:
        """Add a new command line argument to the argument group."""
        self._parser.add(self._topic, *args, **kwargs)


class CustomHelpFormatter(argparse.HelpFormatter):
    """This is a clone of ArgumentDefaultsHelpFormatter, with bugfixes.

    In particular we fix https://bugs.python.org/issue28742
    """

    def _get_help_string(self, action: argparse.Action) -> Optional[str]:
        helpstr = action.help
        if action.help and '%(default)' not in action.help and '(default:' not in action.help:
            if action.default != argparse.SUPPRESS:
                defaulting_nargs = [argparse.OPTIONAL, argparse.ZERO_OR_MORE]
                if helpstr and (action.option_strings or action.nargs in defaulting_nargs):
                    helpstr += ' (default: %(default)s)'
        return helpstr


class _DomainsAction(argparse.Action):
    """Action class for parsing domains."""

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 domain: Union[str, Sequence[Any], None],
                 option_string: Optional[str] = None) -> None:
        """Just wrap add_domains in argparseese."""
        add_domains(namespace, str(domain) if domain is not None else None)


def add_domains(args_or_config: Union[argparse.Namespace, configuration.NamespaceConfig],
                domains: Optional[str]) -> list[san.DNSName]:
    """Registers new domains to be used during the current client run.

    Domains are not added to the list of requested domains if they have
    already been registered.

    :param args_or_config: parsed command line arguments
    :type args_or_config: argparse.Namespace or
        configuration.NamespaceConfig
    :param str domain: one or more comma separated domains

    :returns: domains after they have been normalized and validated
    :rtype: `list` of `str`

    """
    validated_domains: list[san.DNSName] = []
    if not domains:
        return validated_domains

    for d in domains.split(","):
        domain = san.DNSName(d.strip())
        validated_domains.append(domain)
        if domain not in args_or_config.domains:
            args_or_config.domains.append(domain)

    return validated_domains


class _IPAddressAction(argparse.Action):
    """Action class for parsing IP addresses."""

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: Union[str, Sequence[Any], None],
                 option_string: Optional[str] = None) -> None:
        match values:
            case None:
                return
            case str():
                # This will throw an exception if the IP address doesn't parse.
                namespace.ip_addresses.append(san.IPAddress(str(values)))
            case Sequence():
                for v in values:
                    # This will throw an exception if the IP address doesn't parse.
                    namespace.ip_addresses.append(san.IPAddress(str(v)))


class CaseInsensitiveList(list):
    """A list that will ignore case when searching.

    This class is passed to the `choices` argument of `argparse.add_arguments`
    through the `helpful` wrapper. It is necessary due to special handling of
    command line arguments by `set_by_cli` in which the `type_func` is not applied."""
    def __contains__(self, element: object) -> bool:
        if not isinstance(element, str):
            return False
        return super().__contains__(element.lower())


def _user_agent_comment_type(value: str) -> str:
    if "(" in value or ")" in value:
        raise argparse.ArgumentTypeError("may not contain parentheses")
    return value


class _EncodeReasonAction(argparse.Action):
    """Action class for parsing revocation reason."""

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 reason: Union[str, Sequence[Any], None],
                 option_string: Optional[str] = None) -> None:
        """Encodes the reason for certificate revocation."""
        if reason is None:
            raise ValueError("Unexpected null reason.")
        code = constants.REVOCATION_REASONS[str(reason).lower()]
        setattr(namespace, self.dest, code)


def parse_preferred_challenges(pref_challs: Iterable[str]) -> list[str]:
    """Translate and validate preferred challenges.

    :param pref_challs: list of preferred challenge types
    :type pref_challs: `list` of `str`

    :returns: validated list of preferred challenge types
    :rtype: `list` of `str`

    :raises errors.Error: if pref_challs is invalid

    """
    aliases = {"dns": "dns-01", "http": "http-01"}
    challs = [c.strip() for c in pref_challs]
    challs = [aliases.get(c, c) for c in challs]

    unrecognized = ", ".join(name for name in challs
                             if name not in challenges.Challenge.TYPES)
    if unrecognized:
        raise errors.Error(
            "Unrecognized challenges: {0}".format(unrecognized))
    return challs


class _PrefChallAction(argparse.Action):
    """Action class for parsing preferred challenges."""

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 pref_challs: Union[str, Sequence[Any], None],
                 option_string: Optional[str] = None) -> None:
        if pref_challs is None:
            raise ValueError("Unexpected null pref_challs.")
        try:
            challs = parse_preferred_challenges(str(pref_challs).split(","))
        except errors.Error as error:
            raise argparse.ArgumentError(self, str(error))
        namespace.pref_challs.extend(challs)


class _DeployHookAction(argparse.Action):
    """Action class for parsing deploy hooks."""

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: Union[str, Sequence[Any], None],
                 option_string: Optional[str] = None) -> None:
        renew_hook_set = namespace.deploy_hook != namespace.renew_hook
        if renew_hook_set and namespace.renew_hook != values:
            raise argparse.ArgumentError(
                self, "conflicts with --renew-hook value")
        namespace.deploy_hook = namespace.renew_hook = values


class _RenewHookAction(argparse.Action):
    """Action class for parsing renew hooks."""

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: Union[str, Sequence[Any], None],
                 option_string: Optional[str] = None) -> None:
        deploy_hook_set = namespace.deploy_hook is not None
        if deploy_hook_set and namespace.deploy_hook != values:
            raise argparse.ArgumentError(
                self, "conflicts with --deploy-hook value")
        namespace.renew_hook = values


def nonnegative_int(value: str) -> int:
    """Converts value to an int and checks that it is not negative.

    This function should used as the type parameter for argparse
    arguments.

    :param str value: value provided on the command line

    :returns: integer representation of value
    :rtype: int

    :raises argparse.ArgumentTypeError: if value isn't a non-negative integer

    """
    try:
        int_value = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("value must be an integer")

    if int_value < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return int_value

def set_test_server_options(verb: str, config: configuration.NamespaceConfig) -> None:
    """Updates server, break_my_certs, staging, tos, and
    register_unsafely_without_email in config as necessary to prepare
    to use the test server.

    We have --staging/--dry-run; perform sanity check and set config.server

    :param str verb: subcommand called

    :param config: parsed command line arguments
    :type config: configuration.NamespaceConfig

    :raises errors.Error: if non-default server is used and --staging is set
    :raises errors.Error: if inapplicable verb is used and --dry-run is set
    """

    # Flag combinations should produce these results:
    #                             | --staging      | --dry-run   |
    # ------------------------------------------------------------
    # | --server acme-v02         | Use staging    | Use staging |
    # | --server acme-staging-v02 | Use staging    | Use staging |
    # | --server <other>          | Conflict error | Use <other> |

    default_servers = (flag_default("server"), constants.STAGING_URI)

    if config.staging and config.server not in default_servers:
        raise errors.Error("--server value conflicts with --staging")

    if config.server == flag_default("server"):
        config.server = constants.STAGING_URI
        # If the account has already been loaded (such as by calling reconstitute before this),
        # clear it so that we don't try to use the prod account on the staging server.
        config.account = None

    if config.dry_run:
        if verb not in ["certonly", "renew", "reconfigure"]:
            raise errors.Error("--dry-run currently only works with the "
                               "'certonly' or 'renew' subcommands (%r)" % verb)
        config.break_my_certs = config.staging = True
        if glob.glob(os.path.join(config.config_dir, constants.ACCOUNTS_DIR, "*")):
            # The user has a prod account, but might not have a staging
            # one; we don't want to start trying to perform interactive registration
            config.tos = True
            config.register_unsafely_without_email = True
