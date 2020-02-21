"""Certbot command line util function"""
import argparse
import copy

import zope.interface.interface  # pylint: disable=unused-import

from acme import challenges
from certbot import interfaces
from certbot import util
from certbot import errors
from certbot.compat import os
from certbot._internal import constants


class _Default(object):
    """A class to use as a default to detect if a value is set by a user"""

    def __bool__(self):
        return False

    def __eq__(self, other):
        return isinstance(other, _Default)

    def __hash__(self):
        return id(_Default)

    def __nonzero__(self):
        return self.__bool__()


def read_file(filename, mode="rb"):
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
    except IOError as exc:
        raise argparse.ArgumentTypeError(exc.strerror)


def flag_default(name):
    """Default value for CLI flag."""
    # XXX: this is an internal housekeeping notion of defaults before
    # argparse has been set up; it is not accurate for all flags.  Call it
    # with caution.  Plugin defaults are missing, and some things are using
    # defaults defined in this file, not in constants.py :(
    return copy.deepcopy(constants.CLI_DEFAULTS[name])


def config_help(name, hidden=False):
    """Extract the help message for an `.IConfig` attribute."""
    if hidden:
        return argparse.SUPPRESS
    field = interfaces.IConfig.__getitem__(name)  # type: zope.interface.interface.Attribute
    return field.__doc__


class HelpfulArgumentGroup(object):
    """Emulates an argparse group for use with HelpfulArgumentParser.

    This class is used in the add_group method of HelpfulArgumentParser.
    Command line arguments can be added to the group, but help
    suppression and default detection is applied by
    HelpfulArgumentParser when necessary.

    """
    def __init__(self, helpful_arg_parser, topic):
        self._parser = helpful_arg_parser
        self._topic = topic

    def add_argument(self, *args, **kwargs):
        """Add a new command line argument to the argument group."""
        self._parser.add(self._topic, *args, **kwargs)


class CustomHelpFormatter(argparse.HelpFormatter):
    """This is a clone of ArgumentDefaultsHelpFormatter, with bugfixes.

    In particular we fix https://bugs.python.org/issue28742
    """

    def _get_help_string(self, action):
        helpstr = action.help
        if '%(default)' not in action.help and '(default:' not in action.help:
            if action.default != argparse.SUPPRESS:
                defaulting_nargs = [argparse.OPTIONAL, argparse.ZERO_OR_MORE]
                if action.option_strings or action.nargs in defaulting_nargs:
                    helpstr += ' (default: %(default)s)'
        return helpstr


class _DomainsAction(argparse.Action):
    """Action class for parsing domains."""

    def __call__(self, parser, namespace, domain, option_string=None):
        """Just wrap add_domains in argparseese."""
        add_domains(namespace, domain)


def add_domains(args_or_config, domains):
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
    validated_domains = []
    for domain in domains.split(","):
        domain = util.enforce_domain_sanity(domain.strip())
        validated_domains.append(domain)
        if domain not in args_or_config.domains:
            args_or_config.domains.append(domain)

    return validated_domains


class CaseInsensitiveList(list):
    """A list that will ignore case when searching.

    This class is passed to the `choices` argument of `argparse.add_arguments`
    through the `helpful` wrapper. It is necessary due to special handling of
    command line arguments by `set_by_cli` in which the `type_func` is not applied."""
    def __contains__(self, element):
        return super(CaseInsensitiveList, self).__contains__(element.lower())


def _user_agent_comment_type(value):
    if "(" in value or ")" in value:
        raise argparse.ArgumentTypeError("may not contain parentheses")
    return value


class _EncodeReasonAction(argparse.Action):
    """Action class for parsing revocation reason."""

    def __call__(self, parser, namespace, reason, option_string=None):
        """Encodes the reason for certificate revocation."""
        code = constants.REVOCATION_REASONS[reason.lower()]
        setattr(namespace, self.dest, code)


def parse_preferred_challenges(pref_challs):
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

    def __call__(self, parser, namespace, pref_challs, option_string=None):
        try:
            challs = parse_preferred_challenges(pref_challs.split(","))
        except errors.Error as error:
            raise argparse.ArgumentError(self, str(error))
        namespace.pref_challs.extend(challs)


class _DeployHookAction(argparse.Action):
    """Action class for parsing deploy hooks."""

    def __call__(self, parser, namespace, values, option_string=None):
        renew_hook_set = namespace.deploy_hook != namespace.renew_hook
        if renew_hook_set and namespace.renew_hook != values:
            raise argparse.ArgumentError(
                self, "conflicts with --renew-hook value")
        namespace.deploy_hook = namespace.renew_hook = values


class _RenewHookAction(argparse.Action):
    """Action class for parsing renew hooks."""

    def __call__(self, parser, namespace, values, option_string=None):
        deploy_hook_set = namespace.deploy_hook is not None
        if deploy_hook_set and namespace.deploy_hook != values:
            raise argparse.ArgumentError(
                self, "conflicts with --deploy-hook value")
        namespace.renew_hook = values


def nonnegative_int(value):
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
