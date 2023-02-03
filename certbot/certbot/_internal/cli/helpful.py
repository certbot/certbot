"""Certbot command line argument parser"""

import argparse
import copy
import functools
import glob
import sys
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Union

import configargparse

from certbot import crypto_util
from certbot import errors
from certbot import util
from certbot._internal import constants
from certbot._internal import hooks
from certbot._internal.cli.cli_constants import ARGPARSE_PARAMS_TO_REMOVE
from certbot._internal.cli.cli_constants import COMMAND_OVERVIEW
from certbot._internal.cli.cli_constants import EXIT_ACTIONS
from certbot._internal.cli.cli_constants import HELP_AND_VERSION_USAGE
from certbot._internal.cli.cli_constants import SHORT_USAGE
from certbot._internal.cli.cli_constants import ZERO_ARG_ACTIONS
from certbot._internal.cli.cli_utils import _Default
from certbot._internal.cli.cli_utils import add_domains
from certbot._internal.cli.cli_utils import CustomHelpFormatter
from certbot._internal.cli.cli_utils import flag_default
from certbot._internal.cli.cli_utils import HelpfulArgumentGroup
from certbot._internal.cli.verb_help import VERB_HELP
from certbot._internal.cli.verb_help import VERB_HELP_MAP
from certbot._internal.display import obj as display_obj
from certbot._internal.plugins import disco
from certbot.compat import os


class HelpfulArgumentParser:
    """Argparse Wrapper.

    This class wraps argparse, adding the ability to make --help less
    verbose, and request help on specific subcategories at a time, eg
    'certbot --help security' for security options.

    """
    def __init__(self, args: List[str], plugins: Iterable[str],
                 detect_defaults: bool = False) -> None:
        from certbot._internal import main
        self.VERBS = {
            "auth": main.certonly,
            "certonly": main.certonly,
            "run": main.run,
            "install": main.install,
            "plugins": main.plugins_cmd,
            "register": main.register,
            "update_account": main.update_account,
            "show_account": main.show_account,
            "unregister": main.unregister,
            "renew": main.renew,
            "revoke": main.revoke,
            "rollback": main.rollback,
            "everything": main.run,
            "update_symlinks": main.update_symlinks,
            "certificates": main.certificates,
            "delete": main.delete,
            "enhance": main.enhance,
            "reconfigure": main.reconfigure,
        }

        # Get notification function for printing
        self.notify = display_obj.NoninteractiveDisplay(sys.stdout).notification

        # List of topics for which additional help can be provided
        HELP_TOPICS: List[Optional[str]] = ["all", "security", "paths", "automation", "testing"]
        HELP_TOPICS += list(self.VERBS) + self.COMMANDS_TOPICS + ["manage"]

        plugin_names: List[Optional[str]] = list(plugins)
        self.help_topics: List[Optional[str]] = HELP_TOPICS + plugin_names + [None]

        self.detect_defaults = detect_defaults
        self.args = args

        if self.args and self.args[0] == 'help':
            self.args[0] = '--help'

        self.determine_verb()
        help1 = self.prescan_for_flag("-h", self.help_topics)
        help2 = self.prescan_for_flag("--help", self.help_topics)
        self.help_arg: Union[str, bool]
        if isinstance(help1, bool) and isinstance(help2, bool):
            self.help_arg = help1 or help2
        else:
            self.help_arg = help1 if isinstance(help1, str) else help2

        short_usage = self._usage_string(plugins, self.help_arg)

        self.visible_topics = self.determine_help_topics(self.help_arg)

        # elements are added by .add_group()
        self.groups: Dict[str, argparse._ArgumentGroup] = {}
        # elements are added by .parse_args()
        self.defaults: Dict[str, Any] = {}

        self.parser = configargparse.ArgParser(
            prog="certbot",
            usage=short_usage,
            formatter_class=CustomHelpFormatter,
            args_for_setting_config_path=["-c", "--config"],
            default_config_files=flag_default("config_files"),
            config_arg_help_message="path to config file (default: {0})".format(
                " and ".join(flag_default("config_files"))))

        # This is the only way to turn off overly verbose config flag documentation
        self.parser._add_config_file_help = False

        self.verb: str

    # Help that are synonyms for --help subcommands
    COMMANDS_TOPICS = ["command", "commands", "subcommand", "subcommands", "verbs"]

    def _list_subcommands(self) -> str:
        longest = max(len(v) for v in VERB_HELP_MAP)

        text = "The full list of available SUBCOMMANDS is:\n\n"
        for verb, props in sorted(VERB_HELP):
            doc = props.get("short", "")
            text += '{0:<{length}}     {1}\n'.format(verb, doc, length=longest)

        text += "\nYou can get more help on a specific subcommand with --help SUBCOMMAND\n"
        return text

    def _usage_string(self, plugins: Iterable[str], help_arg: Union[str, bool]) -> str:
        """Make usage strings late so that plugins can be initialised late

        :param plugins: all discovered plugins
        :param help_arg: False for none; True for --help; "TOPIC" for --help TOPIC
        :rtype: str
        :returns: a short usage string for the top of --help TOPIC)
        """
        if "nginx" in plugins:
            nginx_doc = "--nginx           Use the Nginx plugin for authentication & installation"
        else:
            nginx_doc = "(the certbot nginx plugin is not installed)"
        if "apache" in plugins:
            apache_doc = "--apache          Use the Apache plugin for authentication & installation"
        else:
            apache_doc = "(the certbot apache plugin is not installed)"

        usage = SHORT_USAGE
        if help_arg is True:
            self.notify(usage + COMMAND_OVERVIEW % (apache_doc, nginx_doc) + HELP_AND_VERSION_USAGE)
            sys.exit(0)
        elif help_arg in self.COMMANDS_TOPICS:
            self.notify(usage + self._list_subcommands())
            sys.exit(0)
        elif help_arg == "all":
            # if we're doing --help all, the OVERVIEW is part of the SHORT_USAGE at
            # the top; if we're doing --help someothertopic, it's OT so it's not
            usage += COMMAND_OVERVIEW % (apache_doc, nginx_doc)
        elif isinstance(help_arg, str):
            custom = VERB_HELP_MAP.get(help_arg, {}).get("usage", None)
            usage = custom if custom else usage
        # Only remaining case is help_arg == False, which gives effectively usage == SHORT_USAGE.

        return usage

    def remove_config_file_domains_for_renewal(self, parsed_args: argparse.Namespace) -> None:
        """Make "certbot renew" safe if domains are set in cli.ini."""
        # Works around https://github.com/certbot/certbot/issues/4096
        if self.verb == "renew":
            for source, flags in self.parser._source_to_settings.items(): # pylint: disable=protected-access
                if source.startswith("config_file") and "domains" in flags:
                    parsed_args.domains = _Default() if self.detect_defaults else []

    def parse_args(self) -> argparse.Namespace:
        """Parses command line arguments and returns the result.

        :returns: parsed command line arguments
        :rtype: argparse.Namespace

        """
        parsed_args = self.parser.parse_args(self.args)
        parsed_args.func = self.VERBS[self.verb]
        parsed_args.verb = self.verb

        self.remove_config_file_domains_for_renewal(parsed_args)

        if self.detect_defaults:
            return parsed_args

        self.defaults = {key: copy.deepcopy(self.parser.get_default(key))
                             for key in vars(parsed_args)}

        # Do any post-parsing homework here

        if self.verb == "renew":
            if parsed_args.force_interactive:
                raise errors.Error(
                    "{0} cannot be used with renew".format(
                        constants.FORCE_INTERACTIVE_FLAG))
            parsed_args.noninteractive_mode = True

        if parsed_args.force_interactive and parsed_args.noninteractive_mode:
            raise errors.Error(
                "Flag for non-interactive mode and {0} conflict".format(
                    constants.FORCE_INTERACTIVE_FLAG))

        if parsed_args.staging or parsed_args.dry_run:
            self.set_test_server(parsed_args)

        if parsed_args.csr:
            self.handle_csr(parsed_args)

        if parsed_args.must_staple:
            parsed_args.staple = True

        if parsed_args.validate_hooks:
            hooks.validate_hooks(parsed_args)

        if parsed_args.allow_subset_of_names:
            if any(util.is_wildcard_domain(d) for d in parsed_args.domains):
                raise errors.Error("Using --allow-subset-of-names with a"
                                   " wildcard domain is not supported.")

        if parsed_args.hsts and parsed_args.auto_hsts:
            raise errors.Error(
                "Parameters --hsts and --auto-hsts cannot be used simultaneously.")

        if isinstance(parsed_args.key_type, list) and len(parsed_args.key_type) > 1:
            raise errors.Error(
                "Only *one* --key-type type may be provided at this time.")

        return parsed_args

    def set_test_server(self, parsed_args: argparse.Namespace) -> None:
        """We have --staging/--dry-run; perform sanity check and set config.server"""

        # Flag combinations should produce these results:
        #                             | --staging      | --dry-run   |
        # ------------------------------------------------------------
        # | --server acme-v02         | Use staging    | Use staging |
        # | --server acme-staging-v02 | Use staging    | Use staging |
        # | --server <other>          | Conflict error | Use <other> |

        default_servers = (flag_default("server"), constants.STAGING_URI)

        if parsed_args.staging and parsed_args.server not in default_servers:
            raise errors.Error("--server value conflicts with --staging")

        if parsed_args.server in default_servers:
            parsed_args.server = constants.STAGING_URI

        if parsed_args.dry_run:
            if self.verb not in ["certonly", "renew"]:
                raise errors.Error("--dry-run currently only works with the "
                                   "'certonly' or 'renew' subcommands (%r)" % self.verb)
            parsed_args.break_my_certs = parsed_args.staging = True
            if glob.glob(os.path.join(parsed_args.config_dir, constants.ACCOUNTS_DIR, "*")):
                # The user has a prod account, but might not have a staging
                # one; we don't want to start trying to perform interactive registration
                parsed_args.tos = True
                parsed_args.register_unsafely_without_email = True

    def handle_csr(self, parsed_args: argparse.Namespace) -> None:
        """Process a --csr flag."""
        if parsed_args.verb != "certonly":
            raise errors.Error("Currently, a CSR file may only be specified "
                               "when obtaining a new or replacement "
                               "via the certonly command. Please try the "
                               "certonly command instead.")
        if parsed_args.allow_subset_of_names:
            raise errors.Error("--allow-subset-of-names cannot be used with --csr")

        csrfile, contents = parsed_args.csr[0:2]
        typ, csr, domains = crypto_util.import_csr_file(csrfile, contents)

        # This is not necessary for webroot to work, however,
        # obtain_certificate_from_csr requires parsed_args.domains to be set
        for domain in domains:
            add_domains(parsed_args, domain)

        if not domains:
            # TODO: add CN to domains instead:
            raise errors.Error(
                "Unfortunately, your CSR %s needs to have a SubjectAltName for every domain"
                % parsed_args.csr[0])

        parsed_args.actual_csr = (csr, typ)

        csr_domains = {d.lower() for d in domains}
        config_domains = set(parsed_args.domains)
        if csr_domains != config_domains:
            raise errors.ConfigurationError(
                "Inconsistent domain requests:\nFrom the CSR: {0}\nFrom command line/config: {1}"
                .format(", ".join(csr_domains), ", ".join(config_domains)))


    def determine_verb(self) -> None:
        """Determines the verb/subcommand provided by the user.

        This function works around some of the limitations of argparse.

        """
        if "-h" in self.args or "--help" in self.args:
            # all verbs double as help arguments; don't get them confused
            self.verb = "help"
            return

        for i, token in enumerate(self.args):
            if token in self.VERBS:
                verb = token
                if verb == "auth":
                    verb = "certonly"
                if verb == "everything":
                    verb = "run"
                self.verb = verb
                self.args.pop(i)
                return

        self.verb = "run"

    def prescan_for_flag(self, flag: str, possible_arguments: Iterable[Optional[str]]
                         ) -> Union[str, bool]:
        """Checks cli input for flags.

        Check for a flag, which accepts a fixed set of possible arguments, in
        the command line; we will use this information to configure argparse's
        help correctly.  Return the flag's argument, if it has one that matches
        the sequence @possible_arguments; otherwise return whether the flag is
        present.

        """
        if flag not in self.args:
            return False
        pos = self.args.index(flag)
        try:
            nxt = self.args[pos + 1]
            if nxt in possible_arguments:
                return nxt
        except IndexError:
            pass
        return True

    def add(self, topics: Optional[Union[List[Optional[str]], str]], *args: Any,
            **kwargs: Any) -> None:
        """Add a new command line argument.

        :param topics: str or [str] help topic(s) this should be listed under,
                       or None for options that don't fit under a specific
                       topic which will only be shown in "--help all" output.
                       The first entry determines where the flag lives in the
                       "--help all" output (None -> "optional arguments").
        :param list *args: the names of this argument flag
        :param dict **kwargs: various argparse settings for this argument

        """
        action = kwargs.get("action")
        if action is util.DeprecatedArgumentAction:
            # If the argument is deprecated through
            # certbot.util.add_deprecated_argument, it is not shown in the help
            # output and any value given to the argument is thrown away during
            # argument parsing. Because of this, we handle this case early
            # skipping putting the argument in different help topics and
            # handling default detection since these actions aren't needed and
            # can cause bugs like
            # https://github.com/certbot/certbot/issues/8495.
            self.parser.add_argument(*args, **kwargs)
            return

        if isinstance(topics, list):
            # if this flag can be listed in multiple sections, try to pick the one
            # that the user has asked for help about
            topic = self.help_arg if self.help_arg in topics else topics[0]
        else:
            topic = topics  # there's only one

        if self.detect_defaults:
            kwargs = self.modify_kwargs_for_default_detection(**kwargs)

        if not isinstance(topic, bool) and self.visible_topics[topic]:
            if topic in self.groups:
                group = self.groups[topic]
                group.add_argument(*args, **kwargs)
            else:
                self.parser.add_argument(*args, **kwargs)
        else:
            kwargs["help"] = argparse.SUPPRESS
            self.parser.add_argument(*args, **kwargs)

    def modify_kwargs_for_default_detection(self, **kwargs: Any) -> Dict[str, Any]:
        """Modify an arg so we can check if it was set by the user.

        Changes the parameters given to argparse when adding an argument
        so we can properly detect if the value was set by the user.

        :param dict kwargs: various argparse settings for this argument

        :returns: a modified versions of kwargs
        :rtype: dict

        """
        action = kwargs.get("action", None)
        if action not in EXIT_ACTIONS:
            kwargs["action"] = ("store_true" if action in ZERO_ARG_ACTIONS else
                                "store")
            kwargs["default"] = _Default()
            for param in ARGPARSE_PARAMS_TO_REMOVE:
                kwargs.pop(param, None)

        return kwargs

    def add_deprecated_argument(self, argument_name: str, num_args: int) -> None:
        """Adds a deprecated argument with the name argument_name.

        Deprecated arguments are not shown in the help. If they are used
        on the command line, a warning is shown stating that the
        argument is deprecated and no other action is taken.

        :param str argument_name: Name of deprecated argument.
        :param int num_args: Number of arguments the option takes.

        """
        # certbot.util.add_deprecated_argument expects the normal add_argument
        # interface provided by argparse. This is what is given including when
        # certbot.util.add_deprecated_argument is used by plugins, however, in
        # that case the first argument to certbot.util.add_deprecated_argument
        # is certbot._internal.cli.HelpfulArgumentGroup.add_argument which
        # internally calls the add method of this class.
        #
        # The difference between the add method of this class and the standard
        # argparse add_argument method caused a bug in the past (see
        # https://github.com/certbot/certbot/issues/8495) so we use the same
        # code path here for consistency and to ensure it works. To do that, we
        # wrap the add method in a similar way to
        # HelpfulArgumentGroup.add_argument by providing a help topic (which in
        # this case is set to None).
        add_func = functools.partial(self.add, None)
        util.add_deprecated_argument(add_func, argument_name, num_args)

    def add_group(self, topic: str, verbs: Iterable[str] = (),
                  **kwargs: Any) -> HelpfulArgumentGroup:
        """Create a new argument group.

        This method must be called once for every topic, however, calls
        to this function are left next to the argument definitions for
        clarity.

        :param str topic: Name of the new argument group.
        :param str verbs: List of subcommands that should be documented as part of
                          this help group / topic

        :returns: The new argument group.
        :rtype: `HelpfulArgumentGroup`

        """
        if self.visible_topics[topic]:
            self.groups[topic] = self.parser.add_argument_group(topic, **kwargs)
            if self.help_arg:
                for v in verbs:
                    self.groups[topic].add_argument(v, help=VERB_HELP_MAP[v]["short"])
        return HelpfulArgumentGroup(self, topic)

    def add_plugin_args(self, plugins: disco.PluginsRegistry) -> None:
        """

        Let each of the plugins add its own command line arguments, which
        may or may not be displayed as help topics.

        """
        for name, plugin_ep in plugins.items():
            parser_or_group = self.add_group(name,
                                             description=plugin_ep.long_description)
            plugin_ep.plugin_cls.inject_parser_options(parser_or_group, name)

    def determine_help_topics(self, chosen_topic: Union[str, bool]
                              ) -> Dict[Optional[str], bool]:
        """

        The user may have requested help on a topic, return a dict of which
        topics to display. @chosen_topic has prescan_for_flag's return type

        :returns: dict

        """
        # topics maps each topic to whether it should be documented by
        # argparse on the command line
        if chosen_topic == "auth":
            chosen_topic = "certonly"
        if chosen_topic == "everything":
            chosen_topic = "run"
        if chosen_topic == "all":
            # Addition of condition closes #6209 (removal of duplicate route53 option).
            return {t: t != 'certbot-route53:auth' for t in self.help_topics}
        elif not chosen_topic:
            return {t: False for t in self.help_topics}
        return {t: t == chosen_topic for t in self.help_topics}
