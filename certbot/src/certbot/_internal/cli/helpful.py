"""Certbot command line argument parser"""

import argparse
import functools
import sys
from typing import Any
from typing import Iterable
from typing import Optional
from typing import Union

import configargparse
from cryptography import x509

from certbot import crypto_util
from certbot import errors
from certbot import util
from certbot._internal import constants
from certbot._internal import hooks
from certbot._internal import san
from certbot._internal.cli.cli_constants import COMMAND_OVERVIEW
from certbot._internal.cli.cli_constants import HELP_AND_VERSION_USAGE
from certbot._internal.cli.cli_constants import SHORT_USAGE
from certbot._internal.cli.cli_utils import CustomHelpFormatter
from certbot._internal.cli.cli_utils import flag_default
from certbot._internal.cli.cli_utils import HelpfulArgumentGroup
from certbot._internal.cli.cli_utils import set_test_server_options
from certbot._internal.cli.verb_help import VERB_HELP
from certbot._internal.cli.verb_help import VERB_HELP_MAP
from certbot._internal.display import obj as display_obj
from certbot._internal.plugins import disco
from certbot.configuration import ArgumentSource
from certbot.configuration import NamespaceConfig


class HelpfulArgumentParser:
    """Argparse Wrapper.

    This class wraps argparse, adding the ability to make --help less
    verbose, and request help on specific subcategories at a time, eg
    'certbot --help security' for security options.

    """
    def __init__(self, args: list[str], plugins: Iterable[str]) -> None:
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
            "certificates": main.certificates,
            "delete": main.delete,
            "enhance": main.enhance,
            "reconfigure": main.reconfigure,
        }

        # Get notification function for printing
        self.notify = display_obj.NoninteractiveDisplay(sys.stdout).notification

        self.actions: list[configargparse.Action] = []

        # List of topics for which additional help can be provided
        HELP_TOPICS: list[Optional[str]] = ["all", "security", "paths", "automation", "testing"]
        HELP_TOPICS += list(self.VERBS) + self.COMMANDS_TOPICS + ["manage"]

        plugin_names: list[Optional[str]] = list(plugins)
        self.help_topics: list[Optional[str]] = HELP_TOPICS + plugin_names + [None]

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
        self.groups: dict[str, argparse._ArgumentGroup] = {}

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

    def remove_config_file_domains_for_renewal(self, config: NamespaceConfig) -> None:
        """Make "certbot renew" safe if domains are set in cli.ini."""
        # Works around https://github.com/certbot/certbot/issues/4096
        assert config.argument_sources is not None
        if (config.argument_sources['domains'] == ArgumentSource.CONFIG_FILE and
                self.verb == "renew"):
            config.domains = []

    def _build_sources_dict(self) -> dict[str, ArgumentSource]:
        # ConfigArgparse's get_source_to_settings_dict doesn't actually create
        # default entries for each argument with a default value, omitting many
        # args we'd otherwise care about. So in general, unless an argument was
        # specified in a config file/environment variable/command line arg,
        # consider it as having a "default" value
        result = { action.dest: ArgumentSource.DEFAULT for action in self.actions }

        source_to_settings_dict: dict[str, dict[str, tuple[configargparse.Action, str]]]
        source_to_settings_dict = self.parser.get_source_to_settings_dict()

        # We'll process the sources dict in order of each source's "priority",
        # i.e. the order in which ConfigArgparse ultimately sets argument
        # values:
        #   1. defaults (`result` already has everything marked as such)
        #   2. config files
        #   3. env vars (shouldn't be any)
        #   4. command line

        def update_result(settings_dict: dict[str, tuple[configargparse.Action, str]],
                          source: ArgumentSource) -> None:
            actions = [self._find_action_for_arg(arg) if action is None else action
                       for arg, (action, _) in settings_dict.items()]
            result.update({ action.dest: source for action in actions })

        # config file sources look like "config_file|<name of file>"
        for source_key in source_to_settings_dict:
            if source_key.startswith('config_file'):
                update_result(source_to_settings_dict[source_key], ArgumentSource.CONFIG_FILE)

        update_result(source_to_settings_dict.get('env_var', {}), ArgumentSource.ENV_VAR)

        # The command line settings dict is weird, so handle it separately
        if 'command_line' in source_to_settings_dict:
            settings_dict: dict[str, tuple[None, list[str]]]
            settings_dict = source_to_settings_dict['command_line'] # type: ignore
            (_, unprocessed_args) = settings_dict['']
            args = []
            for arg in unprocessed_args:
                # ignore non-arguments
                if not arg.startswith('-'):
                    continue

                # special case for config file argument, which we don't have an action for
                if arg in ['-c', '--config']:
                    result['config_dir'] = ArgumentSource.COMMAND_LINE
                    continue

                if '=' in arg:
                    arg = arg.split('=')[0]
                elif ' ' in arg:
                    arg = arg.split(' ')[0]

                if arg.startswith('--'):
                    args.append(arg)
                # for short args (ones that start with a single hyphen), handle
                # the case of multiple short args together, e.g. "-tvm"
                else:
                    for short_arg in arg[1:]:
                        args.append(f"-{short_arg}")

            for arg in args:
                # find the action corresponding to this arg
                action = self._find_action_for_arg(arg)
                result[action.dest] = ArgumentSource.COMMAND_LINE

        return result

    def _find_action_for_arg(self, arg: str) -> configargparse.Action:
        # Finds a configargparse Action which matches the given arg, where arg
        # can either be preceded by hyphens (as on the command line) or not (as
        # in config files)

        # if the argument doesn't have leading hyphens, prefix it so it can be
        # compared directly w/ action option strings
        if arg[0] != '-':
            arg = '--' + arg

        # first, check for exact matches
        for action in self.actions:
            if arg in action.option_strings:
                return action

        # now check for abbreviated (i.e. prefix) matches
        for action in self.actions:
            for option_string in action.option_strings:
                if option_string.startswith(arg):
                    return action

        raise AssertionError(f"Action corresponding to argument {arg} is None")

    def parse_args(self) -> NamespaceConfig:
        """Parses command line arguments and returns the result.

        :returns: parsed command line arguments
        :rtype: configuration.NamespaceConfig

        """
        parsed_args = self.parser.parse_args(self.args)
        parsed_args.func = self.VERBS[self.verb]
        parsed_args.verb = self.verb
        config = NamespaceConfig(parsed_args)
        config.set_argument_sources(self._build_sources_dict())

        self.remove_config_file_domains_for_renewal(config)

        # Do any post-parsing homework here

        if self.verb == "renew":
            if config.force_interactive:
                raise errors.Error(
                    "{0} cannot be used with renew".format(
                        constants.FORCE_INTERACTIVE_FLAG))
            config.noninteractive_mode = True

        if config.force_interactive and config.noninteractive_mode:
            raise errors.Error(
                "Flag for non-interactive mode and {0} conflict".format(
                    constants.FORCE_INTERACTIVE_FLAG))

        if config.staging or config.dry_run:
            self.set_test_server(config)

        if config.csr:
            self.handle_csr(config)

        if config.must_staple and not config.staple:
            config.staple = True

        if config.validate_hooks:
            hooks.validate_hooks(config)

        if config.allow_subset_of_names:
            if any(d.is_wildcard() for d in config.domains):
                raise errors.Error("Using --allow-subset-of-names with a"
                                   " wildcard domain is not supported.")

        if config.hsts and config.auto_hsts:
            raise errors.Error(
                "Parameters --hsts and --auto-hsts cannot be used simultaneously.")

        if isinstance(config.key_type, list) and len(config.key_type) > 1:
            raise errors.Error(
                "Only *one* --key-type type may be provided at this time.")

        return config

    def set_test_server(self, config: NamespaceConfig) -> None:
        """Updates server, break_my_certs, staging, tos, and
        register_unsafely_without_email in config as necessary to prepare
        to use the test server."""
        return set_test_server_options(self.verb, config)

    def handle_csr(self, config: NamespaceConfig) -> None:
        """Process a --csr flag."""
        if config.verb != "certonly":
            raise errors.Error("Currently, a CSR file may only be specified "
                               "when obtaining a new or replacement "
                               "via the certonly command. Please try the "
                               "certonly command instead.")
        if config.allow_subset_of_names:
            raise errors.Error("--allow-subset-of-names cannot be used with --csr")

        csrfile, contents = config.csr[0:2]
        _, util_csr, _ = crypto_util.import_csr_file(csrfile, contents)
        x509_req = x509.load_pem_x509_csr(util_csr.data)
        domains, _ = san.from_x509(x509_req.subject, x509_req.extensions)

        # The SANs from the CSR are added to the domains from command line flags as this config
        # setting is where main.certonly gets the list of identifiers to request.
        config.domains.extend(domains)

        if not domains:
            # TODO: add CN to domains instead:
            raise errors.Error(
                "Unfortunately, your CSR %s needs to have a SubjectAltName for every domain"
                % config.csr[0])

        config.actual_csr = util_csr

        # Check that the original values for --domain set by the user were
        # a subset of the domains listed in the CSR.
        if set(config.domains) != set(domains):
            raise errors.ConfigurationError(
                "Inconsistent requests:\nFrom the CSR: {0}\nFrom command line/config: {1}"
                .format(san.display(domains),
                        san.display(config.domains)))


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

    def add(self, topics: Optional[Union[list[Optional[str]], str]], *args: Any,
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
        self.actions.append(self._add(topics, *args, **kwargs))

    def _add(self, topics: Optional[Union[list[Optional[str]], str]], *args: Any,
            **kwargs: Any) -> configargparse.Action:
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
            return self.parser.add_argument(*args, **kwargs)

        if isinstance(topics, list):
            # if this flag can be listed in multiple sections, try to pick the one
            # that the user has asked for help about
            topic = self.help_arg if self.help_arg in topics else topics[0]
        else:
            topic = topics  # there's only one

        if not isinstance(topic, bool) and self.visible_topics[topic]:
            if topic in self.groups:
                group = self.groups[topic]
                return group.add_argument(*args, **kwargs)
            else:
                return self.parser.add_argument(*args, **kwargs)
        else:
            kwargs["help"] = argparse.SUPPRESS
            return self.parser.add_argument(*args, **kwargs)

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
                              ) -> dict[Optional[str], bool]:
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
