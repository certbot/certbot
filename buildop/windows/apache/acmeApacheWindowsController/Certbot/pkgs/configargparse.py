import argparse
import glob
import os
import re
import sys
import types

if sys.version_info >= (3, 0):
    from io import StringIO
else:
    from StringIO import StringIO

if sys.version_info < (2, 7):
    from ordereddict import OrderedDict
else:
    from collections import OrderedDict


ACTION_TYPES_THAT_DONT_NEED_A_VALUE = (argparse._StoreTrueAction,
    argparse._StoreFalseAction, argparse._CountAction,
    argparse._StoreConstAction, argparse._AppendConstAction)


# global ArgumentParser instances
_parsers = {}

def init_argument_parser(name=None, **kwargs):
    """Creates a global ArgumentParser instance with the given name,
    passing any args other than "name" to the ArgumentParser constructor.
    This instance can then be retrieved using get_argument_parser(..)
    """

    if name is None:
        name = "default"

    if name in _parsers:
        raise ValueError(("kwargs besides 'name' can only be passed in the"
            " first time. '%s' ArgumentParser already exists: %s") % (
            name, _parsers[name]))

    kwargs.setdefault('formatter_class', argparse.ArgumentDefaultsHelpFormatter)
    kwargs.setdefault('conflict_handler', 'resolve')
    _parsers[name] = ArgumentParser(**kwargs)


def get_argument_parser(name=None, **kwargs):
    """Returns the global ArgumentParser instance with the given name. The 1st
    time this function is called, a new ArgumentParser instance will be created
    for the given name, and any args other than "name" will be passed on to the
    ArgumentParser constructor.
    """
    if name is None:
        name = "default"

    if len(kwargs) > 0 or name not in _parsers:
        init_argument_parser(name, **kwargs)

    return _parsers[name]


class ArgumentDefaultsRawHelpFormatter(
    argparse.ArgumentDefaultsHelpFormatter,
    argparse.RawTextHelpFormatter,
    argparse.RawDescriptionHelpFormatter):
    """HelpFormatter that adds default values AND doesn't do line-wrapping"""
    pass


class ConfigFileParser(object):
    """This abstract class can be extended to add support for new config file
    formats"""

    def get_syntax_description(self):
        """Returns a string describing the config file syntax."""
        raise NotImplementedError("get_syntax_description(..) not implemented")

    def parse(self, stream):
        """Parses the keys and values from a config file.

        NOTE: For keys that were specified to configargparse as
        action="store_true" or "store_false", the config file value must be
        one of: "yes", "no", "true", "false". Otherwise an error will be raised.

        Args:
            stream: A config file input stream (such as an open file object).

        Returns:
            OrderedDict of items where the keys have type string and the
            values have type either string or list (eg. to support config file
            formats like YAML which allow lists).
        """
        raise NotImplementedError("parse(..) not implemented")

    def serialize(self, items):
        """Does the inverse of config parsing by taking parsed values and
        converting them back to a string representing config file contents.

        Args:
            items: an OrderedDict of items to be converted to the config file
            format. Keys should be strings, and values should be either strings
            or lists.

        Returns:
            Contents of config file as a string
        """
        raise NotImplementedError("serialize(..) not implemented")


class ConfigFileParserException(Exception):
    """Raised when config file parsing failed."""


class DefaultConfigFileParser(ConfigFileParser):
    """Based on a simplified subset of INI and YAML formats. Here is the
    supported syntax:


        # this is a comment
        ; this is also a comment (.ini style)
        ---            # lines that start with --- are ignored (yaml style)
        -------------------
        [section]      # .ini-style section names are treated as comments

        # how to specify a key-value pair (all of these are equivalent):
        name value     # key is case sensitive: "Name" isn't "name"
        name = value   # (.ini style)  (white space is ignored, so name = value same as name=value)
        name: value    # (yaml style)
        --name value   # (argparse style)

        # how to set a flag arg (eg. arg which has action="store_true")
        --name
        name
        name = True    # "True" and "true" are the same

        # how to specify a list arg (eg. arg which has action="append")
        fruit = [apple, orange, lemon]
        indexes = [1, 12, 35 , 40]

    """

    def get_syntax_description(self):
        msg = ("Config file syntax allows: key=value, flag=true, stuff=[a,b,c] "
               "(for details, see syntax at https://goo.gl/R74nmi).")
        return msg

    def parse(self, stream):
        """Parses the keys + values from a config file."""

        items = OrderedDict()
        for i, line in enumerate(stream):
            line = line.strip()
            if not line or line[0] in ["#", ";", "["] or line.startswith("---"):
                continue
            white_space = "\\s*"
            key = "(?P<key>[^:=;#\s]+?)"
            value = white_space+"[:=\s]"+white_space+"(?P<value>.+?)"
            comment = white_space+"(?P<comment>\\s[;#].*)?"

            key_only_match = re.match("^" + key + comment + "$", line)
            if key_only_match:
                key = key_only_match.group("key")
                items[key] = "true"
                continue

            key_value_match = re.match("^"+key+value+comment+"$", line)
            if key_value_match:
                key = key_value_match.group("key")
                value = key_value_match.group("value")

                if value.startswith("[") and value.endswith("]"):
                    # handle special case of lists
                    value = [elem.strip() for elem in value[1:-1].split(",")]

                items[key] = value
                continue

            raise ConfigFileParserException("Unexpected line %s in %s: %s" % (i,
                getattr(stream, 'name', 'stream'), line))
        return items

    def serialize(self, items):
        """Does the inverse of config parsing by taking parsed values and
        converting them back to a string representing config file contents.
        """
        r = StringIO()
        for key, value in items.items():
            if isinstance(value, list):
                # handle special case of lists
                value = "["+", ".join(map(str, value))+"]"
            r.write("%s = %s\n" % (key, value))
        return r.getvalue()


class YAMLConfigFileParser(ConfigFileParser):
    """Parses YAML config files. Depends on the PyYAML module.
    https://pypi.python.org/pypi/PyYAML
    """

    def get_syntax_description(self):
        msg = ("The config file uses YAML syntax and must represent a YAML "
            "'mapping' (for details, see http://learn.getgrav.org/advanced/yaml).")
        return msg

    def _load_yaml(self):
        """lazy-import PyYAML so that configargparse doesn't have to dependend
        on it unless this parser is used."""
        try:
            import yaml
        except ImportError:
            raise ConfigFileParserException("Could not import yaml. "
                "It can be installed by running 'pip install PyYAML'")

        return yaml

    def parse(self, stream):
        """Parses the keys and values from a config file."""
        yaml = self._load_yaml()

        try:
            parsed_obj = yaml.safe_load(stream)
        except Exception as e:
            raise ConfigFileParserException("Couldn't parse config file: %s" % e)

        if not isinstance(parsed_obj, dict):
            raise ConfigFileParserException("The config file doesn't appear to "
                "contain 'key: value' pairs (aka. a YAML mapping). "
                "yaml.load('%s') returned type '%s' instead of 'dict'." % (
                getattr(stream, 'name', 'stream'),  type(parsed_obj).__name__))

        result = OrderedDict()
        for key, value in parsed_obj.items():
            if isinstance(value, list):
                result[key] = value
            else:
                result[key] = str(value)

        return result


    def serialize(self, items, default_flow_style=False):
        """Does the inverse of config parsing by taking parsed values and
        converting them back to a string representing config file contents.

        Args:
            default_flow_style: defines serialization format (see PyYAML docs)
        """

        # lazy-import so there's no dependency on yaml unless this class is used
        yaml = self._load_yaml()

        # it looks like ordering can't be preserved: http://pyyaml.org/ticket/29
        items = dict(items)
        return yaml.dump(items, default_flow_style=default_flow_style)


# used while parsing args to keep track of where they came from
_COMMAND_LINE_SOURCE_KEY = "command_line"
_ENV_VAR_SOURCE_KEY = "environment_variables"
_CONFIG_FILE_SOURCE_KEY = "config_file"
_DEFAULTS_SOURCE_KEY = "defaults"


class ArgumentParser(argparse.ArgumentParser):
    """Drop-in replacement for argparse.ArgumentParser that adds support for
    environment variables and .ini or .yaml-style config files.
    """

    def __init__(self,
        add_config_file_help=True,
        add_env_var_help=True,
        auto_env_var_prefix=None,
        default_config_files=[],
        ignore_unknown_config_file_keys=False,
        config_file_parser_class=DefaultConfigFileParser,
        args_for_setting_config_path=[],
        config_arg_is_required=False,
        config_arg_help_message="config file path",
        args_for_writing_out_config_file=[],
        write_out_config_file_arg_help_message="takes the current command line "
            "args and writes them out to a config file at the given path, then "
            "exits",
        **kwargs
        ):

        """Supports args of the argparse.ArgumentParser constructor
        as **kwargs, as well as the following additional args.

        Additional Args:
            add_config_file_help: Whether to add a description of config file
                syntax to the help message.
            add_env_var_help: Whether to add something to the help message for
                args that can be set through environment variables.
            auto_env_var_prefix: If set to a string instead of None, all config-
                file-settable options will become also settable via environment
                variables whose names are this prefix followed by the config
                file key, all in upper case. (eg. setting this to "foo_" will
                allow an arg like "--my-arg" to also be set via the FOO_MY_ARG
                environment variable)
            default_config_files: When specified, this list of config files will
                be parsed in order, with the values from each config file
                taking precedence over pervious ones. This allows an application
                to look for config files in multiple standard locations such as
                the install directory, home directory, and current directory.
                Also, shell * syntax can be used to specify all conf files in a
                directory. For exmaple:
                ["/etc/conf/app_config.ini",
                 "/etc/conf/conf-enabled/*.ini",
                "~/.my_app_config.ini",
                "./app_config.txt"]
            ignore_unknown_config_file_keys: If true, settings that are found
                in a config file but don't correspond to any defined
                configargparse args will be ignored. If false, they will be
                processed and appended to the commandline like other args, and
                can be retrieved using parse_known_args() instead of parse_args()
            config_file_parser_class: configargparse.ConfigFileParser subclass
                which determines the config file format. configargparse comes
                with DefaultConfigFileParser and YAMLConfigFileParser.
            args_for_setting_config_path: A list of one or more command line
                args to be used for specifying the config file path
                (eg. ["-c", "--config-file"]). Default: []
            config_arg_is_required: When args_for_setting_config_path is set,
                set this to True to always require users to provide a config path.
            config_arg_help_message: the help message to use for the
                args listed in args_for_setting_config_path.
            args_for_writing_out_config_file: A list of one or more command line
                args to use for specifying a config file output path. If
                provided, these args cause configargparse to write out a config
                file with settings based on the other provided commandline args,
                environment variants and defaults, and then to exit.
                (eg. ["-w", "--write-out-config-file"]). Default: []
            write_out_config_file_arg_help_message: The help message to use for
                the args in args_for_writing_out_config_file.
        """
        self._add_config_file_help = add_config_file_help
        self._add_env_var_help = add_env_var_help
        self._auto_env_var_prefix = auto_env_var_prefix

        argparse.ArgumentParser.__init__(self, **kwargs)

        # parse the additional args
        if config_file_parser_class is None:
            self._config_file_parser = DefaultConfigFileParser()
        else:
            self._config_file_parser = config_file_parser_class()

        self._default_config_files = default_config_files
        self._ignore_unknown_config_file_keys = ignore_unknown_config_file_keys
        if args_for_setting_config_path:
            self.add_argument(*args_for_setting_config_path, dest="config_file",
                required=config_arg_is_required, help=config_arg_help_message,
                is_config_file_arg=True)

        if args_for_writing_out_config_file:
            self.add_argument(*args_for_writing_out_config_file,
                dest="write_out_config_file_to_this_path",
                metavar="CONFIG_OUTPUT_PATH",
                help=write_out_config_file_arg_help_message,
                is_write_out_config_file_arg=True)

    def parse_args(self, args = None, namespace = None,
                   config_file_contents = None, env_vars = os.environ):
        """Supports all the same args as the ArgumentParser.parse_args(..),
        as well as the following additional args.

        Additional Args:
            args: a list of args as in argparse, or a string (eg. "-x -y bla")
            config_file_contents: String. Used for testing.
            env_vars: Dictionary. Used for testing.
        """
        args, argv = self.parse_known_args(args = args,
            namespace = namespace,
            config_file_contents = config_file_contents,
            env_vars = env_vars)
        if argv:
            self.error('unrecognized arguments: %s' % ' '.join(argv))
        return args


    def parse_known_args(self, args = None, namespace = None,
                         config_file_contents = None, env_vars = os.environ):
        """Supports all the same args as the ArgumentParser.parse_args(..),
        as well as the following additional args.

        Additional Args:
            args: a list of args as in argparse, or a string (eg. "-x -y bla")
            config_file_contents: String. Used for testing.
            env_vars: Dictionary. Used for testing.
        """
        if args is None:
            args = sys.argv[1:]
        elif isinstance(args, str):
            args = args.split()
        else:
            args = list(args)

        # normalize args by converting args like --key=value to --key value
        normalized_args = list()
        for arg in args:
            if arg and arg[0] in self.prefix_chars and '=' in arg:
                key, value =  arg.split('=', 1)
                normalized_args.append(key)
                normalized_args.append(value)
            else:
                normalized_args.append(arg)
        args = normalized_args

        for a in self._actions:
            a.is_positional_arg = not a.option_strings

        # maps a string describing the source (eg. env var) to a settings dict
        # to keep track of where values came from (used by print_values()).
        # The settings dicts for env vars and config files will then map
        # the config key to an (argparse Action obj, string value) 2-tuple.
        self._source_to_settings = OrderedDict()
        if args:
            a_v_pair = (None, list(args))  # copy args list to isolate changes
            self._source_to_settings[_COMMAND_LINE_SOURCE_KEY] = {'': a_v_pair}

        # handle auto_env_var_prefix __init__ arg by setting a.env_var as needed
        if self._auto_env_var_prefix is not None:
            for a in self._actions:
                config_file_keys = self.get_possible_config_keys(a)
                if config_file_keys and not (a.env_var or a.is_positional_arg
                    or a.is_config_file_arg or a.is_write_out_config_file_arg or
                    isinstance(a, argparse._VersionAction) or
                    isinstance(a, argparse._HelpAction)):
                    stripped_config_file_key = config_file_keys[0].strip(
                        self.prefix_chars)
                    a.env_var = (self._auto_env_var_prefix +
                                 stripped_config_file_key).replace('-', '_').upper()

        # add env var settings to the commandline that aren't there already
        env_var_args = []
        actions_with_env_var_values = [a for a in self._actions
            if not a.is_positional_arg and a.env_var and a.env_var in env_vars
                and not already_on_command_line(args, a.option_strings)]
        for action in actions_with_env_var_values:
            key = action.env_var
            value = env_vars[key]
            # Make list-string into list.
            if action.nargs or isinstance(action, argparse._AppendAction):
                element_capture = re.match('\[(.*)\]', value)
                if element_capture:
                    value = [val.strip() for val in element_capture.group(1).split(',') if val.strip()]
            env_var_args += self.convert_item_to_command_line_arg(
                action, key, value)

        args = args + env_var_args

        if env_var_args:
            self._source_to_settings[_ENV_VAR_SOURCE_KEY] = OrderedDict(
                [(a.env_var, (a, env_vars[a.env_var]))
                    for a in actions_with_env_var_values])


        # before parsing any config files, check if -h was specified.
        supports_help_arg = any(
            a for a in self._actions if isinstance(a, argparse._HelpAction))
        skip_config_file_parsing = supports_help_arg and (
            "-h" in args or "--help" in args)

        # prepare for reading config file(s)
        known_config_keys = dict((config_key, action) for action in self._actions
            for config_key in self.get_possible_config_keys(action))

        # open the config file(s)
        config_streams = []
        if config_file_contents is not None:
            stream = StringIO(config_file_contents)
            stream.name = "method arg"
            config_streams = [stream]
        elif not skip_config_file_parsing:
            config_streams = self._open_config_files(args)

        # parse each config file
        for stream in reversed(config_streams):
            try:
                config_items = self._config_file_parser.parse(stream)
            except ConfigFileParserException as e:
                self.error(e)
            finally:
                if hasattr(stream, "close"):
                    stream.close()

            # add each config item to the commandline unless it's there already
            config_args = []
            for key, value in config_items.items():
                if key in known_config_keys:
                    action = known_config_keys[key]
                    discard_this_key = already_on_command_line(
                        args, action.option_strings)
                else:
                    action = None
                    discard_this_key = self._ignore_unknown_config_file_keys or \
                        already_on_command_line(
                            args,
                            [self.get_command_line_key_for_unknown_config_file_setting(key)])

                if not discard_this_key:
                    config_args += self.convert_item_to_command_line_arg(
                        action, key, value)
                    source_key = "%s|%s" %(_CONFIG_FILE_SOURCE_KEY, stream.name)
                    if source_key not in self._source_to_settings:
                        self._source_to_settings[source_key] = OrderedDict()
                    self._source_to_settings[source_key][key] = (action, value)

            args = args + config_args


        # save default settings for use by print_values()
        default_settings = OrderedDict()
        for action in self._actions:
            cares_about_default_value = (not action.is_positional_arg or
                action.nargs in [OPTIONAL, ZERO_OR_MORE])
            if (already_on_command_line(args, action.option_strings) or
                    not cares_about_default_value or
                    action.default is None or
                    action.default == SUPPRESS or
                    isinstance(action, ACTION_TYPES_THAT_DONT_NEED_A_VALUE)):
                continue
            else:
                if action.option_strings:
                    key = action.option_strings[-1]
                else:
                    key = action.dest
                default_settings[key] = (action, str(action.default))

        if default_settings:
            self._source_to_settings[_DEFAULTS_SOURCE_KEY] = default_settings

        # parse all args (including commandline, config file, and env var)
        namespace, unknown_args = argparse.ArgumentParser.parse_known_args(
            self, args=args, namespace=namespace)
        # handle any args that have is_write_out_config_file_arg set to true
        # check if the user specified this arg on the commandline
        output_file_paths = [getattr(namespace, a.dest, None) for a in self._actions
                             if getattr(a, "is_write_out_config_file_arg", False)]
        output_file_paths = [a for a in output_file_paths if a is not None]
        self.write_config_file(namespace, output_file_paths, exit_after=True)
        return namespace, unknown_args

    def write_config_file(self, parsed_namespace, output_file_paths, exit_after=False):
        """Write the given settings to output files.

        Args:
            parsed_namespace: namespace object created within parse_known_args()
            output_file_paths: any number of file paths to write the config to
            exit_after: whether to exit the program after writing the config files
        """
        for output_file_path in output_file_paths:
            # validate the output file path
            try:
                with open(output_file_path, "w") as output_file:
                    pass
            except IOError as e:
                raise ValueError("Couldn't open %s for writing: %s" % (
                    output_file_path, e))
        if output_file_paths:
            # generate the config file contents
            config_items = self.get_items_for_config_file_output(
                self._source_to_settings, parsed_namespace)
            file_contents = self._config_file_parser.serialize(config_items)
            for output_file_path in output_file_paths:
                with open(output_file_path, "w") as output_file:
                    output_file.write(file_contents)
            message = "Wrote config file to " + ", ".join(output_file_paths)
            if exit_after:
                self.exit(0, message)
            else:
                print(message)


    def get_command_line_key_for_unknown_config_file_setting(self, key):
        """Compute a commandline arg key to be used for a config file setting
        that doesn't correspond to any defined configargparse arg (and so
        doesn't have a user-specified commandline arg key).

        Args:
            key: The config file key that was being set.
        """
        key_without_prefix_chars = key.strip(self.prefix_chars)
        command_line_key = self.prefix_chars[0]*2 + key_without_prefix_chars

        return command_line_key

    def get_items_for_config_file_output(self, source_to_settings,
                                         parsed_namespace):
        """Converts the given settings back to a dictionary that can be passed
        to ConfigFormatParser.serialize(..).

        Args:
            source_to_settings: the dictionary described in parse_known_args()
            parsed_namespace: namespace object created within parse_known_args()
        Returns:
            an OrderedDict where keys are strings and values are either strings
            or lists
        """
        config_file_items = OrderedDict()
        for source, settings in source_to_settings.items():
            if source == _COMMAND_LINE_SOURCE_KEY:
                _, existing_command_line_args = settings['']
                for action in self._actions:
                    config_file_keys = self.get_possible_config_keys(action)
                    if config_file_keys and not action.is_positional_arg and \
                        already_on_command_line(existing_command_line_args,
                                                action.option_strings):
                        value = getattr(parsed_namespace, action.dest, None)
                        if value is not None:
                            if isinstance(value, bool):
                                value = str(value).lower()
                            config_file_items[config_file_keys[0]] = value

            elif source == _ENV_VAR_SOURCE_KEY:
                for key, (action, value) in settings.items():
                    config_file_keys = self.get_possible_config_keys(action)
                    if config_file_keys:
                        value = getattr(parsed_namespace, action.dest, None)
                        if value is not None:
                            config_file_items[config_file_keys[0]] = value
            elif source.startswith(_CONFIG_FILE_SOURCE_KEY):
                for key, (action, value) in settings.items():
                    config_file_items[key] = value
            elif source == _DEFAULTS_SOURCE_KEY:
                for key, (action, value) in settings.items():
                    config_file_keys = self.get_possible_config_keys(action)
                    if config_file_keys:
                        value = getattr(parsed_namespace, action.dest, None)
                        if value is not None:
                            config_file_items[config_file_keys[0]] = value
        return config_file_items

    def convert_item_to_command_line_arg(self, action, key, value):
        """Converts a config file or env var key + value to a list of
        commandline args to append to the commandline.

        Args:
            action: The argparse Action object for this setting, or None if this
                config file setting doesn't correspond to any defined
                configargparse arg.
            key: string (config file key or env var name)
            value: parsed value of type string or list
        """
        args = []

        if action is None:
            command_line_key = \
                self.get_command_line_key_for_unknown_config_file_setting(key)
        else:
            command_line_key = action.option_strings[-1]

        # handle boolean value
        if action is not None and isinstance(action, ACTION_TYPES_THAT_DONT_NEED_A_VALUE):
            if value.lower() in ("true", "yes", "1"):
                args.append( command_line_key )
            elif value.lower() in ("false", "no", "0"):
                # don't append when set to "false" / "no"
                pass
            else:
                self.error("Unexpected value for %s: '%s'. Expecting 'true', "
                           "'false', 'yes', 'no', '1' or '0'" % (key, value))
        elif isinstance(value, list):
            if action is None or isinstance(action, argparse._AppendAction):
                for list_elem in value:
                    args.append( command_line_key )
                    args.append( str(list_elem) )
            elif (isinstance(action, argparse._StoreAction) and action.nargs in ('+', '*')) or (
                isinstance(action.nargs, int) and action.nargs > 1):
                args.append( command_line_key )
                for list_elem in value:
                    args.append( str(list_elem) )
            else:
                self.error(("%s can't be set to a list '%s' unless its action type is changed "
                            "to 'append' or nargs is set to '*', '+', or > 1") % (key, value))
        elif isinstance(value, str):
            args.append( command_line_key )
            args.append( value )
        else:
            raise ValueError("Unexpected value type %s for value: %s" % (
                type(value), value))

        return args

    def get_possible_config_keys(self, action):
        """This method decides which actions can be set in a config file and
        what their keys will be. It returns a list of 0 or more config keys that
        can be used to set the given action's value in a config file.
        """
        keys = []

        # Do not write out the config options for writing out a config file
        if getattr(action, 'is_write_out_config_file_arg', None):
            return keys

        for arg in action.option_strings:
            if any([arg.startswith(2*c) for c in self.prefix_chars]):
                keys += [arg[2:], arg] # eg. for '--bla' return ['bla', '--bla']

        return keys


    def _open_config_files(self, command_line_args):
        """Tries to parse config file path(s) from within command_line_args.
        Returns a list of opened config files, including files specified on the
        commandline as well as any default_config_files specified in the
        constructor that are present on disk.

        Args:
            command_line_args: List of all args (already split on spaces)
        """
        # open any default config files
        config_files = [open(f) for files in map(glob.glob, map(os.path.expanduser, self._default_config_files))
                        for f in files]

        # list actions with is_config_file_arg=True. Its possible there is more
        # than one such arg.
        user_config_file_arg_actions = [
            a for a in self._actions if getattr(a, "is_config_file_arg", False)]

        if not user_config_file_arg_actions:
            return config_files

        for action in user_config_file_arg_actions:
            # try to parse out the config file path by using a clean new
            # ArgumentParser that only knows this one arg/action.
            arg_parser = argparse.ArgumentParser(
                prefix_chars=self.prefix_chars,
                add_help=False)

            arg_parser._add_action(action)

            # make parser not exit on error by replacing its error method.
            # Otherwise it sys.exits(..) if, for example, config file
            # is_required=True and user doesn't provide it.
            def error_method(self, message):
                pass
            arg_parser.error = types.MethodType(error_method, arg_parser)

            # check whether the user provided a value
            parsed_arg = arg_parser.parse_known_args(args=command_line_args)
            if not parsed_arg:
                continue
            namespace, _ = parsed_arg
            user_config_file = getattr(namespace, action.dest, None)

            if not user_config_file:
                continue
            # validate the user-provided config file path
            user_config_file = os.path.expanduser(user_config_file)
            if not os.path.isfile(user_config_file):
                self.error('File not found: %s' % user_config_file)

            config_files += [open(user_config_file)]

        return config_files

    def format_values(self):
        """Returns a string with all args and settings and where they came from
        (eg. commandline, config file, enviroment variable or default)
        """
        source_key_to_display_value_map = {
            _COMMAND_LINE_SOURCE_KEY: "Command Line Args: ",
            _ENV_VAR_SOURCE_KEY: "Environment Variables:\n",
            _CONFIG_FILE_SOURCE_KEY: "Config File (%s):\n",
            _DEFAULTS_SOURCE_KEY: "Defaults:\n"
        }

        r = StringIO()
        for source, settings in self._source_to_settings.items():
            source = source.split("|")
            source = source_key_to_display_value_map[source[0]] % tuple(source[1:])
            r.write(source)
            for key, (action, value) in settings.items():
                if key:
                    r.write("  %-19s%s\n" % (key+":", value))
                else:
                    if isinstance(value, str):
                        r.write("  %s\n" % value)
                    elif isinstance(value, list):
                        r.write("  %s\n" % ' '.join(value))

        return r.getvalue()

    def print_values(self, file = sys.stdout):
        """Prints the format_values() string (to sys.stdout or another file)."""
        file.write(self.format_values())

    def format_help(self):
        msg = ""
        added_config_file_help = False
        added_env_var_help = False
        if self._add_config_file_help:
            default_config_files = self._default_config_files
            cc = 2*self.prefix_chars[0]  # eg. --
            config_settable_args = [(arg, a) for a in self._actions for arg in
                a.option_strings if self.get_possible_config_keys(a) and not
                (a.dest == "help" or a.is_config_file_arg or
                 a.is_write_out_config_file_arg)]
            config_path_actions = [a for a in
                self._actions if getattr(a, "is_config_file_arg", False)]

            if config_settable_args and (default_config_files or
                                         config_path_actions):
                self._add_config_file_help = False  # prevent duplication
                added_config_file_help = True

                msg += ("Args that start with '%s' (eg. %s) can also be set in "
                        "a config file") % (cc, config_settable_args[0][0])
                config_arg_string = " or ".join(a.option_strings[0]
                    for a in config_path_actions if a.option_strings)
                if config_arg_string:
                    config_arg_string = "specified via " + config_arg_string
                if default_config_files or config_arg_string:
                    msg += " (%s)." % " or ".join(tuple(default_config_files) +
                                                  tuple(filter(None, [config_arg_string])))
                msg += " " + self._config_file_parser.get_syntax_description()

        if self._add_env_var_help:
            env_var_actions = [(a.env_var, a) for a in self._actions
                               if getattr(a, "env_var", None)]
            for env_var, a in env_var_actions:
                env_var_help_string = "   [env var: %s]" % env_var
                if not a.help:
                    a.help = ""
                if env_var_help_string not in a.help:
                    a.help += env_var_help_string
                    added_env_var_help = True
                    self._add_env_var_help = False  # prevent duplication

        if added_env_var_help or added_config_file_help:
            value_sources = ["defaults"]
            if added_config_file_help:
                value_sources = ["config file values"] + value_sources
            if added_env_var_help:
                value_sources = ["environment variables"] + value_sources
            msg += (" If an arg is specified in more than one place, then "
                "commandline values override %s.") % (
                " which override ".join(value_sources))
        if msg:
            self.description = (self.description or "") + " " + msg

        return argparse.ArgumentParser.format_help(self)


def add_argument(self, *args, **kwargs):
    """
    This method supports the same args as ArgumentParser.add_argument(..)
    as well as the additional args below.

    Additional Args:
        env_var: If set, the value of this environment variable will override
            any config file or default values for this arg (but can itself
            be overriden on the commandline). Also, if auto_env_var_prefix is
            set in the constructor, this env var name will be used instead of
            the automatic name.
        is_config_file_arg: If True, this arg is treated as a config file path
            This provides an alternative way to specify config files in place of
            the ArgumentParser(fromfile_prefix_chars=..) mechanism.
            Default: False
        is_write_out_config_file_arg: If True, this arg will be treated as a
            config file path, and, when it is specified, will cause
            configargparse to write all current commandline args to this file
            as config options and then exit.
            Default: False
    """

    env_var = kwargs.pop("env_var", None)

    is_config_file_arg = kwargs.pop(
        "is_config_file_arg", None) or kwargs.pop(
        "is_config_file", None)  # for backward compat.

    is_write_out_config_file_arg = kwargs.pop(
        "is_write_out_config_file_arg", None)

    action = self.original_add_argument_method(*args, **kwargs)

    action.is_positional_arg = not action.option_strings
    action.env_var = env_var
    action.is_config_file_arg = is_config_file_arg
    action.is_write_out_config_file_arg = is_write_out_config_file_arg

    if action.is_positional_arg and env_var:
        raise ValueError("env_var can't be set for a positional arg.")
    if action.is_config_file_arg and not isinstance(action, argparse._StoreAction):
        raise ValueError("arg with is_config_file_arg=True must have "
                         "action='store'")
    if action.is_write_out_config_file_arg:
        error_prefix = "arg with is_write_out_config_file_arg=True "
        if not isinstance(action, argparse._StoreAction):
            raise ValueError(error_prefix + "must have action='store'")
        if is_config_file_arg:
                raise ValueError(error_prefix + "can't also have "
                                                "is_config_file_arg=True")

    return action


def already_on_command_line(existing_args_list, potential_command_line_args):
    """Utility method for checking if any of the potential_command_line_args is
    already present in existing_args.
    """
    return any(potential_arg in existing_args_list
               for potential_arg in potential_command_line_args)



# wrap ArgumentParser's add_argument(..) method with the one above
argparse._ActionsContainer.original_add_argument_method = argparse._ActionsContainer.add_argument
argparse._ActionsContainer.add_argument = add_argument


# add all public classes and constants from argparse module's namespace to this
# module's namespace so that the 2 modules are truly interchangeable
HelpFormatter = argparse.HelpFormatter
RawDescriptionHelpFormatter = argparse.RawDescriptionHelpFormatter
RawTextHelpFormatter = argparse.RawTextHelpFormatter
ArgumentDefaultsHelpFormatter = argparse.ArgumentDefaultsHelpFormatter
ArgumentError = argparse.ArgumentError
ArgumentTypeError = argparse.ArgumentTypeError
Action = argparse.Action
FileType = argparse.FileType
Namespace = argparse.Namespace
ONE_OR_MORE = argparse.ONE_OR_MORE
OPTIONAL = argparse.OPTIONAL
REMAINDER = argparse.REMAINDER
SUPPRESS = argparse.SUPPRESS
ZERO_OR_MORE = argparse.ZERO_OR_MORE

# deprecated PEP-8 incompatible API names.
initArgumentParser = init_argument_parser
getArgumentParser = get_argument_parser
getArgParser = get_argument_parser
getParser = get_argument_parser

# create shorter aliases for the key methods and class names
get_arg_parser = get_argument_parser
get_parser = get_argument_parser

ArgParser = ArgumentParser
Parser = ArgumentParser

argparse._ActionsContainer.add_arg = argparse._ActionsContainer.add_argument
argparse._ActionsContainer.add = argparse._ActionsContainer.add_argument

ArgumentParser.parse = ArgumentParser.parse_args
ArgumentParser.parse_known = ArgumentParser.parse_known_args

RawFormatter = RawDescriptionHelpFormatter
DefaultsFormatter = ArgumentDefaultsHelpFormatter
DefaultsRawFormatter = ArgumentDefaultsRawHelpFormatter
