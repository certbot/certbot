"""ApacheParser is a member object of the ApacheConfigurator class."""
import copy
import fnmatch
import logging
import os
import re
import subprocess
import sys

import six

from acme.magic_typing import Dict, List, Set  # pylint: disable=unused-import, no-name-in-module
from certbot import errors

logger = logging.getLogger(__name__)


class ApacheParser(object):
    # pylint: disable=too-many-public-methods
    """Class handles the fine details of parsing the Apache Configuration.

    .. todo:: Make parsing general... remove sites-available etc...

    :ivar str root: Normalized absolute path to the server root
        directory. Without trailing slash.
    :ivar set modules: All module names that are currently enabled.
    :ivar dict loc: Location to place directives, root - configuration origin,
        default - user config file, name - NameVirtualHost,

    """
    arg_var_interpreter = re.compile(r"\$\{[^ \}]*}")
    fnmatch_chars = set(["*", "?", "\\", "[", "]"])

    def __init__(self, aug, root, vhostroot=None, version=(2, 4),
                 configurator=None):
        # Note: Order is important here.

        # Needed for calling save() with reverter functionality that resides in
        # AugeasConfigurator superclass of ApacheConfigurator. This resolves
        # issues with aug.load() after adding new files / defines to parse tree
        self.configurator = configurator

        self.modules = set()  # type: Set[str]
        self.parser_paths = {}  # type: Dict[str, List[str]]
        self.variables = {}  # type: Dict[str, str]

        self.aug = aug
        # Find configuration root and make sure augeas can parse it.
        self.root = os.path.abspath(root)
        self.loc = {"root": self._find_config_root()}
        self.parse_file(self.loc["root"])

        if version >= (2, 4):
            # Look up variables from httpd and add to DOM if not already parsed
            self.update_runtime_variables()

        # This problem has been fixed in Augeas 1.0
        self.standardize_excl()

        # Parse LoadModule directives from configuration files
        self.parse_modules()

        # Set up rest of locations
        self.loc.update(self._set_locations())

        # list of the active include paths, before modifications
        self.existing_paths = copy.deepcopy(self.parser_paths)

        # Must also attempt to parse additional virtual host root
        if vhostroot:
            self.parse_file(os.path.abspath(vhostroot) + "/" +
                            self.configurator.option("vhost_files"))

        # check to see if there were unparsed define statements
        if version < (2, 4):
            if self.find_dir("Define", exclude=False):
                raise errors.PluginError("Error parsing runtime variables")

    def add_include(self, main_config, inc_path):
        """Add Include for a new configuration file if one does not exist

        :param str main_config: file path to main Apache config file
        :param str inc_path: path of file to include

        """
        if len(self.find_dir(case_i("Include"), inc_path)) == 0:
            logger.debug("Adding Include %s to %s",
                         inc_path, get_aug_path(main_config))
            self.add_dir(
                get_aug_path(main_config),
                "Include", inc_path)

            # Add new path to parser paths
            new_dir = os.path.dirname(inc_path)
            new_file = os.path.basename(inc_path)
            if new_dir in self.existing_paths.keys():
                # Add to existing path
                self.existing_paths[new_dir].append(new_file)
            else:
                # Create a new path
                self.existing_paths[new_dir] = [new_file]

    def add_mod(self, mod_name):
        """Shortcut for updating parser modules."""
        if mod_name + "_module" not in self.modules:
            self.modules.add(mod_name + "_module")
        if "mod_" + mod_name + ".c" not in self.modules:
            self.modules.add("mod_" + mod_name + ".c")

    def reset_modules(self):
        """Reset the loaded modules list. This is called from cleanup to clear
        temporarily loaded modules."""
        self.modules = set()
        self.update_modules()
        self.parse_modules()

    def parse_modules(self):
        """Iterates on the configuration until no new modules are loaded.

        ..todo:: This should be attempted to be done with a binary to avoid
            the iteration issue.  Else... parse and enable mods at same time.

        """
        mods = set()  # type: Set[str]
        matches = self.find_dir("LoadModule")
        iterator = iter(matches)
        # Make sure prev_size != cur_size for do: while: iteration
        prev_size = -1

        while len(mods) != prev_size:
            prev_size = len(mods)

            for match_name, match_filename in six.moves.zip(
                    iterator, iterator):
                mod_name = self.get_arg(match_name)
                mod_filename = self.get_arg(match_filename)
                if mod_name and mod_filename:
                    mods.add(mod_name)
                    mods.add(os.path.basename(mod_filename)[:-2] + "c")
                else:
                    logger.debug("Could not read LoadModule directive from " +
                                 "Augeas path: {0}".format(match_name[6:]))
        self.modules.update(mods)

    def update_runtime_variables(self):
        """Update Includes, Defines and Includes from httpd config dump data"""
        self.update_defines()
        self.update_includes()
        self.update_modules()

    def update_defines(self):
        """Get Defines from httpd process"""

        variables = dict()
        define_cmd = [self.configurator.option("ctl"), "-t", "-D",
                      "DUMP_RUN_CFG"]
        matches = self.parse_from_subprocess(define_cmd, r"Define: ([^ \n]*)")
        try:
            matches.remove("DUMP_RUN_CFG")
        except ValueError:
            return

        for match in matches:
            if match.count("=") > 1:
                logger.error("Unexpected number of equal signs in "
                             "runtime config dump.")
                raise errors.PluginError(
                    "Error parsing Apache runtime variables")
            parts = match.partition("=")
            variables[parts[0]] = parts[2]

        self.variables = variables

    def update_includes(self):
        """Get includes from httpd process, and add them to DOM if needed"""

        # Find_dir iterates over configuration for Include and IncludeOptional
        # directives to make sure we see the full include tree present in the
        # configuration files
        _ = self.find_dir("Include")

        inc_cmd = [self.configurator.option("ctl"), "-t", "-D",
                   "DUMP_INCLUDES"]
        matches = self.parse_from_subprocess(inc_cmd, r"\(.*\) (.*)")
        if matches:
            for i in matches:
                if not self.parsed_in_current(i):
                    self.parse_file(i)

    def update_modules(self):
        """Get loaded modules from httpd process, and add them to DOM"""

        mod_cmd = [self.configurator.option("ctl"), "-t", "-D",
                       "DUMP_MODULES"]
        matches = self.parse_from_subprocess(mod_cmd, r"(.*)_module")
        for mod in matches:
            self.add_mod(mod.strip())

    def parse_from_subprocess(self, command, regexp):
        """Get values from stdout of subprocess command

        :param list command: Command to run
        :param str regexp: Regexp for parsing

        :returns: list parsed from command output
        :rtype: list

        """
        stdout = self._get_runtime_cfg(command)
        return re.compile(regexp).findall(stdout)

    def _get_runtime_cfg(self, command):  # pylint: disable=no-self-use
        """Get runtime configuration info.
        :param command: Command to run

        :returns: stdout from command

        """
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True)
            stdout, stderr = proc.communicate()

        except (OSError, ValueError):
            logger.error(
                "Error running command %s for runtime parameters!%s",
                command, os.linesep)
            raise errors.MisconfigurationError(
                "Error accessing loaded Apache parameters: %s",
                command)
        # Small errors that do not impede
        if proc.returncode != 0:
            logger.warning("Error in checking parameter list: %s", stderr)
            raise errors.MisconfigurationError(
                "Apache is unable to check whether or not the module is "
                "loaded because Apache is misconfigured.")

        return stdout

    def filter_args_num(self, matches, args):  # pylint: disable=no-self-use
        """Filter out directives with specific number of arguments.

        This function makes the assumption that all related arguments are given
        in order.  Thus /files/apache/directive[5]/arg[2] must come immediately
        after /files/apache/directive[5]/arg[1]. Runs in 1 linear pass.

        :param string matches: Matches of all directives with arg nodes
        :param int args: Number of args you would like to filter

        :returns: List of directives that contain # of arguments.
            (arg is stripped off)

        """
        filtered = []
        if args == 1:
            for i in range(len(matches)):
                if matches[i].endswith("/arg"):
                    filtered.append(matches[i][:-4])
        else:
            for i in range(len(matches)):
                if matches[i].endswith("/arg[%d]" % args):
                    # Make sure we don't cause an IndexError (end of list)
                    # Check to make sure arg + 1 doesn't exist
                    if (i == (len(matches) - 1) or
                            not matches[i + 1].endswith("/arg[%d]" %
                                                        (args + 1))):
                        filtered.append(matches[i][:-len("/arg[%d]" % args)])

        return filtered

    def add_dir_to_ifmodssl(self, aug_conf_path, directive, args):
        """Adds directive and value to IfMod ssl block.

        Adds given directive and value along configuration path within
        an IfMod mod_ssl.c block.  If the IfMod block does not exist in
        the file, it is created.

        :param str aug_conf_path: Desired Augeas config path to add directive
        :param str directive: Directive you would like to add, e.g. Listen
        :param args: Values of the directive; str "443" or list of str
        :type args: list

        """
        # TODO: Add error checking code... does the path given even exist?
        #       Does it throw exceptions?
        if_mod_path = self._get_ifmod(aug_conf_path, "mod_ssl.c")
        # IfModule can have only one valid argument, so append after
        self.aug.insert(if_mod_path + "arg", "directive", False)
        nvh_path = if_mod_path + "directive[1]"
        self.aug.set(nvh_path, directive)
        if len(args) == 1:
            self.aug.set(nvh_path + "/arg", args[0])
        else:
            for i, arg in enumerate(args):
                self.aug.set("%s/arg[%d]" % (nvh_path, i + 1), arg)

    def _get_ifmod(self, aug_conf_path, mod):
        """Returns the path to <IfMod mod> and creates one if it doesn't exist.

        :param str aug_conf_path: Augeas configuration path
        :param str mod: module ie. mod_ssl.c

        """
        if_mods = self.aug.match(("%s/IfModule/*[self::arg='%s']" %
                                  (aug_conf_path, mod)))
        if len(if_mods) == 0:
            self.aug.set("%s/IfModule[last() + 1]" % aug_conf_path, "")
            self.aug.set("%s/IfModule[last()]/arg" % aug_conf_path, mod)
            if_mods = self.aug.match(("%s/IfModule/*[self::arg='%s']" %
                                      (aug_conf_path, mod)))
        # Strip off "arg" at end of first ifmod path
        return if_mods[0][:len(if_mods[0]) - 3]

    def add_dir(self, aug_conf_path, directive, args):
        """Appends directive to the end fo the file given by aug_conf_path.

        .. note:: Not added to AugeasConfigurator because it may depend
            on the lens

        :param str aug_conf_path: Augeas configuration path to add directive
        :param str directive: Directive to add
        :param args: Value of the directive. ie. Listen 443, 443 is arg
        :type args: list or str

        """
        self.aug.set(aug_conf_path + "/directive[last() + 1]", directive)
        if isinstance(args, list):
            for i, value in enumerate(args, 1):
                self.aug.set(
                    "%s/directive[last()]/arg[%d]" % (aug_conf_path, i), value)
        else:
            self.aug.set(aug_conf_path + "/directive[last()]/arg", args)

    def add_dir_beginning(self, aug_conf_path, dirname, args):
        """Adds the directive to the beginning of defined aug_conf_path.

        :param str aug_conf_path: Augeas configuration path to add directive
        :param str dirname: Directive to add
        :param args: Value of the directive. ie. Listen 443, 443 is arg
        :type args: list or str
        """
        first_dir = aug_conf_path + "/directive[1]"
        self.aug.insert(first_dir, "directive", True)
        self.aug.set(first_dir, dirname)
        if isinstance(args, list):
            for i, value in enumerate(args, 1):
                self.aug.set(first_dir + "/arg[%d]" % (i), value)
        else:
            self.aug.set(first_dir + "/arg", args)

    def add_comment(self, aug_conf_path, comment):
        """Adds the comment to the augeas path

        :param str aug_conf_path: Augeas configuration path to add directive
        :param str comment: Comment content

        """
        self.aug.set(aug_conf_path + "/#comment[last() + 1]", comment)

    def find_comments(self, arg, start=None):
        """Finds a comment with specified content from the provided DOM path

        :param str arg: Comment content to search
        :param str start: Beginning Augeas path to begin looking

        :returns: List of augeas paths containing the comment content
        :rtype: list

        """
        if not start:
            start = get_aug_path(self.root)

        comments = self.aug.match("%s//*[label() = '#comment']" % start)

        results = []
        for comment in comments:
            c_content = self.aug.get(comment)
            if c_content and arg in c_content:
                results.append(comment)
        return results

    def find_dir(self, directive, arg=None, start=None, exclude=True):
        """Finds directive in the configuration.

        Recursively searches through config files to find directives
        Directives should be in the form of a case insensitive regex currently

        .. todo:: arg should probably be a list
        .. todo:: arg search currently only supports direct matching. It does
            not handle the case of variables or quoted arguments. This should
            be adapted to use a generic search for the directive and then do a
            case-insensitive self.get_arg filter

        Note: Augeas is inherently case sensitive while Apache is case
        insensitive.  Augeas 1.0 allows case insensitive regexes like
        regexp(/Listen/, "i"), however the version currently supported
        by Ubuntu 0.10 does not.  Thus I have included my own case insensitive
        transformation by calling case_i() on everything to maintain
        compatibility.

        :param str directive: Directive to look for
        :param arg: Specific value directive must have, None if all should
                    be considered
        :type arg: str or None

        :param str start: Beginning Augeas path to begin looking
        :param bool exclude: Whether or not to exclude directives based on
            variables and enabled modules

        """
        # Cannot place member variable in the definition of the function so...
        if not start:
            start = get_aug_path(self.loc["root"])

        # No regexp code
        # if arg is None:
        #     matches = self.aug.match(start +
        # "//*[self::directive='" + directive + "']/arg")
        # else:
        #     matches = self.aug.match(start +
        # "//*[self::directive='" + directive +
        #   "']/* [self::arg='" + arg + "']")

        # includes = self.aug.match(start +
        # "//* [self::directive='Include']/* [label()='arg']")

        regex = "(%s)|(%s)|(%s)" % (case_i(directive),
                                    case_i("Include"),
                                    case_i("IncludeOptional"))
        matches = self.aug.match(
            "%s//*[self::directive=~regexp('%s')]" % (start, regex))

        if exclude:
            matches = self._exclude_dirs(matches)

        if arg is None:
            arg_suffix = "/arg"
        else:
            arg_suffix = "/*[self::arg=~regexp('%s')]" % case_i(arg)

        ordered_matches = []  # type: List[str]

        # TODO: Wildcards should be included in alphabetical order
        # https://httpd.apache.org/docs/2.4/mod/core.html#include
        for match in matches:
            dir_ = self.aug.get(match).lower()
            if dir_ == "include" or dir_ == "includeoptional":
                ordered_matches.extend(self.find_dir(
                    directive, arg,
                    self._get_include_path(self.get_arg(match + "/arg")),
                    exclude))
            # This additionally allows Include
            if dir_ == directive.lower():
                ordered_matches.extend(self.aug.match(match + arg_suffix))

        return ordered_matches

    def get_arg(self, match):
        """Uses augeas.get to get argument value and interprets result.

        This also converts all variables and parameters appropriately.

        """
        value = self.aug.get(match)

        # No need to strip quotes for variables, as apache2ctl already does
        # this, but we do need to strip quotes for all normal arguments.

        # Note: normal argument may be a quoted variable
        # e.g. strip now, not later
        if not value:
            return None
        else:
            value = value.strip("'\"")

        variables = ApacheParser.arg_var_interpreter.findall(value)

        for var in variables:
            # Strip off ${ and }
            try:
                value = value.replace(var, self.variables[var[2:-1]])
            except KeyError:
                raise errors.PluginError("Error Parsing variable: %s" % var)

        return value

    def _exclude_dirs(self, matches):
        """Exclude directives that are not loaded into the configuration."""
        filters = [("ifmodule", self.modules), ("ifdefine", self.variables)]

        valid_matches = []

        for match in matches:
            for filter_ in filters:
                if not self._pass_filter(match, filter_):
                    break
            else:
                valid_matches.append(match)
        return valid_matches

    def _pass_filter(self, match, filter_):
        """Determine if directive passes a filter.

        :param str match: Augeas path
        :param list filter: list of tuples of form
            [("lowercase if directive", set of relevant parameters)]

        """
        match_l = match.lower()
        last_match_idx = match_l.find(filter_[0])

        while last_match_idx != -1:
            # Check args
            end_of_if = match_l.find("/", last_match_idx)
            # This should be aug.get (vars are not used e.g. parser.aug_get)
            expression = self.aug.get(match[:end_of_if] + "/arg")

            if expression.startswith("!"):
                # Strip off "!"
                if expression[1:] in filter_[1]:
                    return False
            else:
                if expression not in filter_[1]:
                    return False

            last_match_idx = match_l.find(filter_[0], end_of_if)

        return True

    def _get_include_path(self, arg):
        """Converts an Apache Include directive into Augeas path.

        Converts an Apache Include directive argument into an Augeas
        searchable path

        .. todo:: convert to use os.path.join()

        :param str arg: Argument of Include directive

        :returns: Augeas path string
        :rtype: str

        """
        # Check to make sure only expected characters are used <- maybe remove
        # validChars = re.compile("[a-zA-Z0-9.*?_-/]*")
        # matchObj = validChars.match(arg)
        # if matchObj.group() != arg:
        #     logger.error("Error: Invalid regexp characters in %s", arg)
        #     return []

        # Remove beginning and ending quotes
        arg = arg.strip("'\"")

        # Standardize the include argument based on server root
        if not arg.startswith("/"):
            # Normpath will condense ../
            arg = os.path.normpath(os.path.join(self.root, arg))
        else:
            arg = os.path.normpath(arg)

        # Attempts to add a transform to the file if one does not already exist
        if os.path.isdir(arg):
            self.parse_file(os.path.join(arg, "*"))
        else:
            self.parse_file(arg)

        # Argument represents an fnmatch regular expression, convert it
        # Split up the path and convert each into an Augeas accepted regex
        # then reassemble
        split_arg = arg.split("/")
        for idx, split in enumerate(split_arg):
            if any(char in ApacheParser.fnmatch_chars for char in split):
                # Turn it into a augeas regex
                # TODO: Can this instead be an augeas glob instead of regex
                split_arg[idx] = ("* [label()=~regexp('%s')]" %
                                  self.fnmatch_to_re(split))
        # Reassemble the argument
        # Note: This also normalizes the argument /serverroot/ -> /serverroot
        arg = "/".join(split_arg)

        return get_aug_path(arg)

    def fnmatch_to_re(self, clean_fn_match):  # pylint: disable=no-self-use
        """Method converts Apache's basic fnmatch to regular expression.

        Assumption - Configs are assumed to be well-formed and only writable by
        privileged users.

        https://apr.apache.org/docs/apr/2.0/apr__fnmatch_8h_source.html
        http://apache2.sourcearchive.com/documentation/2.2.16-6/apr__fnmatch_8h_source.html

        :param str clean_fn_match: Apache style filename match, like globs

        :returns: regex suitable for augeas
        :rtype: str

        """
        if sys.version_info < (3, 6):
            # This strips off final /Z(?ms)
            return fnmatch.translate(clean_fn_match)[:-7]
        else:  # pragma: no cover
            # Since Python 3.6, it returns a different pattern like (?s:.*\.load)\Z
            return fnmatch.translate(clean_fn_match)[4:-3]

    def parse_file(self, filepath):
        """Parse file with Augeas

        Checks to see if file_path is parsed by Augeas
        If filepath isn't parsed, the file is added and Augeas is reloaded

        :param str filepath: Apache config file path

        """
        use_new, remove_old = self._check_path_actions(filepath)
        # Ensure that we have the latest Augeas DOM state on disk before
        # calling aug.load() which reloads the state from disk
        if self.configurator:
            self.configurator.ensure_augeas_state()
        # Test if augeas included file for Httpd.lens
        # Note: This works for augeas globs, ie. *.conf
        if use_new:
            inc_test = self.aug.match(
                "/augeas/load/Httpd['%s' =~ glob(incl)]" % filepath)
            if not inc_test:
                # Load up files
                # This doesn't seem to work on TravisCI
                # self.aug.add_transform("Httpd.lns", [filepath])
                if remove_old:
                    self._remove_httpd_transform(filepath)
                self._add_httpd_transform(filepath)
                self.aug.load()

    def parsed_in_current(self, filep):
        """Checks if the file path is parsed by current Augeas parser config
        ie. returns True if the file is found on a path that's found in live
        Augeas configuration.

        :param str filep: Path to match

        :returns: True if file is parsed in existing configuration tree
        :rtype: bool
        """
        return self._parsed_by_parser_paths(filep, self.parser_paths)

    def parsed_in_original(self, filep):
        """Checks if the file path is parsed by existing Apache config.
        ie. returns True if the file is found on a path that matches Include or
        IncludeOptional statement in the Apache configuration.

        :param str filep: Path to match

        :returns: True if file is parsed in existing configuration tree
        :rtype: bool
        """
        return self._parsed_by_parser_paths(filep, self.existing_paths)

    def _parsed_by_parser_paths(self, filep, paths):
        """Helper function that searches through provided paths and returns
        True if file path is found in the set"""
        for directory in paths.keys():
            for filename in paths[directory]:
                if fnmatch.fnmatch(filep, os.path.join(directory, filename)):
                    return True
        return False

    def _check_path_actions(self, filepath):
        """Determine actions to take with a new augeas path

        This helper function will return a tuple that defines
        if we should try to append the new filepath to augeas
        parser paths, and / or remove the old one with more
        narrow matching.

        :param str filepath: filepath to check the actions for

        """

        try:
            new_file_match = os.path.basename(filepath)
            existing_matches = self.parser_paths[os.path.dirname(filepath)]
            if "*" in existing_matches:
                use_new = False
            else:
                use_new = True
            if new_file_match == "*":
                remove_old = True
            else:
                remove_old = False
        except KeyError:
            use_new = True
            remove_old = False
        return use_new, remove_old

    def _remove_httpd_transform(self, filepath):
        """Remove path from Augeas transform

        :param str filepath: filepath to remove
        """

        remove_basenames = self.parser_paths[os.path.dirname(filepath)]
        remove_dirname = os.path.dirname(filepath)
        for name in remove_basenames:
            remove_path = remove_dirname + "/" + name
            remove_inc = self.aug.match(
                "/augeas/load/Httpd/incl [. ='%s']" % remove_path)
            self.aug.remove(remove_inc[0])
        self.parser_paths.pop(remove_dirname)

    def _add_httpd_transform(self, incl):
        """Add a transform to Augeas.

        This function will correctly add a transform to augeas
        The existing augeas.add_transform in python doesn't seem to work for
        Travis CI as it loads in libaugeas.so.0.10.0

        :param str incl: filepath to include for transform

        """
        last_include = self.aug.match("/augeas/load/Httpd/incl [last()]")
        if last_include:
            # Insert a new node immediately after the last incl
            self.aug.insert(last_include[0], "incl", False)
            self.aug.set("/augeas/load/Httpd/incl[last()]", incl)
        # On first use... must load lens and add file to incl
        else:
            # Augeas uses base 1 indexing... insert at beginning...
            self.aug.set("/augeas/load/Httpd/lens", "Httpd.lns")
            self.aug.set("/augeas/load/Httpd/incl", incl)
        # Add included path to paths dictionary
        try:
            self.parser_paths[os.path.dirname(incl)].append(
                os.path.basename(incl))
        except KeyError:
            self.parser_paths[os.path.dirname(incl)] = [
                os.path.basename(incl)]

    def standardize_excl(self):
        """Standardize the excl arguments for the Httpd lens in Augeas.

        Note: Hack!
        Standardize the excl arguments for the Httpd lens in Augeas
        Servers sometimes give incorrect defaults
        Note: This problem should be fixed in Augeas 1.0.  Unfortunately,
        Augeas 0.10 appears to be the most popular version currently.

        """
        # attempt to protect against augeas error in 0.10.0 - ubuntu
        # *.augsave -> /*.augsave upon augeas.load()
        # Try to avoid bad httpd files
        # There has to be a better way... but after a day and a half of testing
        # I had no luck
        # This is a hack... work around... submit to augeas if still not fixed

        excl = ["*.augnew", "*.augsave", "*.dpkg-dist", "*.dpkg-bak",
                "*.dpkg-new", "*.dpkg-old", "*.rpmsave", "*.rpmnew",
                "*~",
                self.root + "/*.augsave",
                self.root + "/*~",
                self.root + "/*/*augsave",
                self.root + "/*/*~",
                self.root + "/*/*/*.augsave",
                self.root + "/*/*/*~"]

        for i, excluded in enumerate(excl, 1):
            self.aug.set("/augeas/load/Httpd/excl[%d]" % i, excluded)

        self.aug.load()

    def _set_locations(self):
        """Set default location for directives.

        Locations are given as file_paths
        .. todo:: Make sure that files are included

        """
        default = self.loc["root"]

        temp = os.path.join(self.root, "ports.conf")
        if os.path.isfile(temp):
            listen = temp
            name = temp
        else:
            listen = default
            name = default

        return {"default": default, "listen": listen, "name": name}

    def _find_config_root(self):
        """Find the Apache Configuration Root file."""
        location = ["apache2.conf", "httpd.conf", "conf/httpd.conf"]
        for name in location:
            if os.path.isfile(os.path.join(self.root, name)):
                return os.path.join(self.root, name)
        raise errors.NoInstallationError("Could not find configuration root")


def case_i(string):
    """Returns case insensitive regex.

    Returns a sloppy, but necessary version of a case insensitive regex.
    Any string should be able to be submitted and the string is
    escaped and then made case insensitive.
    May be replaced by a more proper /i once augeas 1.0 is widely
    supported.

    :param str string: string to make case i regex

    """
    return "".join(["[" + c.upper() + c.lower() + "]"
                    if c.isalpha() else c for c in re.escape(string)])


def get_aug_path(file_path):
    """Return augeas path for full filepath.

    :param str file_path: Full filepath

    """
    return "/files%s" % file_path
