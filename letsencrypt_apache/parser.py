"""ApacheParser is a member object of the ApacheConfigurator class."""
import collections
import itertools
import logging
import os
import re
import subprocess

from letsencrypt import errors


logger = logging.getLogger(__name__)


class ApacheParser(object):
    """Class handles the fine details of parsing the Apache Configuration.

    .. todo:: Make parsing general... remove sites-available etc...

    :ivar str root: Normalized absolute path to the server root
        directory. Without trailing slash.

    """
    def __init__(self, aug, root, ssl_options, ctl):
        # This uses the binary, so it can be done first.
        # https://httpd.apache.org/docs/2.4/mod/core.html#define
        # https://httpd.apache.org/docs/2.4/mod/core.html#ifdefine
        # This only handles invocation parameters and Define directives!
        self.variables = self._init_runtime_variables(ctl)

        # Find configuration root and make sure augeas can parse it.
        self.aug = aug
        self.root = os.path.abspath(root)
        self.loc = self._set_locations(ssl_options)
        self._parse_file(self.loc["root"])

        # Must also attempt to parse sites-available or equivalent
        # Sites-available is not included naturally in configuration
        self._parse_file(os.path.join(self.root, "sites-available") + "/*")

        # This problem has been fixed in Augeas 1.0
        self.standardize_excl()

        # Temporarily set modules to be empty, so that find_dirs can work
        # https://httpd.apache.org/docs/2.4/mod/core.html#ifmodule
        self.modules = set()
        self._init_modules()

    def _init_modules(self):
        """Iterates on the configuration until no new modules are loaded.

        ..todo:: This should be attempted to be done with a binary to avoid
            the iteration issue.  Else... do a better job of parsing to avoid it

        """
        matches = self.find_dir(case_i("LoadModule"))

        iterator = iter(matches)
        # Make sure prev_size != cur_size for do: while: iteration
        prev_size = -1

        while len(self.modules) != prev_size:
            prev_size = len(self.modules)

            for match_name, match_filename in itertools.izip(
                    iterator, iterator):
                self.modules.add(self.aug.get(match_name))
                self.modules.add(
                    os.path.basename(self.aug.get(match_filename))[:-2] + "c")

    def _init_runtime_variables(self, ctl):
        """"

        ..todo:: Also use apache2ctl -V for compiled parameters

        """
        stdout = self._get_runtime_cfg(ctl)

        variables = dict()
        matches = re.compile(r"Define: ([^ \n]*)").findall(stdout)
        matches.remove("DUMP_RUN_CFG")

        for match in matches:
            if match.count("=") > 1:
                logger.error("Unexpected number of equal signs in "
                             "apache2ctl -D DUMP_RUN_CFG")
                raise errors.PluginError(
                    "Error parsing Apache runtime variables")
            parts = match.partition("=")
            variables[parts[0]] = parts[2]

        return variables

    def _get_runtime_cfg(self, ctl):
        """Get runtime configuration info.

        :returns: stdout from DUMP_RUN_CFG

        """
        try:
            proc = subprocess.Popen(
                [ctl, "-D", "DUMP_RUN_CFG"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()

        except (OSError, ValueError):
            logger.error(
                "Error accessing {0} for runtime parameters!{1}".format(
                    ctl, os.linesep))
            raise errors.MisconfigurationError(
                "Error accessing loaded Apache parameters: %s", ctl)
        # Small errors that do not impede
        if proc.returncode != 0:
            logger.warn("Error in checking parameter list: %s", stderr)
            raise errors.MisconfigurationError(
                "Apache is unable to check whether or not the module is "
                "loaded because Apache is misconfigured.")

        return stdout

    def _filter_args_num(self, matches, args):
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
            for i in range(matches):
                if matches[i].endswith("/arg"):
                    filtered.append(matches[i][:-4])
        else:
            for i in range(matches):
                if matches[i].endswith("/arg[%d]", args):
                    # Make sure we don't cause an IndexError (end of list)
                    # Check to make sure arg + 1 doesn't exist
                    if (i == (len(matches) - 1) or
                            not matches[i + 1].endswith("/arg[%d]" % args + 1)):
                        filtered.append(matches[i][:-len("/arg[%d]" % args)])

        return filtered

    def add_dir_to_ifmodssl(self, aug_conf_path, directive, val):
        """Adds directive and value to IfMod ssl block.

        Adds given directive and value along configuration path within
        an IfMod mod_ssl.c block.  If the IfMod block does not exist in
        the file, it is created.

        :param str aug_conf_path: Desired Augeas config path to add directive
        :param str directive: Directive you would like to add
        :param str val: Value of directive ie. Listen 443, 443 is the value

        """
        # TODO: Add error checking code... does the path given even exist?
        #       Does it throw exceptions?
        if_mod_path = self._get_ifmod(aug_conf_path, "mod_ssl.c")
        # IfModule can have only one valid argument, so append after
        self.aug.insert(if_mod_path + "arg", "directive", False)
        nvh_path = if_mod_path + "directive[1]"
        self.aug.set(nvh_path, directive)
        self.aug.set(nvh_path + "/arg", val)

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

    def add_dir(self, aug_conf_path, directive, arg):
        """Appends directive to the end fo the file given by aug_conf_path.

        .. note:: Not added to AugeasConfigurator because it may depend
            on the lens

        :param str aug_conf_path: Augeas configuration path to add directive
        :param str directive: Directive to add
        :param str arg: Value of the directive. ie. Listen 443, 443 is arg

        """
        self.aug.set(aug_conf_path + "/directive[last() + 1]", directive)
        if isinstance(arg, list):
            for i, value in enumerate(arg, 1):
                self.aug.set(
                    "%s/directive[last()]/arg[%d]" % (aug_conf_path, i), value)
        else:
            self.aug.set(aug_conf_path + "/directive[last()]/arg", arg)

    def find_dir(self, directive, arg=None, start=None):
        """Finds directive in the configuration.

        Recursively searches through config files to find directives
        Directives should be in the form of a case insensitive regex currently

        .. todo:: arg should probably be a list
        .. todo:: Check //* notation for including directories not intended
            to be included.

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

        regex = "(%s)|(%s)|(%s)" % (directive,
                                    case_i("Include"),
                                    case_i("IncludeOptional"))
        matches = self.aug.match(
            "%s//*[self::directive=~regexp('%s')]" % (start, regex))

        matches = self._exclude_dirs(matches)


        if arg is None:
            arg_suffix = "/arg"
        else:
            arg_suffix = "/*[self::arg=~regexp('%s')]" % arg

        ordered_matches = []

        for match in matches:
            dir = self.aug.get(match).lower()
            if dir == "include" or dir == "includeoptional":
                # start[6:] to strip off /files
                ordered_matches.extend(self.find_dir(
                    directive, arg, self._get_include_path(
                        strip_dir(start[6:]), self.aug.get(match + "/arg"))))
            else:
                ordered_matches.extend(self.aug.match(match + arg_suffix))

        return ordered_matches

    def _exclude_dirs(self, matches):
        """Exclude directives that are not loaded into the configuration."""
        filters = [("ifmodule", self.modules), ("ifdefine", self.variables)]

        valid_matches = []

        for match in matches:
            for filter in filters:
                if not self._pass_filter(match, filter):
                    break
            else:
                valid_matches.append(match)
        return valid_matches

    def _pass_filter(self, match, filter):
        """Determine if directive passes a filter.

        :param str match: Augeas path
        :param list filter: list of tuples of form
            [("lowercase if directive", set of relevant parameters)]

        """
        match_l = match.lower()
        last_match_idx = match_l.find(filter[0])

        while last_match_idx != -1:
            # Check args
            end_of_if = match_l.find("/", last_match_idx)
            expression = self.aug.get(match[:end_of_if] + "/arg")

            expected = not expression.startswith("!")
            if expected != expression in filter[1]:
                return False

            last_match_idx = match_l.find(filter[0], end_of_if)

        return True

    def _get_include_path(self, cur_dir, arg):
        """Converts an Apache Include directive into Augeas path.

        Converts an Apache Include directive argument into an Augeas
        searchable path

        .. todo:: convert to use os.path.join()

        :param str cur_dir: current working directory

        :param str arg: Argument of Include directive

        :returns: Augeas path string
        :rtype: str

        """
        # Sanity check argument - maybe
        # Question: what can the attacker do with control over this string
        # Effect parse file... maybe exploit unknown errors in Augeas
        # If the attacker can Include anything though... and this function
        # only operates on Apache real config data... then the attacker has
        # already won.
        # Perhaps it is better to simply check the permissions on all
        # included files?
        # check_config to validate apache config doesn't work because it
        # would create a race condition between the check and this input

        # TODO: Maybe... although I am convinced we have lost if
        # Apache files can't be trusted.  The augeas include path
        # should be made to be exact.

        # Check to make sure only expected characters are used <- maybe remove
        # validChars = re.compile("[a-zA-Z0-9.*?_-/]*")
        # matchObj = validChars.match(arg)
        # if matchObj.group() != arg:
        #     logger.error("Error: Invalid regexp characters in %s", arg)
        #     return []

        # Standardize the include argument based on server root
        if not arg.startswith("/"):
            arg = cur_dir + arg
        # conf/ is a special variable for ServerRoot in Apache
        elif arg.startswith("conf/"):
            arg = self.root + arg[4:]
        # TODO: Test if Apache allows ../ or ~/ for Includes

        # Attempts to add a transform to the file if one does not already exist
        self._parse_file(arg)

        # Argument represents an fnmatch regular expression, convert it
        # Split up the path and convert each into an Augeas accepted regex
        # then reassemble
        if "*" in arg or "?" in arg:
            split_arg = arg.split("/")
            for idx, split in enumerate(split_arg):
                # * and ? are the two special fnmatch characters
                if "*" in split or "?" in split:
                    # Turn it into a augeas regex
                    # TODO: Can this instead be an augeas glob instead of regex
                    split_arg[idx] = ("* [label()=~regexp('%s')]" %
                                      self.fnmatch_to_re(split))
            # Reassemble the argument
            arg = "/".join(split_arg)

        # If the include is a directory, just return the directory as a file
        if arg.endswith("/"):
            return get_aug_path(arg[:len(arg)-1])
        return get_aug_path(arg)

    def fnmatch_to_re(self, clean_fn_match):  # pylint: disable=no-self-use
        """Method converts Apache's basic fnmatch to regular expression.

        :param str clean_fn_match: Apache style filename match, similar to globs

        :returns: regex suitable for augeas
        :rtype: str

        """
        # Checkout fnmatch.py in venv/local/lib/python2.7/fnmatch.py
        regex = ""
        for letter in clean_fn_match:
            if letter == ".":
                regex = regex + r"\."
            elif letter == "*":
                regex = regex + ".*"
            # According to apache.org ? shouldn't appear
            # but in case it is valid...
            elif letter == "?":
                regex = regex + "."
            else:
                regex = regex + letter
        return regex

    def _parse_file(self, filepath):
        """Parse file with Augeas

        Checks to see if file_path is parsed by Augeas
        If filepath isn't parsed, the file is added and Augeas is reloaded

        :param str filepath: Apache config file path

        """
        # Test if augeas included file for Httpd.lens
        # Note: This works for augeas globs, ie. *.conf
        inc_test = self.aug.match(
            "/augeas/load/Httpd/incl [. ='%s']" % filepath)
        if not inc_test:
            # Load up files
            # This doesn't seem to work on TravisCI
            # self.aug.add_transform("Httpd.lns", [filepath])
            self._add_httpd_transform(filepath)
            self.aug.load()

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

    def _set_locations(self, ssl_options):
        """Set default location for directives.

        Locations are given as file_paths
        .. todo:: Make sure that files are included

        """
        root = self._find_config_root()
        default = self._set_user_config_file(root)

        temp = os.path.join(self.root, "ports.conf")
        if os.path.isfile(temp):
            listen = temp
            name = temp
        else:
            listen = default
            name = default

        return {"root": root, "default": default, "listen": listen,
                "name": name, "ssl_options": ssl_options}

    def _find_config_root(self):
        """Find the Apache Configuration Root file."""
        location = ["apache2.conf", "httpd.conf"]

        for name in location:
            if os.path.isfile(os.path.join(self.root, name)):
                return os.path.join(self.root, name)

        raise errors.NoInstallationError("Could not find configuration root")

    def _set_user_config_file(self, root):
        """Set the appropriate user configuration file

        .. todo:: This will have to be updated for other distros versions

        :param str root: pathname which contains the user config

        """
        # Basic check to see if httpd.conf exists and
        # in hierarchy via direct include
        # httpd.conf was very common as a user file in Apache 2.2
        if (os.path.isfile(os.path.join(self.root, "httpd.conf")) and
                self.find_dir(
                    case_i("Include"), case_i("httpd.conf"), root)):
            return os.path.join(self.root, "httpd.conf")
        else:
            return os.path.join(self.root, "apache2.conf")


def case_i(string):
    """Returns case insensitive regex.

    Returns a sloppy, but necessary version of a case insensitive regex.
    Any string should be able to be submitted and the string is
    escaped and then made case insensitive.
    May be replaced by a more proper /i once augeas 1.0 is widely
    supported.

    :param str string: string to make case i regex

    """
    return "".join(["["+c.upper()+c.lower()+"]"
                    if c.isalpha() else c for c in re.escape(string)])


def get_aug_path(file_path):
    """Return augeas path for full filepath.

    :param str file_path: Full filepath

    """
    return "/files%s" % file_path


def strip_dir(path):
    """Returns directory of file path.

    .. todo:: Replace this with Python standard function

    :param str path: path is a file path. not an augeas section or
        directive path

    :returns: directory
    :rtype: str

    """
    index = path.rfind("/")
    if index > 0:
        return path[:index+1]
    # No directory
    return ""
