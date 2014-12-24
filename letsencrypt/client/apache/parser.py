"""ApacheParser is a member object of the ApacheConfigurator class."""
import os
import re

from letsencrypt.client import errors


class ApacheParser(object):
    """Class handles the fine details of parsing the Apache Configuration."""

    def __init__(self, aug, root, ssl_options):
        # Find configuration root and make sure augeas can parse it.
        self.aug = aug
        self.root = root
        self.loc = self._set_locations(ssl_options)
        self._parse_file(self.loc["root"])

        # Must also attempt to parse sites-available or equivalent
        # Sites-available is not included naturally in configuration
        self._parse_file(os.path.join(self.root, "sites-available/*"))

        # This problem has been fixed in Augeas 1.0
        self.standardize_excl()

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
        if type(arg) is not list:
            self.aug.set(aug_conf_path + "/directive[last()]/arg", arg)
        else:
            for i in range(len(arg)):
                self.aug.set("%s/directive[last()]/arg[%d]" %
                             (aug_conf_path, (i+1)),
                             arg[i])

    def find_dir(self, directive, arg=None, start=None):
        """Finds directive in the configuration.

        Recursively searches through config files to find directives
        Directives should be in the form of a case insensitive regex currently

        .. todo:: Add order to directives returned. Last directive comes last..
        .. todo:: arg should probably be a list

        Note: Augeas is inherently case sensitive while Apache is case
        insensitive.  Augeas 1.0 allows case insensitive regexes like
        regexp(/Listen/, 'i'), however the version currently supported
        by Ubuntu 0.10 does not.  Thus I have included my own case insensitive
        transformation by calling case_i() on everything to maintain
        compatibility.

        :param str directive: Directive to look for

        :param arg: Specific value direcitve must have, None if all should
                    be considered
        :type arg: str or None

        :param str start: Beginning Augeas path to begin looking

        """
        # Cannot place member variable in the definition of the function so...
        if not start:
            start = get_aug_path(self.loc["root"])

        # Debug code
        # print "find_dir:", directive, "arg:", arg, " | Looking in:", start
        # No regexp code
        # if arg is None:
        #     matches = self.aug.match(start +
        # "//*[self::directive='"+directive+"']/arg")
        # else:
        #     matches = self.aug.match(start +
        # "//*[self::directive='" + directive+"']/* [self::arg='" + arg + "']")

        # includes = self.aug.match(start +
        # "//* [self::directive='Include']/* [label()='arg']")

        if arg is None:
            matches = self.aug.match(("%s//*[self::directive=~regexp('%s')]/arg"
                                      % (start, directive)))
        else:
            matches = self.aug.match(("%s//*[self::directive=~regexp('%s')]/*"
                                      "[self::arg=~regexp('%s')]" %
                                      (start, directive, arg)))

        incl_regex = "(%s)|(%s)" % (case_i('Include'),
                                    case_i('IncludeOptional'))

        includes = self.aug.match(("%s//* [self::directive=~regexp('%s')]/* "
                                   "[label()='arg']" % (start, incl_regex)))

        # for inc in includes:
        #    print inc, self.aug.get(inc)

        for include in includes:
            # start[6:] to strip off /files
            matches.extend(self.find_dir(
                directive, arg, self._get_include_path(
                    strip_dir(start[6:]), self.aug.get(include))))

        return matches

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
        #     logging.error("Error: Invalid regexp characters in %s", arg)
        #     return []

        # Standardize the include argument based on server root
        if not arg.startswith("/"):
            arg = cur_dir + arg
        # conf/ is a special variable for ServerRoot in Apache
        elif arg.startswith("conf/"):
            arg = self.root + arg[5:]
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
        regex = ""
        for letter in clean_fn_match:
            if letter == '.':
                regex = regex + r"\."
            elif letter == '*':
                regex = regex + ".*"
            # According to apache.org ? shouldn't appear
            # but in case it is valid...
            elif letter == '?':
                regex = regex + "."
            else:
                regex = regex + letter
        return regex

    def _parse_file(self, file_path):
        """Parse file with Augeas

        Checks to see if file_path is parsed by Augeas
        If file_path isn't parsed, the file is added and Augeas is reloaded

        :param str file_path: Apache config file path

        """
        # Test if augeas included file for Httpd.lens
        # Note: This works for augeas globs, ie. *.conf
        inc_test = self.aug.match(
            "/augeas/load/Httpd/incl [. ='%s']" % file_path)
        if not inc_test:
            # Load up files
            # self.httpd_incl.append(file_path)
            # self.aug.add_transform("Httpd.lns",
            #                       self.httpd_incl, None, self.httpd_excl)
            self._add_httpd_transform(file_path)
            self.aug.load()

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
                self.root + "*.augsave",
                self.root + "*~",
                self.root + "*/*augsave",
                self.root + "*/*~",
                self.root + "*/*/*.augsave",
                self.root + "*/*/*~"]

        for i in range(len(excl)):
            self.aug.set("/augeas/load/Httpd/excl[%d]" % (i+1), excl[i])

        self.aug.load()

    def _add_httpd_transform(self, incl):
        """Add a transform to Augeas.

        This function will correctly add a transform to augeas
        The existing augeas.add_transform in python is broken.

        :param str incl: TODO

        """
        last_include = self.aug.match("/augeas/load/Httpd/incl [last()]")
        self.aug.insert(last_include[0], "incl", False)
        self.aug.set("/augeas/load/Httpd/incl[last()]", incl)

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

        raise errors.LetsEncryptConfiguratorError(
            "Could not find configuration root")

    def _set_user_config_file(self, root):
        """Set the appropriate user configuration file

        .. todo:: This will have to be updated for other distros versions

        :param str root: pathname which contains the user config

        """
        # Basic check to see if httpd.conf exists and
        # in heirarchy via direct include
        # httpd.conf was very common as a user file in Apache 2.2
        if (os.path.isfile(os.path.join(self.root, 'httpd.conf')) and
                self.find_dir(
                    case_i("Include"), case_i("httpd.conf"), root)):
            return os.path.join(self.root, 'httpd.conf')
        else:
            return os.path.join(self.root + 'apache2.conf')


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
