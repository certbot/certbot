"""NginxParser is a member object of the NginxConfigurator class."""
import glob
import logging
import os
import re
import pyparsing

from letsencrypt.client import errors
from letsencrypt.client.plugins.nginx import obj
from letsencrypt.client.plugins.nginx.nginxparser import dump, load


class NginxParser(object):
    """Class handles the fine details of parsing the Nginx Configuration.

    :ivar str root: Normalized abosulte path to the server root
        directory. Without trailing slash.
    :ivar dict parsed: Mapping of file paths to parsed trees

    """

    def __init__(self, root, ssl_options):
        self.parsed = {}
        self.root = os.path.abspath(root)
        self.loc = self._set_locations(ssl_options)

        # Parse nginx.conf and included files.
        # TODO: Check sites-available/ as well. For now, the configurator does
        # not enable sites from there.
        self._parse_recursively(self.loc["root"])

    def _parse_recursively(self, filepath):
        """Parses nginx config files recursively by looking at 'include'
        directives inside 'http' and 'server' blocks. Note that this only
        reads Nginx files that potentially declare a virtual host.

        .. todo:: Can Nginx 'virtual hosts' be defined somewhere other than in
        the server context?

        :param str filepath: The path to the files to parse, as a glob

        """
        filepath = self.abs_path(filepath)
        trees = self._parse_files(filepath)
        for tree in trees:
            for entry in tree:
                if self._is_include_directive(entry):
                    # Parse the top-level included file
                    self._parse_recursively(entry[1])
                elif entry[0] == ['http'] or entry[0] == ['server']:
                    # Look for includes in the top-level 'http'/'server' context
                    for subentry in entry[1]:
                        if self._is_include_directive(subentry):
                            self._parse_recursively(subentry[1])
                        elif entry[0] == ['http'] and subentry[0] == ['server']:
                            # Look for includes in a 'server' context within
                            # an 'http' context
                            for server_entry in subentry[1]:
                                if self._is_include_directive(server_entry):
                                    self._parse_recursively(server_entry[1])

    def abs_path(self, path):
        """Converts a relative path to an absolute path relative to the root.
        Does nothing for paths that are already absolute.

        :param str path: The path
        :returns: The absolute path
        :rtype str

        """
        if not os.path.isabs(path):
            return os.path.join(self.root, path)
        else:
            return path

    def _is_include_directive(self, entry):
        """Checks if an nginx parsed entry is an 'include' directive.

        :param list entry: the parsed entry
        :returns: Whether it's an 'include' directive
        :rtype: bool

        """
        return (entry[0] == 'include' and len(entry) == 2 and
                type(entry[1]) == str)

    def _get_names(self, entry):
        """Gets server names from nginx parsed entry.

        :param list entry: the parsed entry
        :returns: Set of server names
        :rtype: set

        """
        return set()

    def _get_addrs(self, entry):
        """Gets addresses from nginx parsed entry.

        :param list entry: the parsed entry
        :returns: Set of
            :class:`~letsencrypt.client.plugins.nginx.obj.Addr` objects
        :rtype: set

        """
        return set()

    def _get_ssl(self, entry):
        """Gets whether the nginx parsed entry is SSL-enabled.

        :param list entry: the parsed entry
        :returns: Whether it's SSL-enabled
        :rtype: bool

        """
        # Look for a server block that contains 'listen [port] ssl'
        return False

    def get_vhosts(self):
        """Gets list of all 'virtual hosts' found in Nginx configuration.
        Technically this is a misnomer because Nginx does not have virtual
        hosts, it has 'server blocks'.

        :returns: List of
            :class:`~letsencrypt.client.plugins.nginx.obj.VirtualHost` objects
            found in configuration
        :rtype: list

        """
        enabled = True  # We only look at enabled vhosts for now
        vhosts = []
        for filename in self.parsed:
            tree = self.parsed[filename]
            vhost = obj.VirtulHost(filename,
                                   self._get_addrs(tree),
                                   self._get_ssl(tree),
                                   enabled,
                                   self._get_names(tree))
            vhosts.append(vhost)
        return vhosts

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

        .. todo:: Add order to directives returned. Last directive comes last..
        .. todo:: arg should probably be a list

        Note: Augeas is inherently case sensitive while Nginx is case
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

        # Debug code
        # print "find_dir:", directive, "arg:", arg, " | Looking in:", start
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
        """Converts an Nginx Include directive into Augeas path.

        Converts an Nginx Include directive argument into an Augeas
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
        # only operates on Nginx real config data... then the attacker has
        # already won.
        # Perhaps it is better to simply check the permissions on all
        # included files?
        # check_config to validate nginx config doesn't work because it
        # would create a race condition between the check and this input

        # TODO: Maybe... although I am convinced we have lost if
        # Nginx files can't be trusted.  The augeas include path
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
        # conf/ is a special variable for ServerRoot in Nginx
        elif arg.startswith("conf/"):
            arg = self.root + arg[4:]
        # TODO: Test if Nginx allows ../ or ~/ for Includes

        # Attempts to add a transform to the file if one does not already exist
        self._parse_files(arg)

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
        """Method converts Nginx's basic fnmatch to regular expression.

        :param str clean_fn_match: Nginx style filename match, similar to globs

        :returns: regex suitable for augeas
        :rtype: str

        """
        # Checkout fnmatch.py in venv/local/lib/python2.7/fnmatch.py
        regex = ""
        for letter in clean_fn_match:
            if letter == '.':
                regex = regex + r"\."
            elif letter == '*':
                regex = regex + ".*"
            # According to nginx.org ? shouldn't appear
            # but in case it is valid...
            elif letter == '?':
                regex = regex + "."
            else:
                regex = regex + letter
        return regex

    def _parse_files(self, filepath):
        """Parse files from a glob

        :param str filepath: Nginx config file path
        :returns: list of parsed tree structures
        :rtype: list

        """
        files = glob.glob(filepath)
        trees = []
        for f in files:
            if f in self.parsed:
                continue
            try:
                with open(f) as fo:
                    parsed = load(fo)
                    self.parsed[f] = parsed
                    trees.append(parsed)
            except IOError:
                logging.warn("Could not open file: %s" % f)
            except pyparsing.ParseException:
                logging.warn("Could not parse file: %s" % f)
        return trees

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

    def _set_locations(self, ssl_options):
        """Set default location for directives.

        Locations are given as file_paths
        .. todo:: Make sure that files are included

        """
        root = self._find_config_root()
        default = root

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
        """Find the Nginx Configuration Root file."""
        location = ['nginx.conf']

        for name in location:
            if os.path.isfile(os.path.join(self.root, name)):
                return os.path.join(self.root, name)

        raise errors.LetsEncryptNoInstallationError(
            "Could not find configuration root")

    def filedump(self, ext='tmp'):
        """Dumps parsed configurations into files.

        :param str ext: The file extension to use for the dumped files. If
            empty, this overrides the existing conf files.

        """
        for filename in self.parsed:
            tree = self.parsed[filename]
            if ext:
                filename = filename + os.path.extsep + ext
            try:
                with open(filename, 'w') as f:
                    dump(tree, f)
            except IOError:
                logging.error("Could not open file for writing: %s" % filename)


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
