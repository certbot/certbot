"""NginxParser is a member object of the NginxConfigurator class."""
import glob
import logging
import os
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
        servers = {}  # Map of filename to list of parsed server blocks

        for filename in self.parsed:
            tree = self.parsed[filename]
            servers[filename] = []

            # Find all the server blocks
            do_for_subarray(tree, lambda x: x[0] == ['server'],
                            lambda x: servers[filename].append(x[1]))

            # Find 'include' statements in server blocks and append their trees
            for server in servers[filename]:
                for directive in server:
                    if (self._is_include_directive(directive)):
                        included_files = glob.glob(
                            self.abs_path(directive[1]))
                        for f in included_files:
                            try:
                                servers[f] = self.parsed[f]
                            except:
                                pass

        for filename in servers:
            for server in servers[filename]:
                # Parse the server block into a VirtualHost object
                parsed_server = self._parse_server(server)
                vhost = obj.VirtualHost(filename,
                                        parsed_server.addrs,
                                        parsed_server.ssl,
                                        enabled,
                                        parsed_server.names)
                vhosts.append(vhost)

        return vhosts

    def _parse_server(self, server):
        """Parses a list of server directives.

        :param list server: list of directives in a server block
        :rtype: dict

        """
        parsed_server = {}
        parsed_server.addrs = set()
        parsed_server.ssl = False
        parsed_server.names = set()

        for directive in server:
            if directive[0] == 'listen':
                addr = obj.Addr.fromstring(directive[1])
                parsed_server.addrs.add(addr)
                if not parsed_server.ssl and addr.ssl:
                    parsed_server.ssl = True
            elif directive[0] == 'server_name':
                parsed_server.names.update(' '.split(directive[1]))

        return parsed_server

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

    def add_dir(self, aug_conf_path, directive, arg):
        """Appends directive to the end fo the file given by aug_conf_path.

        .. note:: Not added to AugeasConfigurator because it may depend
            on the lens

        :param str aug_conf_path: Augeas configuration path to add directive
        :param str directive: Directive to add
        :param str arg: Value of the directive. ie. Listen 443, 443 is arg

        """
        pass

    def find_dir(self, directive, arg=None, start=None):
        """Finds directive in the configuration.

        Recursively searches through config files to find directives

        .. todo:: Add order to directives returned. Last directive comes last..
        .. todo:: arg should probably be a list

        :param str directive: Directive to look for

        :param arg: Specific value directive must have, None if all should
                    be considered
        :type arg: str or None

        :param str start: Beginning Augeas path to begin looking
        :rtype: list

        """
        return []

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


def do_for_subarray(entry, condition, func):
    """Executes a function for a subarray of a nested array if it matches
    the given condition.

    :param list entry: The list to iterate over
    :param function condition: Returns true iff func should be executed on item
    :param function func: The function to call for each matching item

    """
    for item in entry:
        if type(item) == list:
            if condition(item):
                try:
                    func(item)
                except:
                    logging.warn("Error in do_for_subarray for %s" % item)
            else:
                do_for_subarray(item, condition, func)
