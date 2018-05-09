"""NginxParser is a member object of the NginxConfigurator class."""
import copy
import glob
import logging
import os
import pyparsing

from certbot import errors
from certbot.plugins import parser_obj as obj

from certbot_nginx import nginxparser
from certbot_nginx import obj as nginx_obj

logger = logging.getLogger(__name__)

REPEATABLE_DIRECTIVES = set(['server_name', 'listen', 'include', 'rewrite'])

def parse_raw_nginx(lists_, context=None):
    """ Primary parsing factory function that adds a couple of extra hooks to the default ones.

    :param list lists_: raw lists from pyparsing to parse.
    :param .ParseContext context: Context containing parsing hooks. If not set,
        uses default nginx parsing hooks.

    :returns .plugins.parser_obj.WithLists: The parsed object.
    """
    if context is None:
        return obj.parse_raw(lists_, NginxParseContext())
    return obj.parse_raw(lists_, context)

class Include(obj.Sentence):
    """ Represents an include statement. On parsing, tries to read and parse included file(s), while
    avoiding duplicates from `context.parsed`."""
    def __init__(self, context=None):
        super(Include, self).__init__(context)
        self.parsed = None

    def parse(self, parse_this, add_spaces=False):
        """ Parsing an include this will try to fetch the associated files (if they exist)
        and pares them all. Any parsed files are added to the global context.parsed_files object.
        """
        super(Include, self).parse(parse_this, add_spaces)
        files = glob.glob(os.path.join(self.context.cwd, self.filename))
        self.parsed = {}
        for f in files:
            if f in self.context.parsed_files:
                self.parsed[f] = self.context.parsed_files[f]
            else:
                self.parsed[f] = parse_from_file_nginx(self.child_context(f))

    @property
    def filename(self):
        """ Retrieves the filename that is being included. """
        return self.words[1]

    def iterate(self, expanded=False, match=None):
        """ Iterates itself, and if expanded is set, iterates over the `Statements` objects
        in all of the included files.
        """
        if match is None or match(self):
            yield self
        if expanded:
            for parsed in self.parsed.values():
                for sub_elem in parsed.iterate(expanded, match):
                    yield sub_elem

class ServerBloc(obj.Bloc):
    """ Parsing object which represents an Nginx server block.
    This bloc should parallel a "VirtualHost" object-- any update or modification should
    also update the corresponding virtual host object. """

    def __init__(self, context=None):
        super(ServerBloc, self).__init__(context)
        self.addrs = set()
        self.ssl = False
        self.server_names = set()
        self.vhost = None

    def _update_vhost(self):
        self.addrs = set()
        self.ssl = False
        self.server_names = set()
        for listen in self.get_directives('listen'):
            addr = nginx_obj.Addr.fromstring(" ".join(listen[1:]))
            if addr:
                self.addrs.add(addr)
                if addr.ssl:
                    self.ssl = True
        for name in self.get_directives('server_name'):
            self.server_names.update(name[1:])
        for ssl in self.get_directives('ssl'):
            if ssl.words[1] == 'on':
                self.ssl = True

        self.vhost.addrs = self.addrs
        self.vhost.names = self.server_names
        self.vhost.ssl = self.ssl
        self.vhost.raw = self

    def _add_directive(self, statement, insert_at_top=False):
        """ Adds a single directive to this Server Block's contents, while enforcing
        repeatability rules."""
        # Ensure no duplicate directives are added.
        if self._has_same_directive(statement):
            return
        # If this directive isn't repeatable, but an instance of it already exists, raise an error.
        if obj.is_sentence(statement) and statement[0] not in REPEATABLE_DIRECTIVES and len(
            list(self.get_directives(statement[0]))) > 0:
            raise errors.MisconfigurationError(
                "Existing %s directive conflicts with %s", statement[0], statement)
        self.contents.add_statement(statement, insert_at_top)

    def _has_same_directive(self, statement):
        """ Returns true if there exists the exact same statement in the contents of this block."""
        matches = list(self.get_directives(statement[0],
            lambda directive: directive.words == statement))
        return len(matches) > 0

    def add_directives(self, statements, insert_at_top=False):
        """ Add directives to this block's contents. If the exact statement already exists,
        don't add it.

        Updates corresponding virtual host.

        :param list statements: List of unparsed statements to add to this block.
        :param bool insert_at_top: Whether to insert `statements` to the top of the block.

        :raises errors.MisconfigurationError: If a non-repeatable directive is repeated
            in this block.
        """
        for statement in statements:
            self._add_directive(statement, insert_at_top)
        self._update_vhost()

    def replace_directives(self, statements, insert_at_top=False):
        """ For each statement in `statements`, if it already exists, replace it.
        Otherwise, add it to this block's contents.

        Updates corresponding virtual host.

        :param list statements: List of unparsed statements to replace.
        :param bool insert_at_top: Whether to insert added statements to the top of the block.
        """
        for s in statements:
            self.contents.replace_statement(s, lambda x, s=s: x[0] == s[0], insert_at_top)
        self._update_vhost()

    def remove_directives(self, directive, match_func=None):
        """ Removes statements from this object.
        :param str directive: The directive name to remove.
        :param callable match_func: An additional matching procedure to specify which directives
            to remove.
        """
        self.contents.remove_statements(lambda x: x[0] == directive and \
            (match_func is None or match_func(x)))
        self._update_vhost()

    def parse(self, parse_this, add_spaces=False):
        """ Parses lists into a ServerBloc object, and creates a corresponding virtualhost. """
        super(ServerBloc, self).parse(parse_this, add_spaces)
        self.vhost = nginx_obj.VirtualHost(self.context.filename \
                if self.context is not None else "",
            self.addrs, self.ssl, True, self.server_names, self, None)
        self._update_vhost()


    def duplicate(self, only_directives=None, remove_singleton_listen_params=False):
        """ Duplicates iteslf into another sibling server block.

        :param bool remove_singleton_listen_params: If we should remove parameters
            from listen directives in the block that can only be used once per address
        :param list only_directives: If it exists, only duplicate the named directives. Only
            looks at first level of depth; does not expand includes.
        """
        # pylint: disable=protected-access
        dup_bloc = self.context.parent.add_statement(copy.deepcopy(self.dump(include_spaces=True)))
        if only_directives is not None:
            dup_bloc.contents.remove_statements(lambda x: x[0] not in only_directives)
        if remove_singleton_listen_params:
            for directive in dup_bloc.get_directives('listen'):
                for word in ['default_server', 'default', 'ipv6only=on']:
                    if word in directive.words:
                        directive._data.remove(word)
        dup_bloc.context.parent = self.context.parent
        dup_bloc._update_vhost()
        return dup_bloc

    def get_directives(self, name, match=None):
        """ Retrieves any child directive starting with `name`.
        :param str name: The directive name to fetch.
        :param callable match: An additional optional filter to specify matching directives.

        :return: An iterator over matching directives.
        """
        return self.contents.get_type(obj.Sentence,
            lambda sentence: sentence[0] == name and (match is None or match(sentence)))

NGINX_PARSING_HOOKS = (
    (lambda list_: obj.is_bloc(list_) and 'server' in list_[0], ServerBloc),
    (lambda list_: obj.is_sentence(list_) and 'include' in list_, Include),
)

class NginxParseContext(obj.ParseContext):
    """ A parsing context which includes a set of parsing hooks specific to Nginx
    configuration files. """
    def __init__(self, cwd="", filename="", parent=None, parsed_files=None,
                 parsing_hooks=NGINX_PARSING_HOOKS + obj.DEFAULT_PARSING_HOOKS)
        super(NginxParseContext, self).__init__(cwd, filename, parent, parsed_files,
            parsing_hooks)

def parse_from_file_nginx(context):
    """ Similar to parse_raw_nginx, but parses from a file specified by `context`.
    :param NginxParseContext context:
    :returns WithLists:
    """
    raw_parsed = []
    with open(os.path.join(context.cwd, context.filename)) as _file:
        try:
            raw_parsed = nginxparser.load_raw(_file)
        except pyparsing.ParseException as err:
            logger.debug("Could not parse file: %s due to %s", context.filename, err)
    parsed = parse_raw_nginx(raw_parsed, context)
    parsed.context.parsed_files[context.filename] = parsed
    return parsed
