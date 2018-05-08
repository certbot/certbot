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
    """ TODO
    """
    if context is None:
        return obj.parse_raw(lists_, NginxParseContext())
    return obj.parse_raw(lists_, context)

class Include(obj.Sentence):
    """ An include statement. """
    def __init__(self, context=None):
        super(Include, self).__init__(context)
        self.parsed = None

    def parse(self, parse_this, add_spaces=False):
        """ Parsing an include touches disk-- this will fetch the associated
        files and actually parse them all! """
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
        """ TODO """
        if match is None or match(self):
            yield self
        if expanded:
            for parsed in self.parsed.values():
                for sub_elem in parsed.iterate(expanded, match):
                    yield sub_elem

class ServerBloc(obj.Bloc):
    """ This bloc should parallel a vhost! """

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
        for listen in self.contents.get_directives('listen'):
            addr = nginx_obj.Addr.fromstring(" ".join(listen[1:]))
            if addr:
                self.addrs.add(addr)
                if addr.ssl:
                    self.ssl = True
        for name in self.contents.get_directives('server_name'):
            self.server_names.update(name[1:])
        for ssl in self.contents.get_directives('ssl'):
            if ssl.words[1] == 'on':
                self.ssl = True

        self.vhost.addrs = self.addrs
        self.vhost.names = self.server_names
        self.vhost.ssl = self.ssl
        self.vhost.raw = self

    # TODO (sydli): contextual sentences/blocks should be parsed automatically
    # (get rid of `is_block`)
    def _add_directive(self, statement, insert_at_top=False, is_block=False):
        # pylint: disable=protected-access
        # ensure no duplicates
        if self.contents.contains_exact_directive(statement):
            return
        # ensure, if it's not repeatable, that it's not repeated
        if not is_block and statement[0] not in REPEATABLE_DIRECTIVES and len(
            list(self.contents.get_directives(statement[0]))) > 0:
            raise errors.MisconfigurationError(
                "Existing %s directive conflicts with %s", statement[0], statement)
        self.contents.add_statement(statement, insert_at_top)

    def add_directives(self, statements, insert_at_top=False, is_block=False):
        """ Add statements to this object. If the exact statement already exists,
        don't add it.

        doesn't expect spaces between elements in statements """
        if is_block:
            self._add_directive(statements, insert_at_top, is_block)
        else:
            for statement in statements:
                self._add_directive(statement, insert_at_top, is_block)
        self._update_vhost()

    def replace_directives(self, statements, insert_at_top=False):
        """ Adds statements to this object. For each of the statements,
        if one of this statement type already exists, replaces existing statement.
        """
        for s in statements:
            self.contents.replace_statement(s, lambda x, s=s: x[0] == s[0], insert_at_top)
        self._update_vhost()

    def remove_directives(self, directive, match_func=None):
        """ Removes statements from this object."""
        self.contents.remove_statements(lambda x: x[0] == directive and \
            (match_func is None or match_func(x)))
        self._update_vhost()

    def parse(self, parse_this, add_spaces=False):
        super(ServerBloc, self).parse(parse_this, add_spaces)
        self.vhost = nginx_obj.VirtualHost(self.context.filename \
                if self.context is not None else "",
            self.addrs, self.ssl, True, self.server_names, self, None)
        self._update_vhost()


    def duplicate(self, only_directives=None, remove_singleton_listen_params=False):
        """ Duplicates iteslf into another sibling server block. """
        # pylint: disable=protected-access
        dup_bloc = self.context.parent.add_statement(copy.deepcopy(self.dump()))
        if only_directives is not None:
            dup_bloc.contents.remove_statements(lambda x: x[0] not in only_directives)
        if remove_singleton_listen_params:
            for directive in dup_bloc.contents.get_directives('listen'):
                for word in ['default_server', 'default', 'ipv6only=on']:
                    if word in directive.words:
                        directive._data.remove(word)
        dup_bloc.context.parent = self.context.parent
        dup_bloc._update_vhost()
        return dup_bloc

NGINX_PARSING_HOOKS = (
    (lambda list_: obj.is_bloc(list_) and 'server' in list_[0], ServerBloc),
    (lambda list_: obj.is_sentence(list_) and 'include' in list_, Include),
) + obj.DEFAULT_PARSING_HOOKS

class NginxParseContext(obj.ParseContext):
    """ TODO
    """
    def __init__(self, cwd="", filename="", parent=None, parsed_files=None,
                 parsing_hooks=NGINX_PARSING_HOOKS):
        super(NginxParseContext, self).__init__(cwd, filename, parent, parsed_files,
            parsing_hooks)

def parse_from_file_nginx(context):
    """ Creates a Statements object from the file referred to by context.
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
