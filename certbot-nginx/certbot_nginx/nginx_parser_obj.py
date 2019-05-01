"""NginxParser is a member object of the NginxConfigurator class."""
import glob
import logging
import pyparsing

from certbot.compat import os

from certbot_nginx import nginxparser
from certbot_nginx import parser_obj as obj
from certbot_nginx import obj as nginx_obj

logger = logging.getLogger(__name__)

class NginxParseContext(obj.ParseContext):
    """ A parsing context which includes a set of parsing hooks specific to Nginx
    configuration files. """
    def __init__(self, parent=None, filename=None, cwd=None, parsed_files=None):
        super(NginxParseContext, self).__init__(parent, filename, cwd)
        self.parsed_files = parsed_files if parsed_files else {}

    @staticmethod
    def parsing_hooks():
        return NGINX_PARSING_HOOKS

    def child(self, parent, filename=None):
        return NginxParseContext(parent,filename if filename else self.filename,
            self.cwd, self.parsed_files)

def parse_from_file_nginx(context):
    """ Parses from a file specified by `context`.
    :param NginxParseContext context:
    :returns WithLists:
    """
    raw_parsed = []
    with open(os.path.join(context.cwd, context.filename)) as _file:
        try:
            raw_parsed = nginxparser.load(_file, True)
        except pyparsing.ParseException as err:
            logger.debug("Could not parse file: %s due to %s", context.filename, err)
    context.parsed_files[context.filename] = None
    parsed = obj.parse_raw(raw_parsed, context=context)
    parsed.context.parsed_files[context.filename] = parsed
    return parsed

class Include(obj.Sentence):
    """ Represents an include statement. On parsing, tries to read and parse included file(s), while
    avoiding duplicates from `context.parsed`."""
    def __init__(self, context):
        super(Include, self).__init__(context)
        self.parsed = dict()

    @staticmethod
    def should_parse(lists):
        return obj.Sentence.should_parse(lists) and "include" in lists

    def parse(self, raw_list, add_spaces=False):
        """ Parsing an include this will try to fetch the associated files (if they exist)
        and parses them all. Any parsed files are added to the global context.parsed_files object.
        """
        super(Include, self).parse(raw_list, add_spaces)
        filepath = self.filename
        if not os.path.isabs(filepath):
            filepath = os.path.join(self.context.cwd, self.filename)
        for f in glob.glob(filepath):
            self.parsed[f] = self.context.parsed_files[f] if f in self.context.parsed_files else \
                parse_from_file_nginx(self.child_context(f))

    @property
    def filename(self):
        """ Retrieves the filename that is being included. """
        return self.words[1]

    def iterate(self, expanded=False, match=None):
        """ Iterates itself, and if expanded is set, iterates over the `Directives` objects
        in all of the included files.
        """
        if match is None or match(self):
            yield self
        if expanded:
            for parsed in self.parsed.values():
                for sub_elem in parsed.iterate(expanded, match):
                    yield sub_elem

class ServerBlock(obj.Block):
    """ Parsing object which represents an Nginx server block.
    This bloc should parallel a "VirtualHost" object-- any update or modification should
    also update the corresponding virtual host object. """

    REPEATABLE_DIRECTIVES = set(['server_name', 'listen', 'include', 'rewrite', 'add_header'])

    def __init__(self, context=None):
        super(ServerBlock, self).__init__(context)
        self.vhost = None

    @staticmethod
    def should_parse(lists):
        return obj.Block.should_parse(lists) and "server" in lists[0]

    def _update_vhost(self):
        # copied from _parse_server_raw
        self.addrs = set()
        self.ssl = False
        self.server_names = set()
        apply_ssl_to_all_addrs = False
        for directive in self.contents.get_type(obj.Sentence):
            if len(directive.words) == 0:
                continue
            if directive[0] == 'listen':
                addr = nginx_obj.Addr.fromstring(" ".join(directive[1:]))
                if addr:
                    self.addrs.add(addr)
                    if addr.ssl:
                        self.ssl = True
            if directive[0] == 'server_name':
                self.server_names.update(x.strip('"\'') for x in directive[1:])
            for ssl in self.get_directives('ssl'):
                if ssl.words[1] == "on":
                    self.ssl = True
                    apply_ssl_to_all_addrs = True
        if apply_ssl_to_all_addrs:
            for addr in self.addrs:
                addr.ssl = True
        return nginx_obj.VirtualHost(
            self.context.filename if self.context is not None else "",
            self.addrs, self.ssl, True, self.server_names, self.dump_unspaced_list()[1],
            self.get_path(), self)

    def get_directives(self, name, match=None):
        """ Retrieves any child directive starting with `name`.
        :param str name: The directive name to fetch.
        :param callable match: An additional optional filter to specify matching directives.
        :return: an iterator over matching directives.
        """
        directives = self.contents.get_type(obj.Sentence)
        return [d for d in directives if len(d) > 0 and d[0] == name and (match is None or match(d))]

    def parse(self, raw_list, add_spaces=False):
        """ Parses lists into a ServerBlock object, and creates a
        corresponding VirtualHost metadata object. """
        super(ServerBlock, self).parse(raw_list, add_spaces)
        self.vhost = self._update_vhost()

NGINX_PARSING_HOOKS = (ServerBlock, obj.Block, Include, obj.Sentence, obj.Directives)
