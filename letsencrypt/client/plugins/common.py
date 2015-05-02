"""Plugin common functions."""
import zope.interface

from letsencrypt.acme.jose import util as jose_util

from letsencrypt.client import interfaces


def option_namespace(name):
    """ArgumentParser options namespace (prefix of all options)."""
    return name + '-'

def dest_namespace(name):
    """ArgumentParser dest namespace (prefix of all destinations)."""
    return name + '_'


class Plugin(object):
    """Generic plugin."""
    zope.interface.implements(interfaces.IPlugin)
    zope.interface.classProvides(interfaces.IPluginFactory)

    def __init__(self, config, name):
        self.config = config
        self.name = name

    @property
    def option_namespace(self):
        return option_namespace(self.name)

    @property
    def dest_namespace(self):
        return dest_namespace(self.name)

    def dest(self, var):
        """Find a destination for given variable ``var``."""
        # this should do exactly the same what ArgumentParser(arg),
        # does to "arg" to compute "dest"
        return self.dest_namespace + var.replace('-', '_')

    def conf(self, var):
        """Find a configuration value for variable ``var``."""
        return getattr(self.config, self.dest(var))

    @classmethod
    def inject_parser_options(cls, parser, name):
        # dummy function, doesn't check if dest.startswith(self.dest_namespace)
        def add(arg_name_no_prefix, *args, **kwargs):
            return parser.add_argument(
                "--{0}{1}".format(option_namespace(name), arg_name_no_prefix),
                *args, **kwargs)
        cls.add_parser_arguments(add)

    @jose_util.abstractclassmethod
    def add_parser_arguments(cls, add):
        """Add plugin arguments to the CLI argument parser.

        :param callable add: Function that proxies calls to
            `argparse.ArgumentParser.add_argument` prepending options
            with unique plugin name prefix.

        """
