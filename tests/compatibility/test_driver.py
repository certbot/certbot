"""Tests Let's Encrypt plugins against different server configurations."""
import argparse
import logging

from tests.compatibility import errors
from tests.compatibility.configurators.apache import apache24


DESCRIPTION = """
Tests Let's Encrypt plugins against different server configuratons. It is
assumed that Docker is already installed. If no test types is specified, all
tests that the plugin supports are performed.

"""


PLUGINS = {"apache" : apache24.Proxy}


logger = logging.getLogger(__name__)


def get_args():
    """Returns parsed command line arguments."""
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    group = parser.add_argument_group("general")
    group.add_argument(
        "-c", "--configs", default="configs.tar.gz",
        help="a directory or tarball containing server configurations")
    group.add_argument(
        "-p", "--plugin", default="apache", help="the plugin to be tested")
    group.add_argument(
        "-v", "--verbose", dest="verbose_count", action="count",
        default=0, help="you know how to use this")
    group.add_argument(
        "-a", "--auth", action="store_true",
        help="tests the challenges the plugin supports")
    group.add_argument(
        "-i", "--install", action="store_true",
        help="tests the plugin as an installer")
    group.add_argument(
        "-e", "--enhance", action="store_true", help="tests the enhancements "
        "the plugin supports (implicitly includes installer tests)")

    for plugin in PLUGINS.itervalues():
        plugin.add_parser_arguments(parser)

    args = parser.parse_args()
    if args.enhance:
        args.install = True
    elif not (args.auth or args.install):
        args.auth = args.install = args.redirect = True

    return args


def setup_logging(args):
    """Prepares logging for the program"""
    handler = logging.StreamHandler()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING - args.verbose_count * 10)
    root_logger.addHandler(handler)


def test_installer(plugin):
    """Tests plugin as an installer"""
    if plugin.get_all_names() != plugin.get_all_names_answer():
        raise errors.Error(
            "Names found by plugin don't match names found by the wrapper")


def main():
    """Main test script execution."""
    args = get_args()
    setup_logging(args)

    if args.plugin not in PLUGINS:
        raise errors.Error("Unknown plugin {0}".format(args.plugin))

    plugin = PLUGINS[args.plugin](args)
    try:
        while plugin.has_more_configs():
            try:
                print "Loaded configuration: {0}".format(plugin.load_config())

                if args.install:
                    test_installer(plugin)
            except errors.Error as error:
                print "Test failed"
                print error
    finally:
        plugin.cleanup_from_tests()


if __name__ == "__main__":
    main()
