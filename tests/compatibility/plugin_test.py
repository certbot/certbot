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


def setup_logging():
    """Prepares logging for the program"""
    handler = logging.StreamHandler()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)


def main():
    """Main test script execution."""
    setup_logging()
    args = get_args()

    if args.plugin not in PLUGINS:
        raise errors.Error("Unknown plugin {0}".format(args.plugin))
    plugin = None
    try:
        plugin = PLUGINS[args.plugin](args)
        plugin.load_config()
        assert plugin.get_all_names() == plugin.get_test_domain_names()
    finally:
        if plugin:
            plugin.cleanup_from_tests()


if __name__ == "__main__":
    main()
