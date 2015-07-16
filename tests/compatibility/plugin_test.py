"""Tests Let's Encrypt plugins against different server configurations."""
import argparse
import logging
import os

from tests.compatibility.configurators.apache import apache24

DESCRIPTION = """
Tests Let's Encrypt plugins against different server configuratons. It is
assumed that Docker is already installed.

"""


PLUGINS = {"apache" : apache24.Proxy}


logger = logging.getLogger(__name__)


def get_args():
    """Returns parsed command line arguments."""
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    group = parser.add_argument_group("general")
    group.add_argument(
        "-c", "--configs", default="configs.tar.gz",
        help="a directory or tarball containing server configurations")
    group.add_argument(
        "-p", "--plugin", default="apache", help="the plugin to be tested")
    group.add_argument(
        "-a", "--auth", action="store_true",
        help="tests the plugin as an authenticator")
    group.add_argument(
        "-i", "--install", action="store_true",
        help="tests the plugin as an installer")
    group.add_argument(
        "-r", "--redirect", action="store_true", help="tests the plugin's "
        "ability to redirect HTTP to HTTPS (implicitly includes installer "
        "tests)")

    for plugin in PLUGINS.itervalues():
        plugin.add_parser_arguments(parser)

    args = parser.parse_args()
    if args.redirect:
        args.install = True
    elif not (args.auth or args.install):
        args.auth = args.install = args.redirect = True

    return args


def setup_logging():
    """Prepares logging for the program"""
    fmt = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt))

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(handler)


def main():
    """Main test script execution."""
    setup_logging()
    args = get_args()

    if args.plugin not in PLUGINS:
        raise errors.Error("Unknown plugin {0}".format(args.plugin))
    plugin = PLUGINS[args.plugin](args)
    plugin.cleanup_from_tests()


if __name__ == "__main__":
    main()
