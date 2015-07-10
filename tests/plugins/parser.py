"""Module for parsing command line arguments and config files."""
import argparse


DESCRIPTION = """
Tests Let's Encrypt plugins against different web servers and configurations
using Docker images. It is assumed that Docker is already installed.

"""

def parse_args():
    """Returns parsed command line arguments."""
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    add_args(parser)
    args = parser.parse_args()

    if args.redirect:
        args.names = True
        args.install = True
    elif args.install:
        args.names = True

    return args


def add_args(parser):
    """Adds general/program wide arguments to the group."""
    group = parser.add_argument_group("general")
    group.add_argument(
        "-t", "--tar", default="configs.tar.gz",
        help="a gzipped tarball containing server configurations")
    group.add_argument(
        "-p", "--plugin", default="apache",
        help="the plugin to be tested")
    group.add_argument(
        "-n", "--names", action="store_true", help="tests installer's domain "
        "name identification")
    group.add_argument(
        "-a", "--auth", action="store_true", help="tests authenticators")
    group.add_argument(
        "-i", "--install", action="store_true", help="tests installer's "
        "certificate installation (implicitly includes -d)")
    group.add_argument(
        "-r", "--redirect", action="store_true", help="tests installer's "
        "redirecting HTTP to HTTPS (implicitly includes -di)")
    group.add_argument(
        "--no-simple-http-tls", action="store_true", help="do not use TLS "
        "when solving SimpleHTTP challenges")
