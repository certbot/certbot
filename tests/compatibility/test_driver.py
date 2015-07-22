"""Tests Let's Encrypt plugins against different server configurations."""
import argparse
import filecmp
import logging
import os
import shutil
import tempfile

import OpenSSL

from acme import challenges
from acme import crypto_util
from acme import messages
from letsencrypt import achallenges
from letsencrypt.tests import acme_util
from tests.compatibility import errors
from tests.compatibility import util
from tests.compatibility.configurators.apache import apache24


DESCRIPTION = """
Tests Let's Encrypt plugins against different server configuratons. It is
assumed that Docker is already installed. If no test types is specified, all
tests that the plugin supports are performed.

"""


PLUGINS = {"apache" : apache24.Proxy}


logger = logging.getLogger(__name__)


def test_authenticator(plugin, config, temp_dir):
    """Tests plugin as an authenticator"""
    backup = os.path.join(temp_dir, "backup")
    shutil.copytree(config, backup, symlinks=True)

    achalls = _create_achalls(plugin)
    if achalls:
        try:
            responses = plugin.perform(achalls)
            for i in xrange(len(responses)):
                if not responses[i]:
                    raise errors.Error(
                        "Plugin returned 'None' or 'False' response to "
                        "challenge")
                elif isinstance(responses[i], challenges.DVSNIResponse):
                    if responses[i].simple_verify(achalls[i],
                                                  achalls[i].domain,
                                                  util.JWK.key.public_key(),
                                                  host="127.0.0.1",
                                                  port=plugin.https_port):
                        logger.info(
                            "Verification of DVSNI response for %s succeeded",
                            achalls[i].domain)
                    else:
                        raise errors.Error(
                            "Verification of DVSNI response for {0} "
                            "failed".format(achalls[i].domain))
        finally:
            plugin.cleanup(achalls)

    if _dirs_are_unequal(config, backup):
        raise errors.Error("Challenge cleanup failed")
    else:
        logger.info("Challenge cleanup succeeded")


def _create_achalls(plugin):
    """Returns a list of annotated challenges to test on plugin"""
    achalls = list()
    names = plugin.get_testable_domain_names()
    for domain in names:
        prefs = plugin.get_chall_pref(domain)
        for chall_type in prefs:
            if chall_type == challenges.DVSNI:
                chall = challenges.DVSNI(
                    r=os.urandom(challenges.DVSNI.R_SIZE),
                    nonce=os.urandom(challenges.DVSNI.NONCE_SIZE))
                challb = acme_util.chall_to_challb(
                    chall, messages.STATUS_PENDING)
                achall = achallenges.DVSNI(
                    challb=challb, domain=domain, key=util.JWK)
                achalls.append(achall)

    return achalls


def test_installer(plugin, config, temp_dir):
    """Tests plugin as an installer"""
    backup = os.path.join(temp_dir, "backup")
    shutil.copytree(config, backup, symlinks=True)

    if plugin.get_all_names() != plugin.get_all_names_answer():
        raise errors.Error("get_all_names test failed")
    else:
        logging.info("get_all_names test succeeded")

    domains = list(plugin.get_testable_domain_names())
    cert = crypto_util.gen_ss_cert(util.KEY, domains)
    cert_path = os.path.join(temp_dir, "cert.pem")
    with open(cert_path, "w") as f:
        f.write(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert))

    for domain in domains:
        plugin.deploy_cert(domain, cert_path, util.KEY_PATH)
    plugin.save()
    plugin.restart()


def _dirs_are_unequal(dir1, dir2):
    """Returns True if dir1 and dir2 are equal"""
    dircmp = filecmp.dircmp(dir1, dir2)

    return (dircmp.left_only or dircmp.right_only or
            dircmp.diff_files or dircmp.funny_files)


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
    root_logger.setLevel(logging.INFO - args.verbose_count * 10)
    root_logger.addHandler(handler)


def main():
    """Main test script execution."""
    args = get_args()
    setup_logging(args)

    if args.plugin not in PLUGINS:
        raise errors.Error("Unknown plugin {0}".format(args.plugin))

    temp_dir = tempfile.mkdtemp()
    plugin = PLUGINS[args.plugin](args)
    try:
        plugin.execute_in_docker("mkdir -p /var/log/apache2")
        while plugin.has_more_configs():
            try:
                config = plugin.load_config()
                logger.info("Loaded configuration: %s", config)
                if args.auth:
                    test_authenticator(plugin, config, temp_dir)
                #if args.install:
                    #test_installer(plugin, temp_dir)
            except errors.Error as error:
                logger.warning("Test failed: %s", error)
    finally:
        plugin.cleanup_from_tests()


if __name__ == "__main__":
    main()
