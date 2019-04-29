"""Tests Certbot plugins against different server configurations."""
import argparse
import contextlib
import filecmp
import logging
import os
import shutil
import tempfile
import time
import sys
from urllib3.util import connection

import OpenSSL

from six.moves import xrange  # pylint: disable=import-error,redefined-builtin

from acme import challenges
from acme import crypto_util
from acme import messages
from acme.magic_typing import List, Tuple  # pylint: disable=unused-import, no-name-in-module
from certbot import achallenges
from certbot import errors as le_errors
from certbot.tests import acme_util

from certbot_compatibility_test import errors
from certbot_compatibility_test import util
from certbot_compatibility_test import validator

from certbot_compatibility_test.configurators.apache import common as a_common
from certbot_compatibility_test.configurators.nginx import common as n_common


DESCRIPTION = """
Tests Certbot plugins against different server configurations. It is
assumed that Docker is already installed. If no test type is specified, all
tests that the plugin supports are performed.

"""

PLUGINS = {"apache": a_common.Proxy, "nginx": n_common.Proxy}


logger = logging.getLogger(__name__)


def test_authenticator(plugin, config, temp_dir):
    """Tests authenticator, returning True if the tests are successful"""
    backup = _create_backup(config, temp_dir)

    achalls = _create_achalls(plugin)
    if not achalls:
        logger.error("The plugin and this program support no common "
                     "challenge types")
        return False

    try:
        responses = plugin.perform(achalls)
    except le_errors.Error:
        logger.error("Performing challenges on %s caused an error:", config, exc_info=True)
        return False

    success = True
    for i in xrange(len(responses)):
        if not responses[i]:
            logger.error(
                "Plugin failed to complete %s for %s in %s",
                type(achalls[i]), achalls[i].domain, config)
            success = False
        elif isinstance(responses[i], challenges.HTTP01Response):
            # We fake the DNS resolution to ensure that any domain is resolved
            # to the local HTTP server setup for the compatibility tests
            with _fake_dns_resolution("127.0.0.1"):
                verified = responses[i].simple_verify(
                    achalls[i].chall, achalls[i].domain,
                    util.JWK.public_key(), port=plugin.http_port)
            if verified:
                logger.info(
                    "http-01 verification for %s succeeded", achalls[i].domain)
            else:
                logger.error(
                    "**** http-01 verification for %s in %s failed",
                    achalls[i].domain, config)
                success = False

    if success:
        try:
            plugin.cleanup(achalls)
        except le_errors.Error:
            logger.error("Challenge cleanup for %s caused an error:", config, exc_info=True)
            success = False

        if _dirs_are_unequal(config, backup):
            logger.error("Challenge cleanup failed for %s", config)
            return False
        else:
            logger.info("Challenge cleanup succeeded")

    return success


def _create_achalls(plugin):
    """Returns a list of annotated challenges to test on plugin"""
    achalls = list()
    names = plugin.get_testable_domain_names()
    for domain in names:
        prefs = plugin.get_chall_pref(domain)
        for chall_type in prefs:
            if chall_type == challenges.HTTP01:
                chall = challenges.HTTP01(
                    token=os.urandom(challenges.HTTP01.TOKEN_SIZE))
                challb = acme_util.chall_to_challb(
                    chall, messages.STATUS_PENDING)
                achall = achallenges.KeyAuthorizationAnnotatedChallenge(
                    challb=challb, domain=domain, account_key=util.JWK)
                achalls.append(achall)

    return achalls


def test_installer(args, plugin, config, temp_dir):
    """Tests plugin as an installer"""
    backup = _create_backup(config, temp_dir)

    names_match = plugin.get_all_names() == plugin.get_all_names_answer()
    if names_match:
        logger.info("get_all_names test succeeded")
    else:
        logger.error("**** get_all_names test failed for config %s", config)

    domains = list(plugin.get_testable_domain_names())
    success = test_deploy_cert(plugin, temp_dir, domains)

    if success and args.enhance:
        success = test_enhancements(plugin, domains)

    good_rollback = test_rollback(plugin, config, backup)
    return names_match and success and good_rollback


def test_deploy_cert(plugin, temp_dir, domains):
    """Tests deploy_cert returning True if the tests are successful"""
    cert = crypto_util.gen_ss_cert(util.KEY, domains)
    cert_path = os.path.join(temp_dir, "cert.pem")
    with open(cert_path, "w") as f:
        f.write(OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, cert))

    for domain in domains:
        try:
            plugin.deploy_cert(domain, cert_path, util.KEY_PATH, cert_path, cert_path)
            plugin.save()  # Needed by the Apache plugin
        except le_errors.Error:
            logger.error("**** Plugin failed to deploy certificate for %s:", domain, exc_info=True)
            return False

    if not _save_and_restart(plugin, "deployed"):
        return False

    success = True
    time.sleep(3)
    for domain in domains:
        verified = validator.Validator().certificate(
            cert, domain, "127.0.0.1", plugin.https_port)
        if not verified:
            logger.error("**** Could not verify certificate for domain %s", domain)
            success = False

    if success:
        logger.info("HTTPS validation succeeded")

    return success


def test_enhancements(plugin, domains):
    """Tests supported enhancements returning True if successful"""
    supported = plugin.supported_enhancements()

    if "redirect" not in supported:
        logger.error("The plugin and this program support no common "
                     "enhancements")
        return False

    domains_and_info = [(domain, []) for domain in domains]  # type: List[Tuple[str, List[bool]]]

    for domain, info in domains_and_info:
        try:
            previous_redirect = validator.Validator().any_redirect(
                "localhost", plugin.http_port, headers={"Host": domain})
            info.append(previous_redirect)
            plugin.enhance(domain, "redirect")
            plugin.save()  # Needed by the Apache plugin
        except le_errors.PluginError as error:
            # Don't immediately fail because a redirect may already be enabled
            logger.warning("*** Plugin failed to enable redirect for %s:", domain)
            logger.warning("%s", error)
        except le_errors.Error:
            logger.error("*** An error occurred while enabling redirect for %s:",
                         domain, exc_info=True)

    if not _save_and_restart(plugin, "enhanced"):
        return False

    success = True
    for domain, info in domains_and_info:
        previous_redirect = info[0]
        if not previous_redirect:
            verified = validator.Validator().redirect(
                "localhost", plugin.http_port, headers={"Host": domain})
            if not verified:
                logger.error("*** Improper redirect for domain %s", domain)
                success = False

    if success:
        logger.info("Enhancements test succeeded")

    return success


def _save_and_restart(plugin, title=None):
    """Saves and restart the plugin, returning True if no errors occurred"""
    try:
        plugin.save(title)
        plugin.restart()
        return True
    except le_errors.Error:
        logger.error("*** Plugin failed to save and restart server:", exc_info=True)
        return False


def test_rollback(plugin, config, backup):
    """Tests the rollback checkpoints function"""
    try:
        plugin.rollback_checkpoints(1337)
    except le_errors.Error:
        logger.error("*** Plugin raised an exception during rollback:", exc_info=True)
        return False

    if _dirs_are_unequal(config, backup):
        logger.error("*** Rollback failed for config `%s`", config)
        return False
    logger.info("Rollback succeeded")
    return True


def _create_backup(config, temp_dir):
    """Creates a backup of config in temp_dir"""
    backup = os.path.join(temp_dir, "backup")
    shutil.rmtree(backup, ignore_errors=True)
    shutil.copytree(config, backup, symlinks=True)

    return backup


def _dirs_are_unequal(dir1, dir2):
    """Returns True if dir1 and dir2 are unequal"""
    dircmps = [filecmp.dircmp(dir1, dir2)]
    while dircmps:
        dircmp = dircmps.pop()
        if dircmp.left_only or dircmp.right_only:
            logger.error("The following files and directories are only "
                         "present in one directory")
            if dircmp.left_only:
                logger.error(str(dircmp.left_only))
            else:
                logger.error(str(dircmp.right_only))
            return True
        elif dircmp.common_funny or dircmp.funny_files:
            logger.error("The following files and directories could not be "
                         "compared:")
            if dircmp.common_funny:
                logger.error(str(dircmp.common_funny))
            else:
                logger.error(str(dircmp.funny_files))
            return True
        elif dircmp.diff_files:
            logger.error("The following files differ:")
            logger.error(str(dircmp.diff_files))
            return True

        for subdir in dircmp.subdirs.itervalues():
            dircmps.append(subdir)

    return False


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
        args.auth = args.install = args.enhance = True

    return args


def setup_logging(args):
    """Prepares logging for the program"""
    handler = logging.StreamHandler()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.ERROR - args.verbose_count * 10)
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
        overall_success = True
        while plugin.has_more_configs():
            success = True

            try:
                config = plugin.load_config()
                logger.info("Loaded configuration: %s", config)
                if args.auth:
                    success = test_authenticator(plugin, config, temp_dir)
                if success and args.install:
                    success = test_installer(args, plugin, config, temp_dir)
            except errors.Error:
                logger.error("Tests on %s raised:", config, exc_info=True)
                success = False

            if success:
                logger.info("All tests on %s succeeded", config)
            else:
                overall_success = False
                logger.error("Tests on %s failed", config)
    finally:
        plugin.cleanup_from_tests()

    if overall_success:
        logger.warning("All compatibility tests succeeded")
        sys.exit(0)
    else:
        logger.warning("One or more compatibility tests failed")
        sys.exit(1)


@contextlib.contextmanager
def _fake_dns_resolution(resolved_ip):
    """Monkey patch urllib3 to make any hostname be resolved to the provided IP"""
    _original_create_connection = connection.create_connection

    def _patched_create_connection(address, *args, **kwargs):
        _, port = address
        return _original_create_connection((resolved_ip, port), *args, **kwargs)

    try:
        connection.create_connection = _patched_create_connection
        yield
    finally:
        connection.create_connection = _original_create_connection


if __name__ == "__main__":
    main()
