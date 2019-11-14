"""Functionality for autorenewal and associated juggling of configurations"""
from __future__ import print_function

import copy
import itertools
import logging
import random
import sys
import time
import traceback

import OpenSSL
import six
import zope.component

from acme.magic_typing import List  # pylint: disable=unused-import, no-name-in-module

from certbot._internal import cli
from certbot import crypto_util
from certbot import errors
from certbot._internal import hooks
from certbot import interfaces
from certbot._internal import storage
from certbot._internal import updater
from certbot import util
from certbot.compat import os
from certbot._internal.plugins import disco as plugins_disco

logger = logging.getLogger(__name__)

# These are the items which get pulled out of a renewal configuration
# file's renewalparams and actually used in the client configuration
# during the renewal process. We have to record their types here because
# the renewal configuration process loses this information.
STR_CONFIG_ITEMS = ["config_dir", "logs_dir", "work_dir", "user_agent",
                    "server", "account", "authenticator", "installer",
                    "renew_hook", "pre_hook", "post_hook", "http01_address"]
INT_CONFIG_ITEMS = ["rsa_key_size", "http01_port"]
BOOL_CONFIG_ITEMS = ["must_staple", "allow_subset_of_names", "reuse_key",
                     "autorenew"]

CONFIG_ITEMS = set(itertools.chain(
    BOOL_CONFIG_ITEMS, INT_CONFIG_ITEMS, STR_CONFIG_ITEMS, ('pref_challs',)))


def _reconstitute(config, full_path):
    """Try to instantiate a RenewableCert, updating config with relevant items.

    This is specifically for use in renewal and enforces several checks
    and policies to ensure that we can try to proceed with the renewal
    request. The config argument is modified by including relevant options
    read from the renewal configuration file.

    :param configuration.NamespaceConfig config: configuration for the
        current lineage
    :param str full_path: Absolute path to the configuration file that
        defines this lineage

    :returns: the RenewableCert object or None if a fatal error occurred
    :rtype: `storage.RenewableCert` or NoneType

    """
    try:
        renewal_candidate = storage.RenewableCert(full_path, config)
    except (errors.CertStorageError, IOError):
        logger.warning("", exc_info=True)
        logger.warning("Renewal configuration file %s is broken. Skipping.", full_path)
        logger.debug("Traceback was:\n%s", traceback.format_exc())
        return None
    if "renewalparams" not in renewal_candidate.configuration:
        logger.warning("Renewal configuration file %s lacks "
                       "renewalparams. Skipping.", full_path)
        return None
    renewalparams = renewal_candidate.configuration["renewalparams"]
    if "authenticator" not in renewalparams:
        logger.warning("Renewal configuration file %s does not specify "
                       "an authenticator. Skipping.", full_path)
        return None
    # Now restore specific values along with their data types, if
    # those elements are present.
    try:
        restore_required_config_elements(config, renewalparams)
        _restore_plugin_configs(config, renewalparams)
    except (ValueError, errors.Error) as error:
        logger.warning(
            "An error occurred while parsing %s. The error was %s. "
            "Skipping the file.", full_path, str(error))
        logger.debug("Traceback was:\n%s", traceback.format_exc())
        return None

    try:
        config.domains = [util.enforce_domain_sanity(d)
                          for d in renewal_candidate.names()]
    except errors.ConfigurationError as error:
        logger.warning("Renewal configuration file %s references a cert "
                       "that contains an invalid domain name. The problem "
                       "was: %s. Skipping.", full_path, error)
        return None

    return renewal_candidate


def _restore_webroot_config(config, renewalparams):
    """
    webroot_map is, uniquely, a dict, and the general-purpose configuration
    restoring logic is not able to correctly parse it from the serialized
    form.
    """
    if "webroot_map" in renewalparams and not cli.set_by_cli("webroot_map"):
        config.webroot_map = renewalparams["webroot_map"]
    # To understand why webroot_path and webroot_map processing are not mutually exclusive,
    # see https://github.com/certbot/certbot/pull/7095
    if "webroot_path" in renewalparams and not cli.set_by_cli("webroot_path"):
        wp = renewalparams["webroot_path"]
        if isinstance(wp, six.string_types):  # prior to 0.1.0, webroot_path was a string
            wp = [wp]
        config.webroot_path = wp


def _restore_plugin_configs(config, renewalparams):
    """Sets plugin specific values in config from renewalparams

    :param configuration.NamespaceConfig config: configuration for the
        current lineage
    :param configobj.Section renewalparams: Parameters from the renewal
        configuration file that defines this lineage

    """
    # Now use parser to get plugin-prefixed items with correct types
    # XXX: the current approach of extracting only prefixed items
    #      related to the actually-used installer and authenticator
    #      works as long as plugins don't need to read plugin-specific
    #      variables set by someone else (e.g., assuming Apache
    #      configurator doesn't need to read webroot_ variables).
    # Note: if a parameter that used to be defined in the parser is no
    #      longer defined, stored copies of that parameter will be
    #      deserialized as strings by this logic even if they were
    #      originally meant to be some other type.
    plugin_prefixes = []  # type: List[str]
    if renewalparams["authenticator"] == "webroot":
        _restore_webroot_config(config, renewalparams)
    else:
        plugin_prefixes.append(renewalparams["authenticator"])

    if renewalparams.get("installer") is not None:
        plugin_prefixes.append(renewalparams["installer"])

    for plugin_prefix in set(plugin_prefixes):
        plugin_prefix = plugin_prefix.replace('-', '_')
        for config_item, config_value in six.iteritems(renewalparams):
            if config_item.startswith(plugin_prefix + "_") and not cli.set_by_cli(config_item):
                # Values None, True, and False need to be treated specially,
                # As their types aren't handled correctly by configobj
                if config_value in ("None", "True", "False"):
                    # bool("False") == True
                    # pylint: disable=eval-used
                    setattr(config, config_item, eval(config_value))
                else:
                    cast = cli.argparse_type(config_item)
                    setattr(config, config_item, cast(config_value))


def restore_required_config_elements(config, renewalparams):
    """Sets non-plugin specific values in config from renewalparams

    :param configuration.NamespaceConfig config: configuration for the
        current lineage
    :param configobj.Section renewalparams: parameters from the renewal
        configuration file that defines this lineage

    """

    required_items = itertools.chain(
        (("pref_challs", _restore_pref_challs),),
        six.moves.zip(BOOL_CONFIG_ITEMS, itertools.repeat(_restore_bool)),
        six.moves.zip(INT_CONFIG_ITEMS, itertools.repeat(_restore_int)),
        six.moves.zip(STR_CONFIG_ITEMS, itertools.repeat(_restore_str)))
    for item_name, restore_func in required_items:
        if item_name in renewalparams and not cli.set_by_cli(item_name):
            value = restore_func(item_name, renewalparams[item_name])
            setattr(config, item_name, value)


def _restore_pref_challs(unused_name, value):
    """Restores preferred challenges from a renewal config file.

    If value is a `str`, it should be a single challenge type.

    :param str unused_name: option name
    :param value: option value
    :type value: `list` of `str` or `str`

    :returns: converted option value to be stored in the runtime config
    :rtype: `list` of `str`

    :raises errors.Error: if value can't be converted to an bool

    """
    # If pref_challs has only one element, configobj saves the value
    # with a trailing comma so it's parsed as a list. If this comma is
    # removed by the user, the value is parsed as a str.
    value = [value] if isinstance(value, six.string_types) else value
    return cli.parse_preferred_challenges(value)


def _restore_bool(name, value):
    """Restores an boolean key-value pair from a renewal config file.

    :param str name: option name
    :param str value: option value

    :returns: converted option value to be stored in the runtime config
    :rtype: bool

    :raises errors.Error: if value can't be converted to an bool

    """
    lowercase_value = value.lower()
    if lowercase_value not in ("true", "false"):
        raise errors.Error(
            "Expected True or False for {0} but found {1}".format(name, value))
    return lowercase_value == "true"


def _restore_int(name, value):
    """Restores an integer key-value pair from a renewal config file.

    :param str name: option name
    :param str value: option value

    :returns: converted option value to be stored in the runtime config
    :rtype: int

    :raises errors.Error: if value can't be converted to an int

    """
    if name == "http01_port" and value == "None":
        logger.info("updating legacy http01_port value")
        return cli.flag_default("http01_port")

    try:
        return int(value)
    except ValueError:
        raise errors.Error("Expected a numeric value for {0}".format(name))


def _restore_str(unused_name, value):
    """Restores an string key-value pair from a renewal config file.

    :param str unused_name: option name
    :param str value: option value

    :returns: converted option value to be stored in the runtime config
    :rtype: str or None

    """
    return None if value == "None" else value


def should_renew(config, lineage):
    "Return true if any of the circumstances for automatic renewal apply."
    if config.renew_by_default:
        logger.debug("Auto-renewal forced with --force-renewal...")
        return True
    if lineage.should_autorenew():
        logger.info("Cert is due for renewal, auto-renewing...")
        return True
    if config.dry_run:
        logger.info("Cert not due for renewal, but simulating renewal for dry run")
        return True
    logger.info("Cert not yet due for renewal")
    return False


def _avoid_invalidating_lineage(config, lineage, original_server):
    "Do not renew a valid cert with one from a staging server!"
    # Some lineages may have begun with --staging, but then had production certs
    # added to them
    with open(lineage.cert) as the_file:
        contents = the_file.read()
    latest_cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, contents)
    # all our test certs are from happy hacker fake CA, though maybe one day
    # we should test more methodically
    now_valid = "fake" not in repr(latest_cert.get_issuer()).lower()

    if util.is_staging(config.server):
        if not util.is_staging(original_server) or now_valid:
            if not config.break_my_certs:
                names = ", ".join(lineage.names())
                raise errors.Error(
                    "You've asked to renew/replace a seemingly valid certificate with "
                    "a test certificate (domains: {0}). We will not do that "
                    "unless you use the --break-my-certs flag!".format(names))


def renew_cert(config, domains, le_client, lineage):
    "Renew a certificate lineage."
    renewal_params = lineage.configuration["renewalparams"]
    original_server = renewal_params.get("server", cli.flag_default("server"))
    _avoid_invalidating_lineage(config, lineage, original_server)
    if not domains:
        domains = lineage.names()
    # The private key is the existing lineage private key if reuse_key is set.
    # Otherwise, generate a fresh private key by passing None.
    new_key = os.path.normpath(lineage.privkey) if config.reuse_key else None
    new_cert, new_chain, new_key, _ = le_client.obtain_certificate(domains, new_key)
    if config.dry_run:
        logger.debug("Dry run: skipping updating lineage at %s",
                    os.path.dirname(lineage.cert))
    else:
        prior_version = lineage.latest_common_version()
        # TODO: Check return value of save_successor
        lineage.save_successor(prior_version, new_cert, new_key.pem, new_chain, config)
        lineage.update_all_links_to(lineage.latest_common_version())

    hooks.renew_hook(config, domains, lineage.live_dir)


def report(msgs, category):
    "Format a results report for a category of renewal outcomes"
    lines = ("%s (%s)" % (m, category) for m in msgs)
    return "  " + "\n  ".join(lines)

def _renew_describe_results(config, renew_successes, renew_failures,
                            renew_skipped, parse_failures):

    out = []  # type: List[str]
    notify = out.append
    disp = zope.component.getUtility(interfaces.IDisplay)

    def notify_error(err):
        """Notify and log errors."""
        notify(str(err))
        logger.error(err)

    if config.dry_run:
        notify("** DRY RUN: simulating 'certbot renew' close to cert expiry")
        notify("**          (The test certificates below have not been saved.)")
    notify("")
    if renew_skipped:
        notify("The following certs are not due for renewal yet:")
        notify(report(renew_skipped, "skipped"))
    if not renew_successes and not renew_failures:
        notify("No renewals were attempted.")
        if (config.pre_hook is not None or
                config.renew_hook is not None or config.post_hook is not None):
            notify("No hooks were run.")
    elif renew_successes and not renew_failures:
        notify("Congratulations, all renewals succeeded. The following certs "
               "have been renewed:")
        notify(report(renew_successes, "success"))
    elif renew_failures and not renew_successes:
        notify_error("All renewal attempts failed. The following certs could "
               "not be renewed:")
        notify_error(report(renew_failures, "failure"))
    elif renew_failures and renew_successes:
        notify("The following certs were successfully renewed:")
        notify(report(renew_successes, "success") + "\n")
        notify_error("The following certs could not be renewed:")
        notify_error(report(renew_failures, "failure"))

    if parse_failures:
        notify("\nAdditionally, the following renewal configurations "
               "were invalid: ")
        notify(report(parse_failures, "parsefail"))

    if config.dry_run:
        notify("** DRY RUN: simulating 'certbot renew' close to cert expiry")
        notify("**          (The test certificates above have not been saved.)")

    disp.notification("\n".join(out), wrap=False)


def handle_renewal_request(config):
    """Examine each lineage; renew if due and report results"""

    # This is trivially False if config.domains is empty
    if any(domain not in config.webroot_map for domain in config.domains):
        # If more plugins start using cli.add_domains,
        # we may want to only log a warning here
        raise errors.Error("Currently, the renew verb is capable of either "
                           "renewing all installed certificates that are due "
                           "to be renewed or renewing a single certificate specified "
                           "by its name. If you would like to renew specific "
                           "certificates by their domains, use the certonly command "
                           "instead. The renew verb may provide other options "
                           "for selecting certificates to renew in the future.")

    if config.certname:
        conf_files = [storage.renewal_file_for_certname(config, config.certname)]
    else:
        conf_files = storage.renewal_conf_files(config)

    renew_successes = []
    renew_failures = []
    renew_skipped = []
    parse_failures = []

    # Noninteractive renewals include a random delay in order to spread
    # out the load on the certificate authority servers, even if many
    # users all pick the same time for renewals.  This delay precedes
    # running any hooks, so that side effects of the hooks (such as
    # shutting down a web service) aren't prolonged unnecessarily.
    apply_random_sleep = not sys.stdin.isatty() and config.random_sleep_on_renew

    for renewal_file in conf_files:
        disp = zope.component.getUtility(interfaces.IDisplay)
        disp.notification("Processing " + renewal_file, pause=False)
        lineage_config = copy.deepcopy(config)
        lineagename = storage.lineagename_for_filename(renewal_file)

        # Note that this modifies config (to add back the configuration
        # elements from within the renewal configuration file).
        try:
            renewal_candidate = _reconstitute(lineage_config, renewal_file)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Renewal configuration file %s (cert: %s) "
                           "produced an unexpected error: %s. Skipping.",
                           renewal_file, lineagename, e)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            parse_failures.append(renewal_file)
            continue

        try:
            if renewal_candidate is None:
                parse_failures.append(renewal_file)
            else:
                # XXX: ensure that each call here replaces the previous one
                zope.component.provideUtility(lineage_config)
                renewal_candidate.ensure_deployed()
                from certbot._internal import main
                plugins = plugins_disco.PluginsRegistry.find_all()
                if should_renew(lineage_config, renewal_candidate):
                    # Apply random sleep upon first renewal if needed
                    if apply_random_sleep:
                        sleep_time = random.uniform(1, 60 * 8)
                        logger.info("Non-interactive renewal: random delay of %s seconds",
                                    sleep_time)
                        time.sleep(sleep_time)
                        # We will sleep only once this day, folks.
                        apply_random_sleep = False

                    # domains have been restored into lineage_config by reconstitute
                    # but they're unnecessary anyway because renew_cert here
                    # will just grab them from the certificate
                    # we already know it's time to renew based on should_renew
                    # and we have a lineage in renewal_candidate
                    main.renew_cert(lineage_config, plugins, renewal_candidate)
                    renew_successes.append(renewal_candidate.fullchain)
                else:
                    expiry = crypto_util.notAfter(renewal_candidate.version(
                        "cert", renewal_candidate.latest_common_version()))
                    renew_skipped.append("%s expires on %s" % (renewal_candidate.fullchain,
                                         expiry.strftime("%Y-%m-%d")))
                # Run updater interface methods
                updater.run_generic_updaters(lineage_config, renewal_candidate,
                                             plugins)

        except Exception as e:  # pylint: disable=broad-except
            # obtain_cert (presumably) encountered an unanticipated problem.
            logger.warning("Attempting to renew cert (%s) from %s produced an "
                           "unexpected error: %s. Skipping.", lineagename,
                               renewal_file, e)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            renew_failures.append(renewal_candidate.fullchain)

    # Describe all the results
    _renew_describe_results(config, renew_successes, renew_failures,
                            renew_skipped, parse_failures)

    if renew_failures or parse_failures:
        raise errors.Error("{0} renew failure(s), {1} parse failure(s)".format(
            len(renew_failures), len(parse_failures)))
    else:
        logger.debug("no renewal failures")
