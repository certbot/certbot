"""Functionality for autorenewal and associated juggling of configurations"""
from __future__ import print_function
import copy
import glob
import logging
import os
import traceback

import six
import zope.component

import OpenSSL

from certbot import configuration
from certbot import cli
from certbot import constants

from certbot import crypto_util
from certbot import errors
from certbot import interfaces
from certbot import le_util
from certbot import hooks
from certbot import storage
from certbot.plugins import disco as plugins_disco

logger = logging.getLogger(__name__)

# These are the items which get pulled out of a renewal configuration
# file's renewalparams and actually used in the client configuration
# during the renewal process. We have to record their types here because
# the renewal configuration process loses this information.
STR_CONFIG_ITEMS = ["config_dir", "logs_dir", "work_dir", "user_agent",
                    "server", "account", "authenticator", "installer",
                    "standalone_supported_challenges"]
INT_CONFIG_ITEMS = ["rsa_key_size", "tls_sni_01_port", "http01_port"]


def renewal_conf_files(config):
    """Return /path/to/*.conf in the renewal conf directory"""
    return glob.glob(os.path.join(config.renewal_configs_dir, "*.conf"))


def _reconstitute(config, full_path):
    """Try to instantiate a RenewableCert, updating config with relevant items.

    This is specifically for use in renewal and enforces several checks
    and policies to ensure that we can try to proceed with the renwal
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
        renewal_candidate = storage.RenewableCert(
            full_path, configuration.RenewerConfiguration(config))
    except (errors.CertStorageError, IOError):
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
        _restore_required_config_elements(config, renewalparams)
        _restore_plugin_configs(config, renewalparams)
    except (ValueError, errors.Error) as error:
        logger.warning(
            "An error occurred while parsing %s. The error was %s. "
            "Skipping the file.", full_path, error.message)
        logger.debug("Traceback was:\n%s", traceback.format_exc())
        return None

    try:
        config.domains = [le_util.enforce_domain_sanity(d)
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
    if "webroot_map" in renewalparams:
        if not cli.set_by_cli("webroot_map"):
            config.namespace.webroot_map = renewalparams["webroot_map"]
    elif "webroot_path" in renewalparams:
        logger.info("Ancient renewal conf file without webroot-map, restoring webroot-path")
        wp = renewalparams["webroot_path"]
        if isinstance(wp, str):  # prior to 0.1.0, webroot_path was a string
            wp = [wp]
        config.namespace.webroot_path = wp


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
    if renewalparams["authenticator"] == "webroot":
        _restore_webroot_config(config, renewalparams)
        plugin_prefixes = []
    else:
        plugin_prefixes = [renewalparams["authenticator"]]

    if renewalparams.get("installer", None) is not None:
        plugin_prefixes.append(renewalparams["installer"])
    for plugin_prefix in set(plugin_prefixes):
        for config_item, config_value in six.iteritems(renewalparams):
            if config_item.startswith(plugin_prefix + "_") and not cli.set_by_cli(config_item):
                # Values None, True, and False need to be treated specially,
                # As their types aren't handled correctly by configobj
                if config_value in ("None", "True", "False"):
                    # bool("False") == True
                    # pylint: disable=eval-used
                    setattr(config.namespace, config_item, eval(config_value))
                else:
                    cast = cli.argparse_type(config_item)
                    setattr(config.namespace, config_item, cast(config_value))


def _restore_required_config_elements(config, renewalparams):
    """Sets non-plugin specific values in config from renewalparams

    :param configuration.NamespaceConfig config: configuration for the
        current lineage
    :param configobj.Section renewalparams: parameters from the renewal
        configuration file that defines this lineage

    """
    # string-valued items to add if they're present
    for config_item in STR_CONFIG_ITEMS:
        if config_item in renewalparams and not cli.set_by_cli(config_item):
            value = renewalparams[config_item]
            # Unfortunately, we've lost type information from ConfigObj,
            # so we don't know if the original was NoneType or str!
            if value == "None":
                value = None
            setattr(config.namespace, config_item, value)
    # int-valued items to add if they're present
    for config_item in INT_CONFIG_ITEMS:
        if config_item in renewalparams and not cli.set_by_cli(config_item):
            config_value = renewalparams[config_item]
            # the default value for http01_port was None during private beta
            if config_item == "http01_port" and config_value == "None":
                logger.info("updating legacy http01_port value")
                int_value = cli.flag_default("http01_port")
            else:
                try:
                    int_value = int(config_value)
                except ValueError:
                    raise errors.Error(
                        "Expected a numeric value for {0}".format(config_item))
            setattr(config.namespace, config_item, int_value)


def should_renew(config, lineage):
    "Return true if any of the circumstances for automatic renewal apply."
    if config.renew_by_default:
        logger.info("Auto-renewal forced with --force-renewal...")
        return True
    if lineage.should_autorenew(interactive=True):
        logger.info("Cert is due for renewal, auto-renewing...")
        return True
    if config.dry_run:
        logger.info("Cert not due for renewal, but simulating renewal for dry run")
        return True
    logger.info("Cert not yet due for renewal")
    return False


def _avoid_invalidating_lineage(config, lineage, original_server):
    "Do not renew a valid cert with one from a staging server!"
    def _is_staging(srv):
        return srv == constants.STAGING_URI or "staging" in srv

    # Some lineages may have begun with --staging, but then had production certs
    # added to them
    latest_cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, open(lineage.cert).read())
    # all our test certs are from happy hacker fake CA, though maybe one day
    # we should test more methodically
    now_valid = "fake" not in repr(latest_cert.get_issuer()).lower()

    if _is_staging(config.server):
        if not _is_staging(original_server) or now_valid:
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
    new_certr, new_chain, new_key, _ = le_client.obtain_certificate(domains)
    if config.dry_run:
        logger.info("Dry run: skipping updating lineage at %s",
                    os.path.dirname(lineage.cert))
    else:
        prior_version = lineage.latest_common_version()
        new_cert = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_PEM, new_certr.body.wrapped)
        new_chain = crypto_util.dump_pyopenssl_chain(new_chain)
        renewal_conf = configuration.RenewerConfiguration(config.namespace)
        # TODO: Check return value of save_successor
        lineage.save_successor(prior_version, new_cert, new_key.pem, new_chain, renewal_conf)
        lineage.update_all_links_to(lineage.latest_common_version())

    hooks.renew_hook(config, domains, lineage.live_dir)


def report(msgs, category):
    "Format a results report for a category of renewal outcomes"
    lines = ("%s (%s)" % (m, category) for m in msgs)
    return "  " + "\n  ".join(lines)

def _renew_describe_results(config, renew_successes, renew_failures,
                            renew_skipped, parse_failures):

    out = []
    notify = out.append

    if config.dry_run:
        notify("** DRY RUN: simulating 'certbot renew' close to cert expiry")
        notify("**          (The test certificates below have not been saved.)")
    notify("")
    if renew_skipped:
        notify("The following certs are not due for renewal yet:")
        notify(report(renew_skipped, "skipped"))
    if not renew_successes and not renew_failures:
        notify("No renewals were attempted.")
    elif renew_successes and not renew_failures:
        notify("Congratulations, all renewals succeeded. The following certs "
               "have been renewed:")
        notify(report(renew_successes, "success"))
    elif renew_failures and not renew_successes:
        notify("All renewal attempts failed. The following certs could not be "
               "renewed:")
        notify(report(renew_failures, "failure"))
    elif renew_failures and renew_successes:
        notify("The following certs were successfully renewed:")
        notify(report(renew_successes, "success"))
        notify("\nThe following certs could not be renewed:")
        notify(report(renew_failures, "failure"))

    if parse_failures:
        notify("\nAdditionally, the following renewal configuration files "
               "were invalid: ")
        notify(report(parse_failures, "parsefail"))

    if config.dry_run:
        notify("** DRY RUN: simulating 'certbot renew' close to cert expiry")
        notify("**          (The test certificates above have not been saved.)")

    if config.quiet and not (renew_failures or parse_failures):
        return
    print("\n".join(out))


def renew_all_lineages(config):
    """Examine each lineage; renew if due and report results"""

    if config.domains != []:
        raise errors.Error("Currently, the renew verb is only capable of "
                           "renewing all installed certificates that are due "
                           "to be renewed; individual domains cannot be "
                           "specified with this action. If you would like to "
                           "renew specific certificates, use the certonly "
                           "command. The renew verb may provide other options "
                           "for selecting certificates to renew in the future.")
    renewer_config = configuration.RenewerConfiguration(config)
    renew_successes = []
    renew_failures = []
    renew_skipped = []
    parse_failures = []
    for renewal_file in renewal_conf_files(renewer_config):
        disp = zope.component.getUtility(interfaces.IDisplay)
        disp.notification("Processing " + renewal_file, pause=False)
        lineage_config = copy.deepcopy(config)

        # Note that this modifies config (to add back the configuration
        # elements from within the renewal configuration file).
        try:
            renewal_candidate = _reconstitute(lineage_config, renewal_file)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Renewal configuration file %s produced an "
                           "unexpected error: %s. Skipping.", renewal_file, e)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            parse_failures.append(renewal_file)
            continue

        try:
            if renewal_candidate is None:
                parse_failures.append(renewal_file)
            else:
                # XXX: ensure that each call here replaces the previous one
                zope.component.provideUtility(lineage_config)
                if should_renew(lineage_config, renewal_candidate):
                    plugins = plugins_disco.PluginsRegistry.find_all()
                    from certbot import main
                    main.obtain_cert(lineage_config, plugins, renewal_candidate)
                    renew_successes.append(renewal_candidate.fullchain)
                else:
                    renew_skipped.append(renewal_candidate.fullchain)
        except Exception as e:  # pylint: disable=broad-except
            # obtain_cert (presumably) encountered an unanticipated problem.
            logger.warning("Attempting to renew cert from %s produced an "
                           "unexpected error: %s. Skipping.", renewal_file, e)
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
