"""Tools for managing certificates."""
import copy
import logging
import traceback
import zope.component

from certbot import configuration
from certbot import interfaces
from certbot import renewal
from certbot import storage

logger = logging.getLogger(__name__)

def update_live_symlinks(config):
    """Update the certificate file family symlinks to use archive_dir.

    Use the information in the config file to make symlinks point to
    the correct archive directory.

    .. note:: This assumes that the installation is using a Reverter object.

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`

    """
    renewer_config = configuration.RenewerConfiguration(config)
    for renewal_file in renewal.renewal_conf_files(renewer_config):
        storage.RenewableCert(renewal_file,
            configuration.RenewerConfiguration(renewer_config),
            update_symlinks=True)

def _report(msgs):
    "Format a results report for a category of renewal outcomes"
    certinfo = [str(msg) for msg in msgs]
    return "  " + "\n  ".join(certinfo)

def _describe_certs(config, parsed_certs, parse_failures):
    """Print information about the certs we know about"""
    out = []

    notify = out.append

    if not parsed_certs and not parse_failures:
        notify("No certs found.")
    else:
        if parsed_certs:
            notify("Found the following certs:")
            notify(_report(parsed_certs))
        if parse_failures:
            notify("\nThe following renewal configuration files "
               "were invalid:")
            notify(_report(parse_failures))

    if config.quiet:
        return
    disp = zope.component.getUtility(interfaces.IDisplay)
    disp.notification("\n".join(out), pause=False)

def list_certs(config):
    """Display information about the certificates that Certbot knows about

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`
    """
    renewer_config = configuration.RenewerConfiguration(config)
    parsed_certs = []
    parse_failures = []
    for renewal_file in renewal.renewal_conf_files(renewer_config):
        lineage_config = copy.deepcopy(config)

        # Note that this modifies config (to add back the configuration
        # elements from within the renewal configuration file).
        try:
            renewal_candidate = storage.RenewableCert(renewal_file,
                configuration.RenewerConfiguration(lineage_config))
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Renewal configuration file %s produced an "
                           "unexpected error: %s. Skipping.", renewal_file, e)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            parse_failures.append(renewal_file)
            continue

        if renewal_candidate is None:
            parse_failures.append(renewal_file)
        else:
            parsed_certs.append(renewal_candidate)

    # Describe all the certs
    _describe_certs(config, parsed_certs, parse_failures)
