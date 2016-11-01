"""Tools for managing certificates."""
import datetime
import logging
import pytz
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

def _report_lines(msgs):
    """Format a results report for a category of single-line renewal outcomes"""
    return "  " + "\n  ".join(str(msg) for msg in msgs)

def _report_human_readable(parsed_certs):
    """Format a results report for a parsed cert"""
    certinfo = []
    for cert in parsed_certs:
        now = pytz.UTC.fromutc(datetime.datetime.utcnow())
        if cert.target_expiry <= now:
            expiration_text = "EXPIRED"
        else:
            diff = cert.target_expiry - now
            if diff.days == 1:
                expiration_text = "1 day"
            elif diff.days < 1:
                expiration_text = "under 1 day"
            else:
                expiration_text = "{0} days".format(diff.days)
        valid_string = "{0} ({1})".format(cert.target_expiry, expiration_text)
        out = "  Lineage: {0}\n    Domains: {1}\n    Valid Until: {2}".format(
            cert.lineagename, " ".join(cert.names()), valid_string)
        certinfo.append(out)
    return "\n".join(certinfo)

def _describe_certs(parsed_certs, parse_failures):
    """Print information about the certs we know about"""
    out = []

    notify = out.append

    if not parsed_certs and not parse_failures:
        notify("No certs found.")
    else:
        if parsed_certs:
            notify("Found the following certs:")
            notify(_report_human_readable(parsed_certs))
        if parse_failures:
            notify("\nThe following renewal configuration files "
               "were invalid:")
            notify(_report_lines(parse_failures))

    disp = zope.component.getUtility(interfaces.IDisplay)
    disp.notification("\n".join(out), pause=False)

def certificates(config):
    """Display information about certs configured with Certbot

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`
    """
    renewer_config = configuration.RenewerConfiguration(config)
    parsed_certs = []
    parse_failures = []
    for renewal_file in renewal.renewal_conf_files(renewer_config):
        try:
            renewal_candidate = storage.RenewableCert(renewal_file,
                configuration.RenewerConfiguration(config))
            parsed_certs.append(renewal_candidate)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Renewal configuration file %s produced an "
                           "unexpected error: %s. Skipping.", renewal_file, e)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            parse_failures.append(renewal_file)

    # Describe all the certs
    _describe_certs(parsed_certs, parse_failures)
