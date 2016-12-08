"""Tools for managing certificates."""
import datetime
import logging
import os
import pytz
import traceback
import zope.component

from certbot import configuration
from certbot import errors
from certbot import interfaces
from certbot import renewal
from certbot import storage
from certbot import util

from certbot.display import util as display_util

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

def rename_lineage(config):
    """Rename the specified lineage to the new name.

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`

    """
    disp = zope.component.getUtility(interfaces.IDisplay)
    renewer_config = configuration.RenewerConfiguration(config)

    certname = config.certname
    if not certname:
        filenames = renewal.renewal_conf_files(renewer_config)
        choices = [storage.lineagename_for_filename(name) for name in filenames]
        if not choices:
            raise errors.Error("No existing certificates found.")
        code, index = disp.menu("Which certificate would you like to rename?",
            choices, ok_label="Select", flag="--cert-name")
        if code != display_util.OK or not index in range(0, len(choices)):
            raise errors.Error("User ended interaction.")
        certname = choices[index]

    new_certname = config.new_certname
    if not new_certname:
        code, new_certname = disp.input("Enter the new name for certificate {0}"
            .format(certname), flag="--updated-cert-name")
        if code != display_util.OK or not new_certname:
            raise errors.Error("User ended interaction.")

    lineage = lineage_for_certname(config, certname)
    if not lineage:
        raise errors.ConfigurationError("No existing certificate with name "
            "{0} found.".format(certname))
    storage.rename_renewal_config(certname, new_certname, renewer_config)
    disp.notification("Successfully renamed {0} to {1}."
        .format(certname, new_certname), pause=False)

def _report_lines(msgs):
    """Format a results report for a category of single-line renewal outcomes"""
    return "  " + "\n  ".join(str(msg) for msg in msgs)

def _report_human_readable(parsed_certs):
    """Format a results report for a parsed cert"""
    certinfo = []
    for cert in parsed_certs:
        now = pytz.UTC.fromutc(datetime.datetime.utcnow())
        if cert.is_test_cert:
            expiration_text = "INVALID: TEST CERT"
        elif cert.target_expiry <= now:
            expiration_text = "INVALID: EXPIRED"
        else:
            diff = cert.target_expiry - now
            if diff.days == 1:
                expiration_text = "VALID: 1 day"
            elif diff.days < 1:
                expiration_text = "VALID: {0} hour(s)".format(diff.seconds // 3600)
            else:
                expiration_text = "VALID: {0} days".format(diff.days)
        valid_string = "{0} ({1})".format(cert.target_expiry, expiration_text)
        certinfo.append("  Certificate Name: {0}\n"
                        "    Domains: {1}\n"
                        "    Expiry Date: {2}\n"
                        "    Certificate Path: {3}\n"
                        "    Private Key Path: {4}".format(
                            cert.lineagename,
                            " ".join(cert.names()),
                            valid_string,
                            cert.fullchain,
                            cert.privkey))
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
    disp.notification("\n".join(out), pause=False, wrap=False)

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

def _search_lineages(config, func, initial_rv):
    """Iterate func over unbroken lineages, allowing custom return conditions.

    Allows flexible customization of return values, including multiple
    return values and complex checks.
    """
    cli_config = configuration.RenewerConfiguration(config)
    configs_dir = cli_config.renewal_configs_dir
    # Verify the directory is there
    util.make_or_verify_dir(configs_dir, mode=0o755, uid=os.geteuid())

    rv = initial_rv
    for renewal_file in renewal.renewal_conf_files(cli_config):
        try:
            candidate_lineage = storage.RenewableCert(renewal_file, cli_config)
        except (errors.CertStorageError, IOError):
            logger.debug("Renewal conf file %s is broken. Skipping.", renewal_file)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            continue
        rv = func(candidate_lineage, rv)
    return rv

def lineage_for_certname(config, certname):
    """Find a lineage object with name certname."""
    def update_cert_for_name_match(candidate_lineage, rv):
        """Return cert if it has name certname, else return rv
        """
        matching_lineage_name_cert = rv
        if candidate_lineage.lineagename == certname:
            matching_lineage_name_cert = candidate_lineage
        return matching_lineage_name_cert
    return _search_lineages(config, update_cert_for_name_match, None)

def domains_for_certname(config, certname):
    """Find the domains in the cert with name certname."""
    def update_domains_for_name_match(candidate_lineage, rv):
        """Return domains if certname matches, else return rv
        """
        matching_domains = rv
        if candidate_lineage.lineagename == certname:
            matching_domains = candidate_lineage.names()
        return matching_domains
    return _search_lineages(config, update_domains_for_name_match, None)

def find_duplicative_certs(config, domains):
    """Find existing certs that duplicate the request."""
    def update_certs_for_domain_matches(candidate_lineage, rv):
        """Return cert as identical_names_cert if it matches,
           or subset_names_cert if it matches as subset
        """
        # TODO: Handle these differently depending on whether they are
        #       expired or still valid?
        identical_names_cert, subset_names_cert = rv
        candidate_names = set(candidate_lineage.names())
        if candidate_names == set(domains):
            identical_names_cert = candidate_lineage
        elif candidate_names.issubset(set(domains)):
            # This logic finds and returns the largest subset-names cert
            # in the case where there are several available.
            if subset_names_cert is None:
                subset_names_cert = candidate_lineage
            elif len(candidate_names) > len(subset_names_cert.names()):
                subset_names_cert = candidate_lineage
        return (identical_names_cert, subset_names_cert)

    return _search_lineages(config, update_certs_for_domain_matches, (None, None))
