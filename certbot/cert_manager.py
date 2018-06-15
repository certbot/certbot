"""Tools for managing certificates."""
import datetime
import logging
import os
import pytz
import re
import traceback
import zope.component

from acme.magic_typing import List  # pylint: disable=unused-import, no-name-in-module
from certbot import crypto_util
from certbot import errors
from certbot import interfaces
from certbot import ocsp
from certbot import storage
from certbot import util

from certbot.display import util as display_util

logger = logging.getLogger(__name__)

###################
# Commands
###################

def update_live_symlinks(config):
    """Update the certificate file family symlinks to use archive_dir.

    Use the information in the config file to make symlinks point to
    the correct archive directory.

    .. note:: This assumes that the installation is using a Reverter object.

    :param config: Configuration.
    :type config: :class:`certbot.configuration.NamespaceConfig`

    """
    for renewal_file in storage.renewal_conf_files(config):
        storage.RenewableCert(renewal_file, config, update_symlinks=True)

def rename_lineage(config):
    """Rename the specified lineage to the new name.

    :param config: Configuration.
    :type config: :class:`certbot.configuration.NamespaceConfig`

    """
    disp = zope.component.getUtility(interfaces.IDisplay)

    certname = get_certnames(config, "rename")[0]

    new_certname = config.new_certname
    if not new_certname:
        code, new_certname = disp.input(
            "Enter the new name for certificate {0}".format(certname),
            flag="--updated-cert-name", force_interactive=True)
        if code != display_util.OK or not new_certname:
            raise errors.Error("User ended interaction.")

    lineage = lineage_for_certname(config, certname)
    if not lineage:
        raise errors.ConfigurationError("No existing certificate with name "
            "{0} found.".format(certname))
    storage.rename_renewal_config(certname, new_certname, config)
    disp.notification("Successfully renamed {0} to {1}."
        .format(certname, new_certname), pause=False)

def certificates(config):
    """Display information about certs configured with Certbot

    :param config: Configuration.
    :type config: :class:`certbot.configuration.NamespaceConfig`
    """
    parsed_certs = []
    parse_failures = []
    for renewal_file in storage.renewal_conf_files(config):
        try:
            renewal_candidate = storage.RenewableCert(renewal_file, config)
            crypto_util.verify_renewable_cert(renewal_candidate)
            parsed_certs.append(renewal_candidate)
        except Exception as e:  # pylint: disable=broad-except
            logger.warning("Renewal configuration file %s produced an "
                           "unexpected error: %s. Skipping.", renewal_file, e)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            parse_failures.append(renewal_file)

    # Describe all the certs
    _describe_certs(config, parsed_certs, parse_failures)

def delete(config):
    """Delete Certbot files associated with a certificate lineage."""
    certnames = get_certnames(config, "delete", allow_multiple=True)
    for certname in certnames:
        storage.delete_files(config, certname)
        disp = zope.component.getUtility(interfaces.IDisplay)
        disp.notification("Deleted all files relating to certificate {0}."
            .format(certname), pause=False)

###################
# Public Helpers
###################

def lineage_for_certname(cli_config, certname):
    """Find a lineage object with name certname."""
    configs_dir = cli_config.renewal_configs_dir
    # Verify the directory is there
    util.make_or_verify_dir(configs_dir, mode=0o755, uid=os.geteuid())
    try:
        renewal_file = storage.renewal_file_for_certname(cli_config, certname)
    except errors.CertStorageError:
        return None
    try:
        return storage.RenewableCert(renewal_file, cli_config)
    except (errors.CertStorageError, IOError):
        logger.debug("Renewal conf file %s is broken.", renewal_file)
        logger.debug("Traceback was:\n%s", traceback.format_exc())
        return None

def domains_for_certname(config, certname):
    """Find the domains in the cert with name certname."""
    lineage = lineage_for_certname(config, certname)
    return lineage.names() if lineage else None

def find_duplicative_certs(config, domains):
    """Find existing certs that match the given domain names.

    This function searches for certificates whose domains are equal to
    the `domains` parameter and certificates whose domains are a subset
    of the domains in the `domains` parameter. If multiple certificates
    are found whose names are a subset of `domains`, the one whose names
    are the largest subset of `domains` is returned.

    If multiple certificates' domains are an exact match or equally
    sized subsets, which matching certificates are returned is
    undefined.

    :param config: Configuration.
    :type config: :class:`certbot.configuration.NamespaceConfig`
    :param domains: List of domain names
    :type domains: `list` of `str`

    :returns: lineages representing the identically matching cert and the
        largest subset if they exist
    :rtype: `tuple` of `storage.RenewableCert` or `None`

    """
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

def _archive_files(candidate_lineage, filetype):
    """ In order to match things like:
        /etc/letsencrypt/archive/example.com/chain1.pem.

        Anonymous functions which call this function are eventually passed (in a list) to
        `match_and_check_overlaps` to help specify the acceptable_matches.

        :param `.storage.RenewableCert` candidate_lineage: Lineage whose archive dir is to
            be searched.
        :param str filetype: main file name prefix e.g. "fullchain" or "chain".

        :returns: Files in candidate_lineage's archive dir that match the provided filetype.
        :rtype: list of str or None
    """
    archive_dir = candidate_lineage.archive_dir
    pattern = [os.path.join(archive_dir, f) for f in os.listdir(archive_dir)
                    if re.match("{0}[0-9]*.pem".format(filetype), f)]
    if len(pattern) > 0:
        return pattern
    else:
        return None

def _acceptable_matches():
    """ Generates the list that's passed to match_and_check_overlaps. Is its own function to
    make unit testing easier.

    :returns: list of functions
    :rtype: list
    """
    return [lambda x: x.fullchain_path, lambda x: x.cert_path,
            lambda x: _archive_files(x, "cert"), lambda x: _archive_files(x, "fullchain")]

def cert_path_to_lineage(cli_config):
    """ If config.cert_path is defined, try to find an appropriate value for config.certname.

    :param `configuration.NamespaceConfig` cli_config: parsed command line arguments

    :returns: a lineage name
    :rtype: str

    :raises `errors.Error`: If the specified cert path can't be matched to a lineage name.
    :raises `errors.OverlappingMatchFound`: If the matched lineage's archive is shared.
    """
    acceptable_matches = _acceptable_matches()
    match = match_and_check_overlaps(cli_config, acceptable_matches,
            lambda x: cli_config.cert_path[0], lambda x: x.lineagename)
    return match[0]

def match_and_check_overlaps(cli_config, acceptable_matches, match_func, rv_func):
    """ Searches through all lineages for a match, and checks for duplicates.
    If a duplicate is found, an error is raised, as performing operations on lineages
    that have their properties incorrectly duplicated elsewhere is probably a bad idea.

    :param `configuration.NamespaceConfig` cli_config: parsed command line arguments
    :param list acceptable_matches: a list of functions that specify acceptable matches
    :param function match_func: specifies what to match
    :param function rv_func: specifies what to return

    """
    def find_matches(candidate_lineage, return_value, acceptable_matches):
        """Returns a list of matches using _search_lineages."""
        acceptable_matches = [func(candidate_lineage) for func in acceptable_matches]
        acceptable_matches_rv = []  # type: List[str]
        for item in acceptable_matches:
            if isinstance(item, list):
                acceptable_matches_rv += item
            else:
                acceptable_matches_rv.append(item)
        match = match_func(candidate_lineage)
        if match in acceptable_matches_rv:
            return_value.append(rv_func(candidate_lineage))
        return return_value

    matched = _search_lineages(cli_config, find_matches, [], acceptable_matches)
    if not matched:
        raise errors.Error("No match found for cert-path {0}!".format(cli_config.cert_path[0]))
    elif len(matched) > 1:
        raise errors.OverlappingMatchFound()
    else:
        return matched

def human_readable_cert_info(config, cert, skip_filter_checks=False):
    """ Returns a human readable description of info about a RenewableCert object"""
    certinfo = []
    checker = ocsp.RevocationChecker()

    if config.certname and cert.lineagename != config.certname and not skip_filter_checks:
        return ""
    if config.domains and not set(config.domains).issubset(cert.names()):
        return ""
    now = pytz.UTC.fromutc(datetime.datetime.utcnow())

    reasons = []
    if cert.is_test_cert:
        reasons.append('TEST_CERT')
    if cert.target_expiry <= now:
        reasons.append('EXPIRED')
    if checker.ocsp_revoked(cert.cert, cert.chain):
        reasons.append('REVOKED')

    if reasons:
        status = "INVALID: " + ", ".join(reasons)
    else:
        diff = cert.target_expiry - now
        if diff.days == 1:
            status = "VALID: 1 day"
        elif diff.days < 1:
            status = "VALID: {0} hour(s)".format(diff.seconds // 3600)
        else:
            status = "VALID: {0} days".format(diff.days)

    valid_string = "{0} ({1})".format(cert.target_expiry, status)
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
    return "".join(certinfo)

def get_certnames(config, verb, allow_multiple=False, custom_prompt=None):
    """Get certname from flag, interactively, or error out.
    """
    certname = config.certname
    if certname:
        certnames = [certname]
    else:
        disp = zope.component.getUtility(interfaces.IDisplay)
        filenames = storage.renewal_conf_files(config)
        choices = [storage.lineagename_for_filename(name) for name in filenames]
        if not choices:
            raise errors.Error("No existing certificates found.")
        if allow_multiple:
            if not custom_prompt:
                prompt = "Which certificate(s) would you like to {0}?".format(verb)
            else:
                prompt = custom_prompt
            code, certnames = disp.checklist(
                prompt, choices, cli_flag="--cert-name", force_interactive=True)
            if code != display_util.OK:
                raise errors.Error("User ended interaction.")
        else:
            if not custom_prompt:
                prompt = "Which certificate would you like to {0}?".format(verb)
            else:
                prompt = custom_prompt

            code, index = disp.menu(
                prompt, choices, cli_flag="--cert-name", force_interactive=True)

            if code != display_util.OK or index not in range(0, len(choices)):
                raise errors.Error("User ended interaction.")
            certnames = [choices[index]]
    return certnames

###################
# Private Helpers
###################

def _report_lines(msgs):
    """Format a results report for a category of single-line renewal outcomes"""
    return "  " + "\n  ".join(str(msg) for msg in msgs)

def _report_human_readable(config, parsed_certs):
    """Format a results report for a parsed cert"""
    certinfo = []
    for cert in parsed_certs:
        certinfo.append(human_readable_cert_info(config, cert))
    return "\n".join(certinfo)

def _describe_certs(config, parsed_certs, parse_failures):
    """Print information about the certs we know about"""
    out = []  # type: List[str]

    notify = out.append

    if not parsed_certs and not parse_failures:
        notify("No certs found.")
    else:
        if parsed_certs:
            match = "matching " if config.certname or config.domains else ""
            notify("Found the following {0}certs:".format(match))
            notify(_report_human_readable(config, parsed_certs))
        if parse_failures:
            notify("\nThe following renewal configuration files "
               "were invalid:")
            notify(_report_lines(parse_failures))

    disp = zope.component.getUtility(interfaces.IDisplay)
    disp.notification("\n".join(out), pause=False, wrap=False)

def _search_lineages(cli_config, func, initial_rv, *args):
    """Iterate func over unbroken lineages, allowing custom return conditions.

    Allows flexible customization of return values, including multiple
    return values and complex checks.

    :param `configuration.NamespaceConfig` cli_config: parsed command line arguments
    :param function func: function used while searching over lineages
    :param initial_rv: initial return value of the function (any type)

    :returns: Whatever was specified by `func` if a match is found.
    """
    configs_dir = cli_config.renewal_configs_dir
    # Verify the directory is there
    util.make_or_verify_dir(configs_dir, mode=0o755, uid=os.geteuid())

    rv = initial_rv
    for renewal_file in storage.renewal_conf_files(cli_config):
        try:
            candidate_lineage = storage.RenewableCert(renewal_file, cli_config)
        except (errors.CertStorageError, IOError):
            logger.debug("Renewal conf file %s is broken. Skipping.", renewal_file)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            continue
        rv = func(candidate_lineage, rv, *args)
    return rv
