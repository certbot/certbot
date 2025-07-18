"""Tools for managing certificates."""
import datetime
import logging
import re
import traceback
from typing import Any
from typing import Callable
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
from typing import TypeVar
from typing import Union

from certbot import configuration
from certbot import crypto_util
from certbot import errors
from certbot import ocsp
from certbot import util
from certbot._internal import storage
from certbot.compat import os
from certbot.display import util as display_util

logger = logging.getLogger(__name__)

###################
# Commands
###################


def rename_lineage(config: configuration.NamespaceConfig) -> None:
    """Rename the specified lineage to the new name.

    :param config: Configuration.
    :type config: :class:`certbot._internal.configuration.NamespaceConfig`

    """
    certname = get_certnames(config, "rename")[0]

    new_certname = config.new_certname
    if not new_certname:
        code, new_certname = display_util.input_text(
            "Enter the new name for certificate {0}".format(certname),
            force_interactive=True)
        if code != display_util.OK or not new_certname:
            raise errors.Error("User ended interaction.")

    lineage = lineage_for_certname(config, certname)
    if not lineage:
        raise errors.ConfigurationError("No existing certificate with name "
            "{0} found.".format(certname))
    storage.rename_renewal_config(certname, new_certname, config)
    display_util.notification("Successfully renamed {0} to {1}."
                                 .format(certname, new_certname), pause=False)


def certificates(config: configuration.NamespaceConfig) -> None:
    """Display information about certs configured with Certbot

    :param config: Configuration.
    :type config: :class:`certbot._internal.configuration.NamespaceConfig`
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


def delete(config: configuration.NamespaceConfig) -> None:
    """Delete Certbot files associated with a certificate lineage."""
    certnames = get_certnames(config, "delete", allow_multiple=True)
    msg = ["The following certificate(s) are selected for deletion:\n"]
    for certname in certnames:
        msg.append("  * " + certname)
    msg.append(
        "\nWARNING: Before continuing, ensure that the listed certificates are not being used "
        "by any installed server software (e.g. Apache, nginx, mail servers). Deleting a "
        "certificate that is still being used will cause the server software to stop working. "
        "See https://certbot.org/deleting-certs for information on deleting certificates safely."
    )
    msg.append("\nAre you sure you want to delete the above certificate(s)?")
    if not display_util.yesno("\n".join(msg), default=True):
        logger.info("Deletion of certificate(s) canceled.")
        return
    for certname in certnames:
        storage.delete_files(config, certname)
        display_util.notify("Deleted all files relating to certificate {0}."
                            .format(certname))

###################
# Public Helpers
###################


def lineage_for_certname(cli_config: configuration.NamespaceConfig,
                         certname: str) -> Optional[storage.RenewableCert]:
    """Find a lineage object with name certname."""
    configs_dir = cli_config.renewal_configs_dir
    # Verify the directory is there
    util.make_or_verify_dir(configs_dir, mode=0o755)
    try:
        renewal_file = storage.renewal_file_for_certname(cli_config, certname)
    except errors.CertStorageError:
        return None
    try:
        return storage.RenewableCert(renewal_file, cli_config)
    except (OSError, errors.CertStorageError):
        logger.debug("Renewal conf file %s is broken.", renewal_file)
        logger.debug("Traceback was:\n%s", traceback.format_exc())
        return None


def domains_for_certname(config: configuration.NamespaceConfig,
                         certname: str) -> Optional[List[str]]:
    """Find the domains in the cert with name certname."""
    lineage = lineage_for_certname(config, certname)
    return lineage.names() if lineage else None


def find_duplicative_certs(config: configuration.NamespaceConfig,
                           domains: List[str]) -> Tuple[Optional[storage.RenewableCert],
                                                        Optional[storage.RenewableCert]]:
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
    :type config: :class:`certbot._internal.configuration.NamespaceConfig`
    :param domains: List of domain names
    :type domains: `list` of `str`

    :returns: lineages representing the identically matching cert and the
        largest subset if they exist
    :rtype: `tuple` of `storage.RenewableCert` or `None`

    """
    def update_certs_for_domain_matches(candidate_lineage: storage.RenewableCert,
                                        rv: Tuple[Optional[storage.RenewableCert],
                                                  Optional[storage.RenewableCert]]
                                        ) -> Tuple[Optional[storage.RenewableCert],
                                                   Optional[storage.RenewableCert]]:
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

    init: Tuple[Optional[storage.RenewableCert], Optional[storage.RenewableCert]] = (None, None)

    return _search_lineages(config, update_certs_for_domain_matches, init)


def _archive_files(candidate_lineage: storage.RenewableCert, filetype: str) -> Optional[List[str]]:
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
    if pattern:
        return pattern
    return None


def _acceptable_matches() -> List[Union[Callable[[storage.RenewableCert], str],
                                        Callable[[storage.RenewableCert], Optional[List[str]]]]]:
    """ Generates the list that's passed to match_and_check_overlaps. Is its own function to
    make unit testing easier.

    :returns: list of functions
    :rtype: list
    """
    return [lambda x: x.fullchain_path, lambda x: x.cert_path,
            lambda x: _archive_files(x, "cert"), lambda x: _archive_files(x, "fullchain")]


def cert_path_to_lineage(cli_config: configuration.NamespaceConfig) -> str:
    """ If config.cert_path is defined, try to find an appropriate value for config.certname.

    :param `configuration.NamespaceConfig` cli_config: parsed command line arguments

    :returns: a lineage name
    :rtype: str

    :raises `errors.Error`: If the specified cert path can't be matched to a lineage name.
    :raises `errors.OverlappingMatchFound`: If the matched lineage's archive is shared.
    """
    acceptable_matches = _acceptable_matches()
    match = match_and_check_overlaps(cli_config, acceptable_matches,
                                     lambda x: cli_config.cert_path, lambda x: x.lineagename)
    return match[0]


def match_and_check_overlaps(cli_config: configuration.NamespaceConfig,
                             acceptable_matches: Iterable[Union[
                                 Callable[[storage.RenewableCert], str],
                                 Callable[[storage.RenewableCert], Optional[List[str]]]]],
                             match_func: Callable[[storage.RenewableCert], str],
                             rv_func: Callable[[storage.RenewableCert], str]) -> List[str]:
    """ Searches through all lineages for a match, and checks for duplicates.
    If a duplicate is found, an error is raised, as performing operations on lineages
    that have their properties incorrectly duplicated elsewhere is probably a bad idea.

    :param `configuration.NamespaceConfig` cli_config: parsed command line arguments
    :param list acceptable_matches: a list of functions that specify acceptable matches
    :param function match_func: specifies what to match
    :param function rv_func: specifies what to return

    """
    def find_matches(candidate_lineage: storage.RenewableCert, return_value: List[str],
                     acceptable_matches: Iterable[Union[
                         Callable[[storage.RenewableCert], str],
                         Callable[[storage.RenewableCert], Optional[List[str]]]]]) -> List[str]:
        """Returns a list of matches using _search_lineages."""
        acceptable_matches_resolved = [func(candidate_lineage) for func in acceptable_matches]
        acceptable_matches_rv: List[str] = []
        for item in acceptable_matches_resolved:
            if isinstance(item, list):
                acceptable_matches_rv += item
            elif item:
                acceptable_matches_rv.append(item)
        match = match_func(candidate_lineage)
        if match in acceptable_matches_rv:
            return_value.append(rv_func(candidate_lineage))
        return return_value

    matched: List[str] = _search_lineages(cli_config, find_matches, [], acceptable_matches)
    if not matched:
        raise errors.Error(f"No match found for cert-path {cli_config.cert_path}!")
    elif len(matched) > 1:
        raise errors.OverlappingMatchFound()
    return matched


def human_readable_cert_info(config: configuration.NamespaceConfig, cert: storage.RenewableCert,
                             skip_filter_checks: bool = False) -> Optional[str]:
    """ Returns a human readable description of info about a RenewableCert object"""
    certinfo = []
    checker = ocsp.RevocationChecker()

    if config.certname and cert.lineagename != config.certname and not skip_filter_checks:
        return None
    if config.domains and not set(config.domains).issubset(cert.names()):
        return None
    now = datetime.datetime.now(datetime.timezone.utc)

    reasons = []
    if cert.is_test_cert:
        reasons.append('TEST_CERT')
    if cert.target_expiry <= now:
        reasons.append('EXPIRED')
    elif checker.ocsp_revoked(cert):
        reasons.append('REVOKED')

    if reasons:
        status = "INVALID: " + ", ".join(reasons)
    else:
        diff = cert.target_expiry - now
        if diff.days == 1:
            status = "VALID: 1 day"
        elif diff.days < 1:
            status = f"VALID: {diff.seconds // 3600} hour(s)"
        else:
            status = f"VALID: {diff.days} days"

    valid_string = "{0} ({1})".format(cert.target_expiry, status)
    serial = format(crypto_util.get_serial_from_cert(cert.cert_path), 'x')
    certinfo.append(f"  Certificate Name: {cert.lineagename}\n"
                    f"    Serial Number: {serial}\n"
                    f"    Key Type: {cert.private_key_type}\n"
                    f'    Domains: {" ".join(cert.names())}\n'
                    f"    Expiry Date: {valid_string}\n"
                    f"    Certificate Path: {cert.fullchain}\n"
                    f"    Private Key Path: {cert.privkey}")
    return "".join(certinfo)


def get_certnames(config: configuration.NamespaceConfig, verb: str, allow_multiple: bool = False,
                  custom_prompt: Optional[str] = None) -> List[str]:
    """Get certname from flag, interactively, or error out."""
    certname = config.certname
    if certname:
        certnames = [certname]
    else:
        filenames = storage.renewal_conf_files(config)
        choices = [storage.lineagename_for_filename(name) for name in filenames]
        if not choices:
            raise errors.Error("No existing certificates found.")
        if allow_multiple:
            if not custom_prompt:
                prompt = "Which certificate(s) would you like to {0}?".format(verb)
            else:
                prompt = custom_prompt
            code, certnames = display_util.checklist(
                prompt, choices, cli_flag="--cert-name", force_interactive=True)
            if code != display_util.OK:
                raise errors.Error("User ended interaction.")
        else:
            if not custom_prompt:
                prompt = "Which certificate would you like to {0}?".format(verb)
            else:
                prompt = custom_prompt

            code, index = display_util.menu(
                prompt, choices, cli_flag="--cert-name", force_interactive=True)

            if code != display_util.OK or index not in range(0, len(choices)):
                raise errors.Error("User ended interaction.")
            certnames = [choices[index]]
    return certnames

###################
# Private Helpers
###################


def _report_lines(msgs: Iterable[str]) -> str:
    """Format a results report for a category of single-line renewal outcomes"""
    return "  " + "\n  ".join(str(msg) for msg in msgs)


def _report_human_readable(config: configuration.NamespaceConfig,
                           parsed_certs: Iterable[storage.RenewableCert]) -> str:
    """Format a results report for a parsed cert"""
    certinfo = []
    for cert in parsed_certs:
        cert_info = human_readable_cert_info(config, cert)
        if cert_info is not None:
            certinfo.append(cert_info)
    return "\n".join(certinfo)


def _describe_certs(config: configuration.NamespaceConfig,
                    parsed_certs: Iterable[storage.RenewableCert],
                    parse_failures: Iterable[str]) -> None:
    """Print information about the certs we know about"""
    out: List[str] = []

    notify = out.append

    if not parsed_certs and not parse_failures:
        notify("No certificates found.")
    else:
        if parsed_certs:
            match = "matching " if config.certname or config.domains else ""
            notify("Found the following {0}certs:".format(match))
            notify(_report_human_readable(config, parsed_certs))
        if parse_failures:
            notify("\nThe following renewal configurations "
               "were invalid:")
            notify(_report_lines(parse_failures))

    display_util.notification("\n".join(out), pause=False, wrap=False)


T = TypeVar('T')

def _search_lineages(cli_config: configuration.NamespaceConfig, func: Callable[..., T],
                     initial_rv: T, *args: Any) -> T:
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
    util.make_or_verify_dir(configs_dir, mode=0o755)

    rv = initial_rv
    for renewal_file in storage.renewal_conf_files(cli_config):
        try:
            candidate_lineage = storage.RenewableCert(renewal_file, cli_config)
        except (OSError, errors.CertStorageError):
            logger.debug("Renewal conf file %s is broken. Skipping.", renewal_file)
            logger.debug("Traceback was:\n%s", traceback.format_exc())
            continue
        rv = func(candidate_lineage, rv, *args)
    return rv
