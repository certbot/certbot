"""Contains UI methods for LE user operations."""
import logging
from textwrap import indent
from typing import Any
from typing import Callable
from typing import Iterable
from typing import Optional

from certbot import errors
from certbot import interfaces
from certbot import util
from certbot._internal import account
from certbot._internal import san
from certbot._internal.display import util as internal_display_util
from certbot.compat import os
from certbot.display import util as display_util

logger = logging.getLogger(__name__)


def get_email(invalid: bool = False, **kwargs: Any) -> str:
    """Prompt for valid email address.

    :param bool invalid: True if an invalid address was provided by the user

    :returns: e-mail address
    :rtype: str

    :raises errors.Error: if the user cancels

    """
    # pylint: disable=unused-argument
    invalid_prefix = ""
    if invalid:
        invalid_prefix = "The server reported a problem with your email address. "
    msg = "Enter email address or hit Enter to skip.\n"

    while True:
        code, email = display_util.input_text(invalid_prefix + msg, default="")

        if code != display_util.OK:
            raise errors.Error("Error getting email address.")
        if email == "":
            return ""
        if util.safe_email(email):
            return email
        invalid_prefix = "There is a problem with your email address. "


def choose_account(accounts: list[account.Account]) -> Optional[account.Account]:
    """Choose an account.

    :param list accounts: Containing at least one
        :class:`~certbot._internal.account.Account`

    """
    # Note this will get more complicated once we start recording authorizations
    labels = [acc.slug for acc in accounts]

    code, index = display_util.menu("Please choose an account", labels, force_interactive=True)
    if code == display_util.OK:
        return accounts[index]
    return None


def choose_values(values: list[str], question: Optional[str] = None) -> list[str]:
    """Display screen to let user pick one or multiple values from the provided
    list.

    :param list values: Values to select from
    :param str question: Question to ask to user while choosing values

    :returns: List of selected values
    :rtype: list
    """
    code, items = display_util.checklist(question if question else "", tags=values,
                                         force_interactive=True)
    if code == display_util.OK and items:
        return items
    return []


def choose_names(installer: Optional[interfaces.Installer],
                 question: Optional[str] = None) -> list[san.DNSName]:
    """Display screen to select domains to validate.

    Only returns domain names, not IP addresses, due to entanglement with the --domains CLI flag.

    :param installer: An installer object
    :type installer: :class:`certbot.interfaces.Installer`

    :param `str` question: Overriding default question to ask the user if asked
        to choose from domain names.

    :returns: List of selected names
    :rtype: `list` of `str`

    """
    if installer is None:
        logger.debug("No installer, picking names manually")
        return _choose_names_manually()

    domains = list(installer.get_all_names())
    names = get_valid_domains(domains)

    if not names:
        return _choose_names_manually()

    code, filtered_names = _filter_names(names, question)
    if code == display_util.OK and filtered_names:
        return filtered_names
    return []


def get_valid_domains(domains: Iterable[str]) -> list[san.DNSName]:
    """Helper method for choose_names that implements basic checks
     on domain names

    :param list domains: Domain names to validate
    :return: List of valid domains
    :rtype: list
    """
    valid_domains: list[san.DNSName] = []
    for domain in domains:
        try:
            valid_domains.append(san.DNSName(domain))
        except errors.ConfigurationError:
            continue
    return valid_domains


def _sort_names(FQDNs: Iterable[san.DNSName]) -> list[san.DNSName]:
    """Sort FQDNs by SLD (and if many, by their subdomains)

    :param list FQDNs: list of domain names

    :returns: Sorted list of domain names
    :rtype: list
    """
    return sorted(FQDNs, key=lambda fqdn: fqdn.dns_name.split('.')[::-1][1:])


def _filter_names(names: Iterable[san.DNSName],
                  override_question: Optional[str] = None) -> tuple[str, list[san.DNSName]]:
    """Determine which names the user would like to select from a list.

    Only handles domain names, not IP addresses, due to entanglement with the --domains CLI flag.

    :param list names: domain names

    :returns: tuple of the form (`code`, `names`) where
        `code` - str display exit code
        `names` - list of names selected
    :rtype: tuple

    """
    # Sort by domain first, and then by subdomain
    sorted_names = _sort_names(names)
    if override_question:
        question = override_question
    else:
        question = (
            "Which names would you like to activate HTTPS for?\n"
            "We recommend selecting either all domains, or all domains in a VirtualHost/server "
            "block.")
    sorted_name_strs = list(map(str, sorted_names))
    code, checked_names = display_util.checklist(
        question, tags=sorted_name_strs, cli_flag="--domains", force_interactive=True)
    return code, [san.DNSName(s) for s in checked_names]


def _choose_names_manually(prompt_prefix: str = "") -> list[san.DNSName]:
    """Manually input names for those without an installer.

    Only returns DNS names for now, due to entanglement with the --domains CLI flag.

    :param str prompt_prefix: string to prepend to prompt for domains

    :returns: list of provided names
    :rtype: `list` of `str`

    """
    code, input_ = display_util.input_text(
        prompt_prefix +
        "Please enter the domain name(s) you would like on your certificate "
        "(comma and/or space separated)",
        cli_flag="--domains", force_interactive=True)

    if code == display_util.OK:
        invalid_domains = {}
        retry_message = ""
        try:
            domain_list = internal_display_util.separate_list_input(input_)
        except UnicodeEncodeError:
            domain_list = []
            retry_message = (
                "Internationalized domain names are not presently "
                "supported.{0}{0}Would you like to re-enter the "
                "names?{0}").format(os.linesep)

        checked_domains = []
        for domain in domain_list:
            try:
                checked_domains.append(san.DNSName(domain))
            except errors.ConfigurationError as e:
                invalid_domains[domain] = str(e)

        if invalid_domains:
            retry_message = (
                "One or more of the entered domain names was not valid:"
                "{0}{0}").format(os.linesep)
            for invalid_domain, err in invalid_domains.items():
                retry_message = retry_message + "{1}: {2}{0}".format(
                    os.linesep, invalid_domain, err)
            retry_message = retry_message + (
                "{0}Would you like to re-enter the names?{0}").format(
                    os.linesep)

        if retry_message:
            # We had error in input
            retry = display_util.yesno(retry_message, force_interactive=True)
            if retry:
                return _choose_names_manually()
        else:
            return checked_domains
    return []


def success_installation(sans: list[san.SAN]) -> None:
    """Display a box confirming the installation of HTTPS.

    :param list sans: domain names and/or IP addresses which were enabled

    """
    display_util.notify(
        "Congratulations! You have successfully enabled HTTPS on {0}"
        .format(_gen_https_names(sans))
    )


def success_renewal(unused_sans: list[san.SAN]) -> None:
    """Display a box confirming the renewal of an existing certificate.

    :param list unused_sans: domain names and/or IP addresses which were renewed

    """
    display_util.notify(
        "Your existing certificate has been successfully renewed, and the "
        "new certificate has been installed."
    )


def success_revocation(cert_path: str) -> None:
    """Display a message confirming a certificate has been revoked.

    :param list cert_path: path to certificate which was revoked.

    """
    display_util.notify(
        "Congratulations! You have successfully revoked the certificate "
        "that was located at {0}.".format(cert_path)
    )


def report_executed_command(command_name: str, returncode: int, stdout: str, stderr: str) -> None:
    """Display a message describing the success or failure of an executed process (e.g. hook).

    :param str command_name: Human-readable description of the executed command
    :param int returncode: The exit code of the executed command
    :param str stdout: The stdout output of the executed command
    :param str stderr: The stderr output of the executed command

    """
    out_s, err_s = stdout.strip(), stderr.strip()
    if returncode != 0:
        logger.warning("%s reported error code %d", command_name, returncode)
    if out_s:
        display_util.notify(f"{command_name} ran with output:\n{indent(out_s, ' ')}")
    if err_s:
        logger.warning("%s ran with error output:\n%s", command_name, indent(err_s, ' '))


def _gen_https_names(sans: list[san.SAN]) -> str:
    """Returns a string of the https domains.

    Domains are formatted nicely with ``https://`` prepended to each.

    :param list sans: domains and/or IP addresses

    """
    if len(sans) == 1:
        return "https://{0}".format(sans[0])
    elif len(sans) == 2:
        return f"https://{sans[0]} and https://{sans[1]}"
    elif len(sans) > 2:
        return "{0}{1}{2}".format(
            ", ".join("https://%s" % s for s in sans[:-1]),
            ", and https://",
            sans[-1])

    return ""


def _get_validated(method: Callable[..., tuple[str, str]],
                   validator: Callable[[str], Any], message: str,
                   default: Optional[str] = None, **kwargs: Any) -> tuple[str, str]:
    if default is not None:
        try:
            validator(default)
        except errors.Error:
            logger.debug('Encountered invalid default value "%s" when prompting for "%s"',
                         default,
                         message,
                         exc_info=True)
            raise AssertionError('Invalid default "{0}"'.format(default))

    while True:
        code, raw = method(message, default=default, **kwargs)
        if code == display_util.OK:
            try:
                validator(raw)
                return code, raw
            except errors.Error as error:
                logger.debug('Validator rejected "%s" when prompting for "%s"',
                             raw,
                             message,
                             exc_info=True)
                display_util.notification(str(error), pause=False)
        else:
            return code, raw


def validated_input(validator: Callable[[str], Any],
                    *args: Any, **kwargs: Any) -> tuple[str, str]:
    """Like `~certbot.display.util.input_text`, but with validation.

    :param callable validator: A method which will be called on the
        supplied input. If the method raises an `errors.Error`, its
        text will be displayed and the user will be re-prompted.
    :param list `*args`: Arguments to be passed to `~certbot.display.util.input_text`.
    :param dict `**kwargs`: Arguments to be passed to `~certbot.display.util.input_text`.
    :return: as `~certbot.display.util.input_text`
    :rtype: tuple
    """
    return _get_validated(display_util.input_text, validator, *args, **kwargs)


def validated_directory(validator: Callable[[str], Any],
                        *args: Any, **kwargs: Any) -> tuple[str, str]:
    """Like `~certbot.display.util.directory_select`, but with validation.

    :param callable validator: A method which will be called on the
        supplied input. If the method raises an `errors.Error`, its
        text will be displayed and the user will be re-prompted.
    :param list `*args`: Arguments to be passed to `~certbot.display.util.directory_select`.
    :param dict `**kwargs`: Arguments to be passed to
        `~certbot.display.util.directory_select`.
    :return: as `~certbot.display.util.directory_select`
    :rtype: tuple
    """
    return _get_validated(display_util.directory_select, validator, *args, **kwargs)
