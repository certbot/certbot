"""Contains UI methods for LE user operations."""
import logging
from textwrap import indent
from typing import Any
from typing import Callable
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple

from certbot import errors
from certbot import interfaces
from certbot import util
from certbot._internal import account
from certbot._internal.display import util as internal_display_util
from certbot.compat import os
from certbot.display import util as display_util

logger = logging.getLogger(__name__)


def get_email(invalid: bool = False, optional: bool = True) -> str:
    """Prompt for valid email address.

    :param bool invalid: True if an invalid address was provided by the user
    :param bool optional: True if the user can use
        --register-unsafely-without-email to avoid providing an e-mail

    :returns: e-mail address
    :rtype: str

    :raises errors.Error: if the user cancels

    """
    invalid_prefix = "There seem to be problems with that address. "
    msg = "Enter email address (used for urgent renewal and security notices)\n"
    unsafe_suggestion = ("\n\nIf you really want to skip this, you can run "
                         "the client with --register-unsafely-without-email "
                         "but you will then be unable to receive notice about "
                         "impending expiration or revocation of your "
                         "certificates or problems with your Certbot "
                         "installation that will lead to failure to renew.\n\n")
    if optional:
        if invalid:
            msg += unsafe_suggestion
            suggest_unsafe = False
        else:
            suggest_unsafe = True
    else:
        suggest_unsafe = False

    while True:
        try:
            code, email = display_util.input_text(invalid_prefix + msg if invalid else msg,
                                                  force_interactive=True)
        except errors.MissingCommandlineFlag:
            msg = ("You should register before running non-interactively, "
                   "or provide --agree-tos and --email <email_address> flags.")
            raise errors.MissingCommandlineFlag(msg)

        if code != display_util.OK:
            if optional:
                raise errors.Error(
                    "An e-mail address or "
                    "--register-unsafely-without-email must be provided.")
            raise errors.Error("An e-mail address must be provided.")
        if util.safe_email(email):
            return email
        if suggest_unsafe:
            msg = unsafe_suggestion + msg
            suggest_unsafe = False  # add this message at most once

        invalid = bool(email)


def choose_account(accounts: List[account.Account]) -> Optional[account.Account]:
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


def choose_values(values: List[str], question: Optional[str] = None) -> List[str]:
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
                 question: Optional[str] = None) -> List[str]:
    """Display screen to select domains to validate.

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

    code, names = _filter_names(names, question)
    if code == display_util.OK and names:
        return names
    return []


def get_valid_domains(domains: Iterable[str]) -> List[str]:
    """Helper method for choose_names that implements basic checks
     on domain names

    :param list domains: Domain names to validate
    :return: List of valid domains
    :rtype: list
    """
    valid_domains: List[str] = []
    for domain in domains:
        try:
            valid_domains.append(util.enforce_domain_sanity(domain))
        except errors.ConfigurationError:
            continue
    return valid_domains


def _sort_names(FQDNs: Iterable[str]) -> List[str]:
    """Sort FQDNs by SLD (and if many, by their subdomains)

    :param list FQDNs: list of domain names

    :returns: Sorted list of domain names
    :rtype: list
    """
    return sorted(FQDNs, key=lambda fqdn: fqdn.split('.')[::-1][1:])


def _filter_names(names: Iterable[str],
                  override_question: Optional[str] = None) -> Tuple[str, List[str]]:
    """Determine which names the user would like to select from a list.

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
    code, names = display_util.checklist(
        question, tags=sorted_names, cli_flag="--domains", force_interactive=True)
    return code, [str(s) for s in names]


def _choose_names_manually(prompt_prefix: str = "") -> List[str]:
    """Manually input names for those without an installer.

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

        for i, domain in enumerate(domain_list):
            try:
                domain_list[i] = util.enforce_domain_sanity(domain)
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
            return domain_list
    return []


def success_installation(domains: List[str]) -> None:
    """Display a box confirming the installation of HTTPS.

    :param list domains: domain names which were enabled

    """
    display_util.notify(
        "Congratulations! You have successfully enabled HTTPS on {0}"
        .format(_gen_https_names(domains))
    )


def success_renewal(unused_domains: List[str]) -> None:
    """Display a box confirming the renewal of an existing certificate.

    :param list domains: domain names which were renewed

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


def _gen_https_names(domains: List[str]) -> str:
    """Returns a string of the https domains.

    Domains are formatted nicely with ``https://`` prepended to each.

    :param list domains: Each domain is a 'str'

    """
    if len(domains) == 1:
        return "https://{0}".format(domains[0])
    elif len(domains) == 2:
        return "https://{dom[0]} and https://{dom[1]}".format(dom=domains)
    elif len(domains) > 2:
        return "{0}{1}{2}".format(
            ", ".join("https://%s" % dom for dom in domains[:-1]),
            ", and https://",
            domains[-1])

    return ""


def _get_validated(method: Callable[..., Tuple[str, str]],
                   validator: Callable[[str], Any], message: str,
                   default: Optional[str] = None, **kwargs: Any) -> Tuple[str, str]:
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
                    *args: Any, **kwargs: Any) -> Tuple[str, str]:
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
                        *args: Any, **kwargs: Any) -> Tuple[str, str]:
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
