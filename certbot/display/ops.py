"""Contains UI methods for LE user operations."""
import logging
import os

import zope.component

from certbot import errors
from certbot import interfaces
from certbot import util
from certbot.display import util as display_util

logger = logging.getLogger(__name__)

# Define a helper function to avoid verbose code
z_util = zope.component.getUtility


def get_email(invalid=False, optional=True):
    """Prompt for valid email address.

    :param bool invalid: True if an invalid address was provided by the user
    :param bool optional: True if the user can use
        --register-unsafely-without-email to avoid providing an e-mail

    :returns: e-mail address
    :rtype: str

    :raises errors.Error: if the user cancels

    """
    invalid_prefix = "There seem to be problems with that address. "
    msg = "Enter email address (used for urgent notices and lost key recovery)"
    unsafe_suggestion = ("\n\nIf you really want to skip this, you can run "
                         "the client with --register-unsafely-without-email "
                         "but make sure you then backup your account key from "
                         "/etc/letsencrypt/accounts\n\n")
    if optional:
        if invalid:
            msg += unsafe_suggestion
        else:
            suggest_unsafe = True
    else:
        suggest_unsafe = False

    while True:
        try:
            code, email = z_util(interfaces.IDisplay).input(
                invalid_prefix + msg if invalid else msg)
        except errors.MissingCommandlineFlag:
            msg = ("You should register before running non-interactively, "
                   "or provide --agree-tos and --email <email_address> flags.")
            raise errors.MissingCommandlineFlag(msg)

        if code != display_util.OK:
            if optional:
                raise errors.Error(
                    "An e-mail address or "
                    "--register-unsafely-without-email must be provided.")
            else:
                raise errors.Error("An e-mail address must be provided.")
        elif util.safe_email(email):
            return email
        elif suggest_unsafe:
            msg += unsafe_suggestion
            suggest_unsafe = False  # add this message at most once

        invalid = bool(email)


def choose_account(accounts):
    """Choose an account.

    :param list accounts: Containing at least one
        :class:`~certbot.account.Account`

    """
    # Note this will get more complicated once we start recording authorizations
    labels = [acc.slug for acc in accounts]

    code, index = z_util(interfaces.IDisplay).menu(
        "Please choose an account", labels)
    if code == display_util.OK:
        return accounts[index]
    else:
        return None


def choose_names(installer):
    """Display screen to select domains to validate.

    :param installer: An installer object
    :type installer: :class:`certbot.interfaces.IInstaller`

    :returns: List of selected names
    :rtype: `list` of `str`

    """
    if installer is None:
        logger.debug("No installer, picking names manually")
        return _choose_names_manually()

    domains = list(installer.get_all_names())
    names = get_valid_domains(domains)

    if not names:
        return _choose_names_manually(
            "No names were found in your configuration files. ")

    code, names = _filter_names(names)
    if code == display_util.OK and names:
        return names
    else:
        return []


def get_valid_domains(domains):
    """Helper method for choose_names that implements basic checks
     on domain names

    :param list domains: Domain names to validate
    :return: List of valid domains
    :rtype: list
    """
    valid_domains = []
    for domain in domains:
        try:
            valid_domains.append(util.enforce_domain_sanity(domain))
        except errors.ConfigurationError:
            continue
    return valid_domains


def _filter_names(names):
    """Determine which names the user would like to select from a list.

    :param list names: domain names

    :returns: tuple of the form (`code`, `names`) where
        `code` - str display exit code
        `names` - list of names selected
    :rtype: tuple

    """
    code, names = z_util(interfaces.IDisplay).checklist(
        "Which names would you like to activate HTTPS for?",
        tags=names, cli_flag="--domains")
    return code, [str(s) for s in names]


def _choose_names_manually(prompt_prefix=""):
    """Manually input names for those without an installer.

    :param str prompt_prefix: string to prepend to prompt for domains

    :returns: list of provided names
    :rtype: `list` of `str`

    """
    code, input_ = z_util(interfaces.IDisplay).input(
        prompt_prefix +
        "Please enter in your domain name(s) (comma and/or space separated) ",
        cli_flag="--domains")

    if code == display_util.OK:
        invalid_domains = dict()
        retry_message = ""
        try:
            domain_list = display_util.separate_list_input(input_)
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
                try:  # Python 2
                    # pylint: disable=no-member
                    err_msg = e.message.encode('utf-8')
                except AttributeError:
                    err_msg = str(e)
                invalid_domains[domain] = err_msg

        if len(invalid_domains):
            retry_message = (
                "One or more of the entered domain names was not valid:"
                "{0}{0}").format(os.linesep)
            for domain in invalid_domains:
                retry_message = retry_message + "{1}: {2}{0}".format(
                    os.linesep, domain, invalid_domains[domain])
            retry_message = retry_message + (
                "{0}Would you like to re-enter the names?{0}").format(
                    os.linesep)

        if retry_message:
            # We had error in input
            retry = z_util(interfaces.IDisplay).yesno(retry_message)
            if retry:
                return _choose_names_manually()
        else:
            return domain_list
    return []


def success_installation(domains):
    """Display a box confirming the installation of HTTPS.

    .. todo:: This should be centered on the screen

    :param list domains: domain names which were enabled

    """
    z_util(interfaces.IDisplay).notification(
        "Congratulations! You have successfully enabled {0}{1}{1}"
        "You should test your configuration at:{1}{2}".format(
            _gen_https_names(domains),
            os.linesep,
            os.linesep.join(_gen_ssl_lab_urls(domains))),
        height=(10 + len(domains)),
        pause=False)


def success_renewal(domains, action):
    """Display a box confirming the renewal of an existing certificate.

    .. todo:: This should be centered on the screen

    :param list domains: domain names which were renewed
    :param str action: can be "reinstall" or "renew"

    """
    z_util(interfaces.IDisplay).notification(
        "Your existing certificate has been successfully {3}ed, and the "
        "new certificate has been installed.{1}{1}"
        "The new certificate covers the following domains: {0}{1}{1}"
        "You should test your configuration at:{1}{2}".format(
            _gen_https_names(domains),
            os.linesep,
            os.linesep.join(_gen_ssl_lab_urls(domains)),
            action),
        height=(14 + len(domains)),
        pause=False)


def _gen_ssl_lab_urls(domains):
    """Returns a list of urls.

    :param list domains: Each domain is a 'str'

    """
    return ["https://www.ssllabs.com/ssltest/analyze.html?d=%s" % dom for dom in domains]


def _gen_https_names(domains):
    """Returns a string of the https domains.

    Domains are formatted nicely with https:// prepended to each.

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
