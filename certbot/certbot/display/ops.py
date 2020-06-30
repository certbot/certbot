"""Contains UI methods for LE user operations."""
import logging

import zope.component

from certbot import errors
from certbot import interfaces
from certbot import util
from certbot.compat import misc
from certbot.compat import os
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
    msg = "Enter email address (used for urgent renewal and security notices)\n"
    unsafe_suggestion = ("\n\nIf you really want to skip this, you can run "
                         "the client with --register-unsafely-without-email "
                         "but make sure you then backup your account key from "
                         "{0}\n\n".format(os.path.join(
                             misc.get_default_folder('config'), 'accounts')))
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
            code, email = z_util(interfaces.IDisplay).input(
                invalid_prefix + msg if invalid else msg,
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


def choose_account(accounts):
    """Choose an account.

    :param list accounts: Containing at least one
        :class:`~certbot._internal.account.Account`

    """
    # Note this will get more complicated once we start recording authorizations
    labels = [acc.slug for acc in accounts]

    code, index = z_util(interfaces.IDisplay).menu(
        "Please choose an account", labels, force_interactive=True)
    if code == display_util.OK:
        return accounts[index]
    return None

def choose_values(values, question=None):
    """Display screen to let user pick one or multiple values from the provided
    list.

    :param list values: Values to select from

    :returns: List of selected values
    :rtype: list
    """
    code, items = z_util(interfaces.IDisplay).checklist(
        question, tags=values, force_interactive=True)
    if code == display_util.OK and items:
        return items
    return []

def choose_names(installer, question=None):
    """Display screen to select domains to validate.

    :param installer: An installer object
    :type installer: :class:`certbot.interfaces.IInstaller`

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
        return _choose_names_manually(
            "No names were found in your configuration files. ")

    code, names = _filter_names(names, question)
    if code == display_util.OK and names:
        return names
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

def _sort_names(FQDNs):
    """Sort FQDNs by SLD (and if many, by their subdomains)

    :param list FQDNs: list of domain names

    :returns: Sorted list of domain names
    :rtype: list
    """
    return sorted(FQDNs, key=lambda fqdn: fqdn.split('.')[::-1][1:])


def _filter_names(names, override_question=None):
    """Determine which names the user would like to select from a list.

    :param list names: domain names

    :returns: tuple of the form (`code`, `names`) where
        `code` - str display exit code
        `names` - list of names selected
    :rtype: tuple

    """
    #Sort by domain first, and then by subdomain
    sorted_names = _sort_names(names)
    if override_question:
        question = override_question
    else:
        question = "Which names would you like to activate HTTPS for?"
    code, names = z_util(interfaces.IDisplay).checklist(
        question, tags=sorted_names, cli_flag="--domains", force_interactive=True)
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
        cli_flag="--domains", force_interactive=True)

    if code == display_util.OK:
        invalid_domains = {}
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
                invalid_domains[domain] = str(e)

        if invalid_domains:
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
            retry = z_util(interfaces.IDisplay).yesno(retry_message,
                                                      force_interactive=True)
            if retry:
                return _choose_names_manually()
        else:
            return domain_list
    return []


def success_installation(domains):
    """Display a box confirming the installation of HTTPS.

    :param list domains: domain names which were enabled

    """
    z_util(interfaces.IDisplay).notification(
        "Congratulations! You have successfully enabled {0}".format(
            _gen_https_names(domains)),
        pause=False)


def success_renewal(domains):
    """Display a box confirming the renewal of an existing certificate.

    :param list domains: domain names which were renewed

    """
    z_util(interfaces.IDisplay).notification(
        "Your existing certificate has been successfully renewed, and the "
        "new certificate has been installed.{1}{1}"
        "The new certificate covers the following domains: {0}".format(
            _gen_https_names(domains),
            os.linesep),
        pause=False)


def success_revocation(cert_path):
    """Display a box confirming a certificate has been revoked.

    :param list cert_path: path to certificate which was revoked.

    """
    z_util(interfaces.IDisplay).notification(
        "Congratulations! You have successfully revoked the certificate "
        "that was located at {0}{1}{1}".format(
            cert_path,
            os.linesep),
        pause=False)


def _gen_ssl_lab_urls(domains):
    """Returns a list of urls.

    :param list domains: Each domain is a 'str'

    """
    return ["https://www.ssllabs.com/ssltest/analyze.html?d=%s" % dom for dom in domains]


def _gen_https_names(domains):
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


def _get_validated(method, validator, message, default=None, **kwargs):
    if default is not None:
        try:
            validator(default)
        except errors.Error as error:
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
                zope.component.getUtility(interfaces.IDisplay).notification(str(error), pause=False)
        else:
            return code, raw


def validated_input(validator, *args, **kwargs):
    """Like `~certbot.interfaces.IDisplay.input`, but with validation.

    :param callable validator: A method which will be called on the
        supplied input. If the method raises an `errors.Error`, its
        text will be displayed and the user will be re-prompted.
    :param list `*args`: Arguments to be passed to `~certbot.interfaces.IDisplay.input`.
    :param dict `**kwargs`: Arguments to be passed to `~certbot.interfaces.IDisplay.input`.
    :return: as `~certbot.interfaces.IDisplay.input`
    :rtype: tuple
    """
    return _get_validated(zope.component.getUtility(interfaces.IDisplay).input,
                          validator, *args, **kwargs)


def validated_directory(validator, *args, **kwargs):
    """Like `~certbot.interfaces.IDisplay.directory_select`, but with validation.

    :param callable validator: A method which will be called on the
        supplied input. If the method raises an `errors.Error`, its
        text will be displayed and the user will be re-prompted.
    :param list `*args`: Arguments to be passed to `~certbot.interfaces.IDisplay.directory_select`.
    :param dict `**kwargs`: Arguments to be passed to
        `~certbot.interfaces.IDisplay.directory_select`.
    :return: as `~certbot.interfaces.IDisplay.directory_select`
    :rtype: tuple
    """
    return _get_validated(zope.component.getUtility(interfaces.IDisplay).directory_select,
                          validator, *args, **kwargs)
