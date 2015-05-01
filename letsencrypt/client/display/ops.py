"""Contains UI methods for LE user operations."""
import os

import zope.component

from letsencrypt.client import interfaces
from letsencrypt.client.display import util as display_util

# Define a helper function to avoid verbose code
util = zope.component.getUtility  # pylint: disable=invalid-name


def choose_authenticator(auths, errs):
    """Allow the user to choose their authenticator.

    :param list auths: Where each of type
        :class:`letsencrypt.client.interfaces.IAuthenticator` object
    :param dict errs: Mapping IAuthenticator objects to error messages

    :returns: Authenticator selected
    :rtype: :class:`letsencrypt.client.interfaces.IAuthenticator` or `None`

    """
    descs = [auth.description if auth not in errs
             else "%s (Misconfigured)" % auth.description
             for auth in auths]

    while True:
        code, index = util(interfaces.IDisplay).menu(
            "How would you like to authenticate with the Let's Encrypt CA?",
            descs, help_label="More Info")

        if code == display_util.OK:
            return auths[index]
        elif code == display_util.HELP:
            if auths[index] in errs:
                msg = "Reported Error: %s" % errs[auths[index]]
            else:
                msg = auths[index].more_info()
            util(interfaces.IDisplay).notification(
                msg, height=display_util.HEIGHT)
        else:
            return


def choose_account(accounts):
    """Choose an account.

    :param list accounts: Containing at least one
        :class:`~letsencrypt.client.account.Account`

    """
    # Note this will get more complicated once we start recording authorizations
    labels = [
        "%s | %s" % (acc.email.ljust(display_util.WIDTH - 39),
                     acc.phone if acc.phone is not None else "")
        for acc in accounts
    ]

    code, index = util(interfaces.IDisplay).menu(
        "Please choose an account", labels)
    if code == display_util.OK:
        return accounts[index]
    else:
        return None


def choose_names(installer):
    """Display screen to select domains to validate.

    :param installer: An installer object
    :type installer: :class:`letsencrypt.client.interfaces.IInstaller`

    :returns: List of selected names
    :rtype: `list` of `str`

    """
    if installer is None:
        return _choose_names_manually()

    names = list(installer.get_all_names())

    if not names:
        manual = util(interfaces.IDisplay).yesno(
            "No names were found in your configuration files.{0}You should "
            "specify ServerNames in your config files in order to allow for "
            "accurate installation of your certificate.{0}"
            "If you do use the default vhost, you may specify the name "
            "manually. Would you like to continue?{0}".format(os.linesep))

        if manual:
            return _choose_names_manually()
        else:
            return []

    code, names = _filter_names(names)
    if code == display_util.OK and names:
        return names
    else:
        return []


def _filter_names(names):
    """Determine which names the user would like to select from a list.

    :param list names: domain names

    :returns: tuple of the form (`code`, `names`) where
        `code` - str display exit code
        `names` - list of names selected
    :rtype: tuple

    """
    code, names = util(interfaces.IDisplay).checklist(
        "Which names would you like to activate HTTPS for?",
        tags=names)
    return code, [str(s) for s in names]


def _choose_names_manually():
    """Manually input names for those without an installer."""

    code, input_ = util(interfaces.IDisplay).input(
        "Please enter in your domain name(s) (comma and/or space separated) ")

    if code == display_util.OK:
        return display_util.separate_list_input(input_)
    return []


def success_installation(domains):
    """Display a box confirming the installation of HTTPS.

    .. todo:: This should be centered on the screen

    :param list domains: domain names which were enabled

    """
    util(interfaces.IDisplay).notification(
        "Congratulations! You have successfully enabled "
        "%s!" % _gen_https_names(domains), pause=False)


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
