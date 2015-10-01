"""Contains UI methods for LE user operations."""
import logging
import os

import zope.component

from letsencrypt import interfaces
from letsencrypt import le_util
from letsencrypt.display import util as display_util


logger = logging.getLogger(__name__)

# Define a helper function to avoid verbose code
util = zope.component.getUtility


def choose_plugin(prepared, question):
    """Allow the user to choose their plugin.

    :param list prepared: List of `~.PluginEntryPoint`.
    :param str question: Question to be presented to the user.

    :returns: Plugin entry point chosen by the user.
    :rtype: `~.PluginEntryPoint`

    """
    opts = [plugin_ep.description_with_name +
            (" [Misconfigured]" if plugin_ep.misconfigured else "")
            for plugin_ep in prepared]

    while True:
        code, index = util(interfaces.IDisplay).menu(
            question, opts, help_label="More Info")

        if code == display_util.OK:
            return prepared[index]
        elif code == display_util.HELP:
            if prepared[index].misconfigured:
                msg = "Reported Error: %s" % prepared[index].prepare()
            else:
                msg = prepared[index].init().more_info()
            util(interfaces.IDisplay).notification(
                msg, height=display_util.HEIGHT)
        else:
            return None


def pick_plugin(config, default, plugins, question, ifaces):
    """Pick plugin.

    :param letsencrypt.interfaces.IConfig: Configuration
    :param str default: Plugin name supplied by user or ``None``.
    :param letsencrypt.plugins.disco.PluginsRegistry plugins:
        All plugins registered as entry points.
    :param str question: Question to be presented to the user in case
        multiple candidates are found.
    :param list ifaces: Interfaces that plugins must provide.

    :returns: Initialized plugin.
    :rtype: IPlugin

    """
    if default is not None:
        # throw more UX-friendly error if default not in plugins
        filtered = plugins.filter(lambda p_ep: p_ep.name == default)
    else:
        filtered = plugins.visible().ifaces(ifaces)

    filtered.init(config)
    verified = filtered.verify(ifaces)
    verified.prepare()
    prepared = verified.available()

    if len(prepared) > 1:
        logger.debug("Multiple candidate plugins: %s", prepared)
        plugin_ep = choose_plugin(prepared.values(), question)
        if plugin_ep is None:
            return None
        else:
            return plugin_ep.init()
    elif len(prepared) == 1:
        plugin_ep = prepared.values()[0]
        logger.debug("Single candidate plugin: %s", plugin_ep)
        if plugin_ep.misconfigured:
            return None
        return plugin_ep.init()
    else:
        logger.debug("No candidate plugin")
        return None


def pick_authenticator(
        config, default, plugins, question="How would you "
        "like to authenticate with the Let's Encrypt CA?"):
    """Pick authentication plugin."""
    return pick_plugin(
        config, default, plugins, question, (interfaces.IAuthenticator,))


def pick_installer(config, default, plugins,
                   question="How would you like to install certificates?"):
    """Pick installer plugin."""
    return pick_plugin(
        config, default, plugins, question, (interfaces.IInstaller,))


def pick_configurator(
        config, default, plugins,
        question="How would you like to authenticate and install "
                 "certificates?"):
    """Pick configurator plugin."""
    return pick_plugin(
        config, default, plugins, question,
        (interfaces.IAuthenticator, interfaces.IInstaller))


def get_email():
    """Prompt for valid email address.

    :returns: Email or ``None`` if cancelled by user.
    :rtype: str

    """
    while True:
        code, email = zope.component.getUtility(interfaces.IDisplay).input(
            "Enter email address")

        if code == display_util.OK:
            if le_util.safe_email(email):
                return email
        else:
            return None


def choose_account(accounts):
    """Choose an account.

    :param list accounts: Containing at least one
        :class:`~letsencrypt.account.Account`

    """
    # Note this will get more complicated once we start recording authorizations
    labels = [acc.slug for acc in accounts]

    code, index = util(interfaces.IDisplay).menu(
        "Please choose an account", labels)
    if code == display_util.OK:
        return accounts[index]
    else:
        return None


def choose_names(installer):
    """Display screen to select domains to validate.

    :param installer: An installer object
    :type installer: :class:`letsencrypt.interfaces.IInstaller`

    :returns: List of selected names
    :rtype: `list` of `str`

    """
    if installer is None:
        logger.debug("No installer, picking names manually")
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
        "Congratulations! You have successfully enabled {0}!{1}{1}"
        "You should test your configuration at:{1}{2}".format(
            _gen_https_names(domains),
            os.linesep,
            os.linesep.join(_gen_ssl_lab_urls(domains))),
        height=(10 + len(domains)),
        pause=False)


def success_renewal(domains):
    """Display a box confirming the renewal of an existing certificate.

    .. todo:: This should be centered on the screen

    :param list domains: domain names which were renewed

    """
    util(interfaces.IDisplay).notification(
        "Your existing certificate has been successfully renewed, and the "
        "new certificate has been installed.{1}{1}"
        "The new certificate covers the following domains: {0}{1}{1}"
        "You should test your configuration at:{1}{2}".format(
            _gen_https_names(domains),
            os.linesep,
            os.linesep.join(_gen_ssl_lab_urls(domains))),
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
