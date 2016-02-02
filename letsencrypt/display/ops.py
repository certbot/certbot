"""Contains UI methods for LE user operations."""
import logging
import os

import zope.component

from letsencrypt import errors
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
        disp = util(interfaces.IDisplay)
        code, index = disp.menu(question, opts, help_label="More Info")

        if code == display_util.OK:
            plugin_ep = prepared[index]
            if plugin_ep.misconfigured:
                util(interfaces.IDisplay).notification(
                    "The selected plugin encountered an error while parsing "
                    "your server configuration and cannot be used. The error "
                    "was:\n\n{0}".format(plugin_ep.prepare()),
                    height=display_util.HEIGHT, pause=False)
            else:
                return plugin_ep
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
        if config.noninteractive_mode:
            # it's really bad to auto-select the single available plugin in
            # non-interactive mode, because an update could later add a second
            # available plugin
            raise errors.MissingCommandlineFlag(
                "Missing command line flags. For non-interactive execution, "
                "you will need to specify a plugin on the command line.  Run "
                "with '--help plugins' to see a list of options, and see "
                "https://eff.org/letsencrypt-plugins for more detail on what "
                "the plugins do and how to use them.")

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


def get_email(more=False, invalid=False):
    """Prompt for valid email address.

    :param bool more: explain why the email is strongly advisable, but how to
        skip it
    :param bool invalid: true if the user just typed something, but it wasn't
        a valid-looking email

    :returns: Email or ``None`` if cancelled by user.
    :rtype: str

    """
    msg = "Enter email address (used for urgent notices and lost key recovery)"
    if invalid:
        msg = "There seem to be problems with that address. " + msg
    if more:
        msg += ('\n\nIf you really want to skip this, you can run the client with '
                '--register-unsafely-without-email but make sure you backup your '
                'account key from /etc/letsencrypt/accounts\n\n')
    try:
        code, email = zope.component.getUtility(interfaces.IDisplay).input(msg)
    except errors.MissingCommandlineFlag:
        msg = ("You should register before running non-interactively, or provide --agree-tos"
               " and --email <email_address> flags")
        raise errors.MissingCommandlineFlag(msg)

    if code == display_util.OK:
        if le_util.safe_email(email):
            return email
        else:
            # TODO catch the server's ACME invalid email address error, and
            # make a similar call when that happens
            return get_email(more=True, invalid=(email != ""))
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

    domains = list(installer.get_all_names())
    names = get_valid_domains(domains)

    if not names:
        manual = util(interfaces.IDisplay).yesno(
            "No names were found in your configuration files.{0}You should "
            "specify ServerNames in your config files in order to allow for "
            "accurate installation of your certificate.{0}"
            "If you do use the default vhost, you may specify the name "
            "manually. Would you like to continue?{0}".format(os.linesep),
            default=True)

        if manual:
            return _choose_names_manually()
        else:
            return []

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
            valid_domains.append(le_util.enforce_domain_sanity(domain))
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
    code, names = util(interfaces.IDisplay).checklist(
        "Which names would you like to activate HTTPS for?",
        tags=names, cli_flag="--domains")
    return code, [str(s) for s in names]


def _choose_names_manually():
    """Manually input names for those without an installer."""

    code, input_ = util(interfaces.IDisplay).input(
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
                domain_list[i] = le_util.enforce_domain_sanity(domain)
            except errors.ConfigurationError as e:
                invalid_domains[domain] = e.message

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
            retry = util(interfaces.IDisplay).yesno(retry_message)
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
    util(interfaces.IDisplay).notification(
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
    util(interfaces.IDisplay).notification(
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
