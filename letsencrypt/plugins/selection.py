from __future__ import print_function
import os
from letsencrypt import errors
from letsencrypt.display import ops as display_ops

logger = logging.getLogger(__name__)

noninstaller_plugins = ["webroot", "manual", "standalone"]

def record_chosen_plugins(config, plugins, auth, inst):
    "Update the config entries to reflect the plugins we actually selected."
    cn = config.namespace
    cn.authenticator = plugins.find_init(auth).name if auth else "none"
    cn.installer = plugins.find_init(inst).name if inst else "none"


def choose_configurator_plugins(config, plugins, verb):
    """
    Figure out which configurator we're going to use, modifies
    config.authenticator and config.istaller strings to reflect that choice if
    necessary.

    :raises errors.PluginSelectionError if there was a problem

    :returns: (an `IAuthenticator` or None, an `IInstaller` or None)
    :rtype: tuple
    """

    req_auth, req_inst = cli_plugin_requests(config)

    # Which plugins do we need?
    if verb == "run":
        need_inst = need_auth = True
        from letsencrypt.cli import cli_command
        if req_auth in noninstaller_plugins and not req_inst:
            msg = ('With the {0} plugin, you probably want to use the "certonly" command, eg:{1}'
                   '{1}    {2} certonly --{0}{1}{1}'
                   '(Alternatively, add a --installer flag. See https://eff.org/letsencrypt-plugins'
                   '{1} and "--help plugins" for more information.)'.format(
                       req_auth, os.linesep, cli_command))

            raise errors.MissingCommandlineFlag(msg)
    else:
        need_inst = need_auth = False
    if verb == "certonly":
        need_auth = True
    if verb == "install":
        need_inst = True
        if config.authenticator:
            logger.warn("Specifying an authenticator doesn't make sense in install mode")

    # Try to meet the user's request and/or ask them to pick plugins
    authenticator = installer = None
    if verb == "run" and req_auth == req_inst:
        # Unless the user has explicitly asked for different auth/install,
        # only consider offering a single choice
        authenticator = installer = display_ops.pick_configurator(config, req_inst, plugins)
    else:
        if need_inst or req_inst:
            installer = display_ops.pick_installer(config, req_inst, plugins)
        if need_auth:
            authenticator = display_ops.pick_authenticator(config, req_auth, plugins)
    logger.debug("Selected authenticator %s and installer %s", authenticator, installer)

    # Report on any failures
    if need_inst and not installer:
        diagnose_configurator_problem("installer", req_inst, plugins)
    if need_auth and not authenticator:
        diagnose_configurator_problem("authenticator", req_auth, plugins)

    record_chosen_plugins(config, plugins, authenticator, installer)
    return installer, authenticator


def set_configurator(previously, now):
    """
    Setting configurators multiple ways is okay, as long as they all agree
    :param str previously: previously identified request for the installer/authenticator
    :param str requested: the request currently being processed
    """
    if now is None:
        # we're not actually setting anything
        return previously
    if previously:
        if previously != now:
            msg = "Too many flags setting configurators/installers/authenticators {0} -> {1}"
            raise errors.PluginSelectionError(msg.format(repr(previously), repr(now)))
    return now


def cli_plugin_requests(config):
    """
    Figure out which plugins the user requested with CLI and config options

    :returns: (requested authenticator string or None, requested installer string or None)
    :rtype: tuple
    """
    req_inst = req_auth = config.configurator
    req_inst = set_configurator(req_inst, config.installer)
    req_auth = set_configurator(req_auth, config.authenticator)
    if config.nginx:
        req_inst = set_configurator(req_inst, "nginx")
        req_auth = set_configurator(req_auth, "nginx")
    if config.apache:
        req_inst = set_configurator(req_inst, "apache")
        req_auth = set_configurator(req_auth, "apache")
    if config.standalone:
        req_auth = set_configurator(req_auth, "standalone")
    if config.webroot:
        req_auth = set_configurator(req_auth, "webroot")
    if config.manual:
        req_auth = set_configurator(req_auth, "manual")
    logger.debug("Requested authenticator %s and installer %s", req_auth, req_inst)
    return req_auth, req_inst


def diagnose_configurator_problem(cfg_type, requested, plugins):
    """
    Raise the most helpful error message about a plugin being unavailable

    :param str cfg_type: either "installer" or "authenticator"
    :param str requested: the plugin that was requested
    :param .PluginsRegistry plugins: available plugins

    :raises error.PluginSelectionError: if there was a problem
    """

    if requested:
        if requested not in plugins:
            msg = "The requested {0} plugin does not appear to be installed".format(requested)
        else:
            msg = ("The {0} plugin is not working; there may be problems with "
                   "your existing configuration.\nThe error was: {1!r}"
                   .format(requested, plugins[requested].problem))
    elif cfg_type == "installer":
        if os.path.exists("/etc/debian_version"):
            # Debian... installers are at least possible
            msg = ('No installers seem to be present and working on your system; '
                   'fix that or try running letsencrypt with the "certonly" command')
        else:
            # XXX update this logic as we make progress on #788 and nginx support
            msg = ('No installers are available on your OS yet; try running '
                   '"letsencrypt-auto certonly" to get a cert you can install manually')
    else:
        msg = "{0} could not be determined or is not installed".format(cfg_type)
    raise errors.PluginSelectionError(msg)
