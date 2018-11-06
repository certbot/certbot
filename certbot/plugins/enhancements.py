"""New interface style Certbot enhancements"""
import abc
import six

from certbot import constants

from acme.magic_typing import Dict, List, Any  # pylint: disable=unused-import, no-name-in-module

def enabled_enhancements(config):
    """
    Generator to yield the enabled new style enhancements.

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`
    """
    for enh in _INDEX:
        if getattr(config, enh["cli_dest"]):
            yield enh

def are_requested(config):
    """
    Checks if one or more of the requested enhancements are those of the new
    enhancement interfaces.

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`
    """
    return any(enabled_enhancements(config))

def are_supported(config, installer):
    """
    Checks that all of the requested enhancements are supported by the
    installer.

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`

    :param installer: Installer object
    :type installer: interfaces.IInstaller

    :returns: If all the requested enhancements are supported by the installer
    :rtype: bool
    """
    for enh in enabled_enhancements(config):
        if not isinstance(installer, enh["class"]):
            return False
    return True

def enable(lineage, domains, installer, config):
    """
    Run enable method for each requested enhancement that is supported.

    :param lineage: Certificate lineage object
    :type lineage: certbot.storage.RenewableCert

    :param domains: List of domains in certificate to enhance
    :type domains: str

    :param installer: Installer object
    :type installer: interfaces.IInstaller

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`
    """
    for enh in enabled_enhancements(config):
        getattr(installer, enh["enable_function"])(lineage, domains)

def populate_cli(add):
    """
    Populates the command line flags for certbot.cli.HelpfulParser

    :param add: Add function of certbot.cli.HelpfulParser
    :type add: func
    """
    for enh in _INDEX:
        add(enh["cli_groups"], enh["cli_flag"], action=enh["cli_action"],
            dest=enh["cli_dest"], default=enh["cli_flag_default"],
            help=enh["cli_help"])


@six.add_metaclass(abc.ABCMeta)
class AutoHSTSEnhancement(object):
    """
    Enhancement interface that installer plugins can implement in order to
    provide functionality that configures the software to have a
    'Strict-Transport-Security' with initially low max-age value that will
    increase over time.

    The plugins implementing new style enhancements are responsible of handling
    the saving of configuration checkpoints as well as calling possible restarts
    of managed software themselves. For update_autohsts method, the installer may
    have to call prepare() to finalize the plugin initialization.

    Methods:
        enable_autohsts is called when the header is initially installed using a
        low max-age value.

        update_autohsts is called every time when Certbot is run using 'renew'
        verb. The max-age value should be increased over time using this method.

        deploy_autohsts is called for every lineage that has had its certificate
        renewed. A long HSTS max-age value should be set here, as we should be
        confident that the user is able to automatically renew their certificates.


    """

    @abc.abstractmethod
    def update_autohsts(self, lineage, *args, **kwargs):
        """
        Gets called for each lineage every time Certbot is run with 'renew' verb.
        Implementation of this method should increase the max-age value.

        :param lineage: Certificate lineage object
        :type lineage: certbot.storage.RenewableCert

        .. note:: prepare() method inherited from `interfaces.IPlugin` might need
            to be called manually within implementation of this interface method
            to finalize the plugin initialization.
        """

    @abc.abstractmethod
    def deploy_autohsts(self, lineage, *args, **kwargs):
        """
        Gets called for a lineage when its certificate is successfully renewed.
        Long max-age value should be set in implementation of this method.

        :param lineage: Certificate lineage object
        :type lineage: certbot.storage.RenewableCert
        """

    @abc.abstractmethod
    def enable_autohsts(self, lineage, domains, *args, **kwargs):
        """
        Enables the AutoHSTS enhancement, installing
        Strict-Transport-Security header with a low initial value to be increased
        over the subsequent runs of Certbot renew.

        :param lineage: Certificate lineage object
        :type lineage: certbot.storage.RenewableCert

        :param domains: List of domains in certificate to enhance
        :type domains: str
        """

# This is used to configure internal new style enhancements in Certbot. These
# enhancement interfaces need to be defined in this file. Please do not modify
# this list from plugin code.
_INDEX = [
    {
        "name": "AutoHSTS",
        "cli_help": "Gradually increasing max-age value for HTTP Strict Transport "+
                    "Security security header",
        "cli_flag": "--auto-hsts",
        "cli_flag_default": constants.CLI_DEFAULTS["auto_hsts"],
        "cli_groups": ["security", "enhance"],
        "cli_dest": "auto_hsts",
        "cli_action": "store_true",
        "class": AutoHSTSEnhancement,
        "updater_function": "update_autohsts",
        "deployer_function": "deploy_autohsts",
        "enable_function": "enable_autohsts"
    }
]  # type: List[Dict[str, Any]]
