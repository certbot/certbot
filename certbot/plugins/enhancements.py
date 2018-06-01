import abc
import six

from certbot import errors

def is_supported(config):
    """Checks if one or more of the requested enhancements are supported by
    the enhancement interfaces."""
    supported = []
    for enh in _INDEX:
        if hasattr(config, enh["cli_dest"]):
            supported.append(getattr(config, enh["cli_dest"]))
    return bool(supported)

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
    for enh in _INDEX:
        if hasattr(config, enh["cli_dest"]) and getattr(config, enh["cli_dest"]):
            if not isinstance(installer, enh["class"]):
                msg = ("Requested enhancement {} not supported by selected "
                       "installer").format(enh["name"])
                raise errors.NotSupportedError(msg)
            # Run the enable method
            getattr(installer, enh["enable_function"])(lineage, domains)


@six.add_metaclass(abc.ABCMeta)
class AutoHSTSEnhancement(object):
    """Example enhancement interface class for AutoHSTS"""

    @abc.abstractmethod
    def update_autohsts(self, domain, *args, **kwargs):
        """As updater method, takes the same parameters as
        interfaces.GenericUpdater.generic_updates
        """

    @abc.abstractmethod
    def deploy_autohsts(self, lineage, *args, **kwargs):
        """As renewer method, takes the same parameters as
        interfaces.RenewDeployer
        """

    @abc.abstractmethod
    def enable_autohsts(self, lineage, domains, *args, **kwargs):
        """Installer method, uses lineage as a parameter.

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
        "cli_flag": "--autohsts",
        "cli_flag_default": None,
        "cli_groups": ["security", "enhance"],
        "cli_dest": "auto_hsts",
        "cli_action": "store_true",
        "class": AutoHSTSEnhancement,
        "updater_function": "update_autohsts",
        "deployer_function": "deploy_autohsts",
        "enable_function": "enable_autohsts"
    }
]
