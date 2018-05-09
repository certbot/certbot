import abc
import six

from certbot import errors

def is_supported(config):
    """Checks if one or more of the requested enhancements are supported by
    the enhancement interfaces."""
    supported = []
    for enh in INDEX:
        if hasattr(config, enh["cli_dest"]):
            supported.append(getattr(config, enh["cli_dest"]))
    return bool(supported)

def enable(lineage, installer, config):
    """
    Run enable method for each requested enhancement that is supported.

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param installer: Installer object
    :type installer: interfaces.IInstaller

    :param config: Configuration.
    :type config: :class:`certbot.interfaces.IConfig`
    """
    for enh in INDEX:
        if hasattr(config, enh["cli_dest"]) and getattr(config, enh["cli_dest"]):
            if not isinstance(installer, enh["class"]):
                msg = ("Requested enhancement {} not supported by selected "
                       "installer").format(enh["name"])
                raise errors.NotSupportedError(msg)
            # Run the enable function
            getattr(installer, enh["enable_function"])(lineage)


@six.add_metaclass(abc.ABCMeta)
class AutoHSTSEnhancement(object):
    """Example enhancement interface class for AutoHSTS"""

    @abc.abstractmethod
    def update_autohsts(self, domain, *args, **kwargs):
        """As updater function, takes the same parameters as
        interfaces.GenericUpdater.generic_updates
        """

    @abc.abstractmethod
    def deploy_autohsts(self, lineage, *args, **kwargs):
        """As renewer function, takes the same parameters as
        interfaces.RenewDeployer
        """

    @abc.abstractmethod
    def enable_autohsts(self, lineage, *args, **kwargs):
        """Installer function, uses lineage as a parameter.
        """


@six.add_metaclass(abc.ABCMeta)
class OCSPPrefetchEnhancement(object):
    """Example enhancement interface class for OCSP prefetch"""

    @abc.abstractmethod
    def update_ocsp_prefetch(self, domain, *args, **kwargs):
        """As updater function, takes the same parameters as
        interfaces.GenericUpdater.generic_updates
        """

    @abc.abstractmethod
    def deploy_ocsp_prefetch(self, lineage, *args, **kwargs):
        """As renewer function, takes the same parameters as
        interfaces.RenewDeployer
        """

    @abc.abstractmethod
    def enable_ocsp_prefetch(self, lineage, *args, **kwargs):
        """Installer function, uses lineage as a parameter."""


INDEX = [
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
    },
    {
        "name": "OCSP Prefetch",
        "cli_help": "Prefetch OCSP responses within scheduled run with renew verb",
        "cli_flag": "--ocspprefetch",
        "cli_flag_default": None,
        "cli_groups": ["security", "enhance"],
        "cli_dest": "ocsp_prefetch",
        "cli_action": "store_true",
        "class": OCSPPrefetchEnhancement,
        "updater_function": "update_ocsp_prefetch",
        "deployer_function": None,
        "enable_function": "enable_ocsp_prefetch"
    }
]
