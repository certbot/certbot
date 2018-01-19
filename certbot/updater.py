"""Updaters run at renewal"""
import logging

from certbot import errors
from certbot import interfaces

from certbot.plugins import selection as plug_sel

logger = logging.getLogger(__name__)

def run_renewal_updaters(config, plugins, lineage):
    """Run updaters that the plugin supports

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param plugins: List of plugins
    :type plugins: `list` of `str`

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :returns: `None`
    :rtype: None
    """
    try:
        # installers are used in auth mode to determine domain names
        installer, _ = plug_sel.choose_configurator_plugins(config, plugins, "certonly")
    except errors.PluginSelectionError as e:
        logger.info("Could not choose appropriate plugin: %s", e)
        raise
    _run_updaters(lineage, installer, config)

def run_renewal_deployer(lineage, installer, config):
    """Helper function to run deployer interface method if supported by the used
    installer plugin.

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param installer: Installer object
    :type installer: interfaces.IInstaller

    :returns: `None`
    :rtype: None
    """
    if config.installer_updates and isinstance(installer, interfaces.RenewDeployer):
        installer.renew_deploy(lineage)

def _run_updaters(lineage, installer, config):
    """Helper function to run the updater interface methods if supported by the
    used installer plugin.

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param installer: Installer object
    :type installer: interfaces.IInstaller

    :returns: `None`
    :rtype: None
    """
    for domain in lineage.names():
        if config.server_tls_updates:
            if isinstance(installer, interfaces.ServerTLSUpdater):
                installer.server_tls_updates(domain)
        if config.installer_updates:
            if isinstance(installer, interfaces.GenericUpdater):
                installer.generic_updates(domain)
