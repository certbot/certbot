"""Updaters run at renewal"""
import logging

from certbot import errors
from certbot import interfaces

from certbot.plugins import selection as plug_sel

logger = logging.getLogger(__name__)

def run_generic_updaters(config, lineage, plugins):
    """Run updaters that the plugin supports

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param plugins: List of plugins
    :type plugins: `list` of `str`

    :returns: `None`
    :rtype: None
    """
    if config.dry_run:
        logger.debug("Skipping updaters in dry-run mode.")
        return
    try:
        # installers are used in auth mode to determine domain names
        installer, _ = plug_sel.choose_configurator_plugins(config, plugins, "certonly")
    except errors.PluginSelectionError as e:
        logger.warning("Could not choose appropriate plugin for updaters: %s", e)
        return
    _run_updaters(lineage, installer, config)

def run_renewal_deployer(config, lineage, installer):
    """Helper function to run deployer interface method if supported by the used
    installer plugin.

    :param config: Configuration object
    :type config: interfaces.IConfig

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param installer: Installer object
    :type installer: interfaces.IInstaller

    :returns: `None`
    :rtype: None
    """
    if config.dry_run:
        logger.debug("Skipping renewal deployer in dry-run mode.")
        return

    if not config.disable_renew_updates and isinstance(installer,
                                                       interfaces.RenewDeployer):
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
    if not config.disable_renew_updates:
        if isinstance(installer, interfaces.GenericUpdater):
            installer.generic_updates(lineage)
