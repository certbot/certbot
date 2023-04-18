"""Updaters run at renewal"""
import logging

from certbot import configuration
from certbot import errors
from certbot import interfaces
from certbot._internal import storage
from certbot._internal.plugins import disco as plugin_disco
from certbot._internal.plugins import selection as plug_sel
from certbot.plugins import enhancements

logger = logging.getLogger(__name__)


def run_generic_updaters(config: configuration.NamespaceConfig, lineage: storage.RenewableCert,
                         plugins: plugin_disco.PluginsRegistry) -> None:
    """Run updaters that the plugin supports

    :param config: Configuration object
    :type config: certbot.configuration.NamespaceConfig

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param plugins: List of plugins
    :type plugins: certbot._internal.plugins.disco.PluginsRegistry

    :returns: `None`
    :rtype: None
    """
    if config.dry_run:
        logger.debug("Skipping updaters in dry-run mode.")
        return
    try:
        installer = plug_sel.get_unprepared_installer(config, plugins)
    except errors.Error as e:
        logger.error("Could not choose appropriate plugin for updaters: %s", e)
        return
    if installer:
        _run_updaters(lineage, installer, config)
        _run_enhancement_updaters(lineage, installer, config)


def run_renewal_deployer(config: configuration.NamespaceConfig, lineage: storage.RenewableCert,
                         installer: interfaces.Installer) -> None:
    """Helper function to run deployer interface method if supported by the used
    installer plugin.

    :param config: Configuration object
    :type config: certbot.configuration.NamespaceConfig

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param installer: Installer object
    :type installer: interfaces.Installer

    :returns: `None`
    :rtype: None
    """
    if config.dry_run:
        logger.debug("Skipping renewal deployer in dry-run mode.")
        return

    if not config.disable_renew_updates and isinstance(installer,
                                                       interfaces.RenewDeployer):
        installer.renew_deploy(lineage)
    _run_enhancement_deployers(lineage, installer, config)


def _run_updaters(lineage: storage.RenewableCert, installer: interfaces.Installer,
                  config: configuration.NamespaceConfig) -> None:
    """Helper function to run the updater interface methods if supported by the
    used installer plugin.

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param installer: Installer object
    :type installer: interfaces.Installer

    :returns: `None`
    :rtype: None
    """
    if not config.disable_renew_updates:
        if isinstance(installer, interfaces.GenericUpdater):
            installer.generic_updates(lineage)


def _run_enhancement_updaters(lineage: storage.RenewableCert, installer: interfaces.Installer,
                              config: configuration.NamespaceConfig) -> None:
    """Iterates through known enhancement interfaces. If the installer implements
    an enhancement interface and the enhance interface has an updater method, the
    updater method gets run.

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param installer: Installer object
    :type installer: interfaces.Installer

    :param config: Configuration object
    :type config: certbot.configuration.NamespaceConfig
    """

    if config.disable_renew_updates:
        return
    for enh in enhancements._INDEX:  # pylint: disable=protected-access
        if isinstance(installer, enh["class"]) and enh["updater_function"]:
            getattr(installer, enh["updater_function"])(lineage)


def _run_enhancement_deployers(lineage: storage.RenewableCert, installer: interfaces.Installer,
                               config: configuration.NamespaceConfig) -> None:
    """Iterates through known enhancement interfaces. If the installer implements
    an enhancement interface and the enhance interface has an deployer method, the
    deployer method gets run.

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param installer: Installer object
    :type installer: interfaces.Installer

    :param config: Configuration object
    :type config: certbot.configuration.NamespaceConfig
    """

    if config.disable_renew_updates:
        return
    for enh in enhancements._INDEX:  # pylint: disable=protected-access
        if isinstance(installer, enh["class"]) and enh["deployer_function"]:
            getattr(installer, enh["deployer_function"])(lineage)
