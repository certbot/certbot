"""Updaters run at renewal"""
import logging

from certbot import errors
from certbot import interfaces

from certbot.plugins import selection as plug_sel
import certbot.plugins.enhancements as enhancements

logger = logging.getLogger(__name__)

def run_generic_updaters(config, plugins, lineage):
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
        logger.warning("Could not choose appropriate plugin for updaters: %s", e)
        return
    _run_updaters(lineage, installer, config)
    _run_enhancement_updaters(lineage, installer, config)

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
    if not config.disable_renew_updates and isinstance(installer,
                                                       interfaces.RenewDeployer):
        installer.renew_deploy(lineage)
    _run_enhancement_deployers(lineage, installer, config)

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
        if not config.disable_renew_updates:
            if isinstance(installer, interfaces.GenericUpdater):
                installer.generic_updates(domain)

def _run_enhancement_updaters(lineage, installer, config):
    """Iterates through known enhancement interfaces. If the installer implements
    an enhancement interface and the enhance interface has an updater method, the
    updater method gets run.

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param installer: Installer object
    :type installer: interfaces.IInstaller

    :param config: Configuration object
    :type config: interfaces.IConfig
    """

    if config.disable_renew_updates:
        return
    for enh in enhancements.INDEX:
        if isinstance(installer, enh["class"]) and enh["updater_function"]:
            upd_func = getattr(installer, enh["updater_function"])
            for domain in lineage.names():
                upd_func(domain)
        else:
            continue


def _run_enhancement_deployers(lineage, installer, config):
    """Iterates through known enhancement interfaces. If the installer implements
    an enhancement interface and the enhance interface has an deployer method, the
    deployer method gets run.

    :param lineage: Certificate lineage object
    :type lineage: storage.RenewableCert

    :param installer: Installer object
    :type installer: interfaces.IInstaller

    :param config: Configuration object
    :type config: interfaces.IConfig
    """

    if config.disable_renew_updates:
        return
    for enh in enhancements.INDEX:
        if isinstance(installer, enh["class"]) and enh["deployer_function"]:
            getattr(installer, enh["deployer_function"])(lineage)
