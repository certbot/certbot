""" Distribution specific override class for Debian family (Ubuntu/Debian) """
import logging

from certbot_apache._internal import apache_util
from certbot_apache._internal import configurator
from certbot_apache._internal.configurator import OsOptions
from certbot_apache._internal.obj import VirtualHost

from certbot import errors
from certbot import util
from certbot.compat import filesystem
from certbot.compat import os

logger = logging.getLogger(__name__)


class DebianConfigurator(configurator.ApacheConfigurator):
    """Debian specific ApacheConfigurator override class"""

    OS_DEFAULTS = OsOptions(
        enmod="a2enmod",
        dismod="a2dismod",
        handle_modules=True,
        handle_sites=True,
    )

    def enable_site(self, vhost: VirtualHost) -> None:
        """Enables an available site, Apache reload required.

        .. note:: Does not make sure that the site correctly works or that all
                  modules are enabled appropriately.

        :param vhost: vhost to enable
        :type vhost: :class:`~certbot_apache._internal.obj.VirtualHost`

        :raises .errors.NotSupportedError: If filesystem layout is not
            supported.

        """
        if vhost.enabled:
            return None

        enabled_path = ("%s/sites-enabled/%s" %
                        (self.parser.root,
                         os.path.basename(vhost.filep)))
        if not os.path.isdir(os.path.dirname(enabled_path)):
            # For some reason, sites-enabled / sites-available do not exist
            # Call the parent method
            return super().enable_site(vhost)
        self.reverter.register_file_creation(False, enabled_path)
        try:
            os.symlink(vhost.filep, enabled_path)
        except OSError as err:
            if os.path.islink(enabled_path) and filesystem.realpath(
               enabled_path) == vhost.filep:
                # Already in shape
                vhost.enabled = True
                return None
            logger.error(
                "Could not symlink %s to %s, got error: %s", enabled_path,
                vhost.filep, err.strerror)
            errstring = ("Encountered error while trying to enable a " +
                         "newly created VirtualHost located at {0} by " +
                         "linking to it from {1}")
            raise errors.NotSupportedError(errstring.format(vhost.filep,
                                                            enabled_path))
        vhost.enabled = True
        logger.info("Enabling available site: %s", vhost.filep)
        self.save_notes += "Enabled site %s\n" % vhost.filep
        return None

    def enable_mod(self, mod_name: str, temp: bool = False) -> None:
        """Enables module in Apache.

        Both enables and reloads Apache so module is active.

        :param str mod_name: Name of the module to enable. (e.g. 'ssl')
        :param bool temp: Whether or not this is a temporary action.

        :raises .errors.NotSupportedError: If the filesystem layout is not
            supported.
        :raises .errors.MisconfigurationError: If a2enmod or a2dismod cannot be
            run.

        """
        avail_path = os.path.join(self.parser.root, "mods-available")
        enabled_path = os.path.join(self.parser.root, "mods-enabled")
        if not os.path.isdir(avail_path) or not os.path.isdir(enabled_path):
            raise errors.NotSupportedError(
                "Unsupported directory layout. You may try to enable mod %s "
                "and try again." % mod_name)

        deps = apache_util.get_mod_deps(mod_name)

        # Enable all dependencies
        for dep in deps:
            if (dep + "_module") not in self.parser.modules:
                self._enable_mod_debian(dep, temp)
                self.parser.add_mod(dep)
                note = "Enabled dependency of %s module - %s" % (mod_name, dep)
                if not temp:
                    self.save_notes += note + os.linesep
                logger.debug(note)

        # Enable actual module
        self._enable_mod_debian(mod_name, temp)
        self.parser.add_mod(mod_name)

        if not temp:
            self.save_notes += "Enabled %s module in Apache\n" % mod_name
        logger.info("Enabled Apache %s module", mod_name)

        # Modules can enable additional config files. Variables may be defined
        # within these new configuration sections.
        # Reload is not necessary as DUMP_RUN_CFG uses latest config.
        self.parser.update_runtime_variables()

    def _enable_mod_debian(self, mod_name: str, temp: bool) -> None:
        """Assumes mods-available, mods-enabled layout."""
        # Generate reversal command.
        # Try to be safe here... check that we can probably reverse before
        # applying enmod command
        if (self.options.dismod is None or self.options.enmod is None
                or not util.exe_exists(self.options.dismod)):
            raise errors.MisconfigurationError(
                "Unable to find a2dismod, please make sure a2enmod and "
                "a2dismod are configured correctly for certbot.")

        self.reverter.register_undo_command(temp, [self.options.dismod, "-f", mod_name])
        util.run_script([self.options.enmod, mod_name])
