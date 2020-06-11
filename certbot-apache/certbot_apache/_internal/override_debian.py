""" Distribution specific override class for Debian family (Ubuntu/Debian) """
import logging

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot import util
from certbot.compat import filesystem
from certbot.compat import os
from certbot_apache._internal import apache_util
from certbot_apache._internal import configurator

logger = logging.getLogger(__name__)


@zope.interface.provider(interfaces.IPluginFactory)
class DebianConfigurator(configurator.ApacheConfigurator):
    """Debian specific ApacheConfigurator override class"""

    OS_DEFAULTS = dict(
        server_root="/etc/apache2",
        vhost_root="/etc/apache2/sites-available",
        vhost_files="*",
        logs_root="/var/log/apache2",
        ctl="apache2ctl",
        version_cmd=['apache2ctl', '-v'],
        restart_cmd=['apache2ctl', 'graceful'],
        conftest_cmd=['apache2ctl', 'configtest'],
        enmod="a2enmod",
        dismod="a2dismod",
        le_vhost_ext="-le-ssl.conf",
        handle_modules=True,
        handle_sites=True,
        challenge_location="/etc/apache2",
        bin=None,
    )

    def enable_site(self, vhost):
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
            return super(DebianConfigurator, self).enable_site(vhost)
        self.reverter.register_file_creation(False, enabled_path)
        try:
            os.symlink(vhost.filep, enabled_path)
        except OSError as err:
            if os.path.islink(enabled_path) and filesystem.realpath(
               enabled_path) == vhost.filep:
                # Already in shape
                vhost.enabled = True
                return None
            logger.warning(
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

    def enable_mod(self, mod_name, temp=False):
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

    def _enable_mod_debian(self, mod_name, temp):
        """Assumes mods-available, mods-enabled layout."""
        # Generate reversal command.
        # Try to be safe here... check that we can probably reverse before
        # applying enmod command
        if not util.exe_exists(self.option("dismod")):
            raise errors.MisconfigurationError(
                "Unable to find a2dismod, please make sure a2enmod and "
                "a2dismod are configured correctly for certbot.")

        self.reverter.register_undo_command(
            temp, [self.option("dismod"), "-f", mod_name])
        util.run_script([self.option("enmod"), mod_name])
