""" Distribution specific override class for Debian family (Ubuntu/Debian) """
import logging
import os

from certbot import errors
from certbot import util

from certbot_apache import apache_util

logger = logging.getLogger(__name__)

class Override(object):
    """ Debian override class """
    def __init__(self, config):
        """
        Initializes the override class.

        :param config: caller `certbot_apache.configurator.ApacheConfigurator`
        """
        self.config = config

    def enable_site(self, vhost):
        """Enables an available site, Apache reload required.

        .. note:: Does not make sure that the site correctly works or that all
                  modules are enabled appropriately.

        .. todo:: This function should number subdomains before the domain
                  vhost

        .. todo:: Make sure link is not broken...

        :param vhost: vhost to enable
        :type vhost: :class:`~certbot_apache.obj.VirtualHost`

        :raises .errors.NotSupportedError: If filesystem layout is not
            supported.

        """
        if vhost.enabled:
            return

        enabled_path = ("%s/sites-enabled/%s" %
                        (self.config.parser.root,
                         os.path.basename(vhost.filep)))
        self.config.reverter.register_file_creation(False, enabled_path)
        try:
            os.symlink(vhost.filep, enabled_path)
        except OSError as err:
            if os.path.islink(enabled_path) and os.path.realpath(
               enabled_path) == vhost.filep:
                # Already in shape
                vhost.enabled = True
                return
            else:
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
        self.config.save_notes += "Enabled site %s\n" % vhost.filep

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
        avail_path = os.path.join(self.config.parser.root, "mods-available")
        enabled_path = os.path.join(self.config.parser.root, "mods-enabled")
        if not os.path.isdir(avail_path) or not os.path.isdir(enabled_path):
            raise errors.NotSupportedError(
                "Unsupported directory layout. You may try to enable mod %s "
                "and try again." % mod_name)

        deps = apache_util.get_mod_deps(mod_name)
        # Enable all dependencies
        for dep in deps:
            if (dep + "_module") not in self.config.parser.modules:
                self._enable_mod_debian(dep, temp)
                self.config.add_parser_mod(dep)
                note = "Enabled dependency of %s module - %s" % (mod_name, dep)
                if not temp:
                    self.config.save_notes += note + os.linesep
                logger.debug(note)

        # Enable actual module
        self._enable_mod_debian(mod_name, temp)
        self.config.add_parser_mod(mod_name)

        if not temp:
            self.config.save_notes += "Enabled %s module in Apache\n" % mod_name
        logger.info("Enabled Apache %s module", mod_name)

        # Modules can enable additional config files. Variables may be defined
        # within these new configuration sections.
        # Reload is not necessary as DUMP_RUN_CFG uses latest config.
        self.config.parser.update_runtime_variables()

    def _enable_mod_debian(self, mod_name, temp):
        """Assumes mods-available, mods-enabled layout."""
        # Generate reversal command.
        # Try to be safe here... check that we can probably reverse before
        # applying enmod command
        if not util.exe_exists(self.config.conf("dismod")):
            raise errors.MisconfigurationError(
                "Unable to find a2dismod, please make sure a2enmod and "
                "a2dismod are configured correctly for certbot.")

        self.config.reverter.register_undo_command(
            temp, [self.config.conf("dismod"), mod_name])
        util.run_script([self.config.conf("enmod"), mod_name])
