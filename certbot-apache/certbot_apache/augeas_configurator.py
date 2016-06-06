"""Class of Augeas Configurators."""
import logging


from certbot import errors
from certbot import reverter
from certbot.plugins import common

from certbot_apache import constants

logger = logging.getLogger(__name__)


class AugeasConfigurator(common.Plugin):
    """Base Augeas Configurator class.

    :ivar config: Configuration.
    :type config: :class:`~certbot.interfaces.IConfig`

    :ivar aug: Augeas object
    :type aug: :class:`augeas.Augeas`

    :ivar str save_notes: Human-readable configuration change notes
    :ivar reverter: saves and reverts checkpoints
    :type reverter: :class:`certbot.reverter.Reverter`

    """
    def __init__(self, *args, **kwargs):
        super(AugeasConfigurator, self).__init__(*args, **kwargs)

        # Placeholder for augeas
        self.aug = None

        self.save_notes = ""

        # See if any temporary changes need to be recovered
        # This needs to occur before VirtualHost objects are setup...
        # because this will change the underlying configuration and potential
        # vhosts
        self.reverter = reverter.Reverter(self.config)

    def init_augeas(self):
        """ Initialize the actual Augeas instance """
        import augeas
        self.aug = augeas.Augeas(
            # specify a directory to load our preferred lens from
            loadpath=constants.AUGEAS_LENS_DIR,
            # Do not save backup (we do it ourselves), do not load
            # anything by default
            flags=(augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD))
        self.recovery_routine()

    def check_parsing_errors(self, lens):
        """Verify Augeas can parse all of the lens files.

        :param str lens: lens to check for errors

        :raises .errors.PluginError: If there has been an error in parsing with
            the specified lens.

        """
        error_files = self.aug.match("/augeas//error")

        for path in error_files:
            # Check to see if it was an error resulting from the use of
            # the httpd lens
            lens_path = self.aug.get(path + "/lens")
            # As aug.get may return null
            if lens_path and lens in lens_path:
                msg = (
                    "There has been an error in parsing the file (%s): %s",
                    # Strip off /augeas/files and /error
                    path[13:len(path) - 6], self.aug.get(path + "/message"))
                raise errors.PluginError(msg)

    # TODO: Cleanup this function
    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.

        This function first checks for save errors, if none are found,
        all configuration changes made will be saved. According to the
        function parameters. If an exception is raised, a new checkpoint
        was not created.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (ie. challenges)

        :raises .errors.PluginError: If there was an error in Augeas, in
            an attempt to save the configuration, or an error creating a
            checkpoint

        """
        save_state = self.aug.get("/augeas/save")
        self.aug.set("/augeas/save", "noop")
        # Existing Errors
        ex_errs = self.aug.match("/augeas//error")
        try:
            # This is a noop save
            self.aug.save()
        except (RuntimeError, IOError):
            self._log_save_errors(ex_errs)
            # Erase Save Notes
            self.save_notes = ""
            raise errors.PluginError(
                "Error saving files, check logs for more info.")

        # Retrieve list of modified files
        # Note: Noop saves can cause the file to be listed twice, I used a
        # set to remove this possibility. This is a known augeas 0.10 error.
        save_paths = self.aug.match("/augeas/events/saved")

        # If the augeas tree didn't change, no files were saved and a backup
        # should not be created
        if save_paths:
            save_files = set()
            for path in save_paths:
                save_files.add(self.aug.get(path)[6:])

            try:
                # Create Checkpoint
                if temporary:
                    self.reverter.add_to_temp_checkpoint(
                        save_files, self.save_notes)
                else:
                    self.reverter.add_to_checkpoint(save_files,
                                                    self.save_notes)
            except errors.ReverterError as err:
                raise errors.PluginError(str(err))

        self.aug.set("/augeas/save", save_state)
        self.save_notes = ""
        self.aug.save()

        if title and not temporary:
            try:
                self.reverter.finalize_checkpoint(title)
            except errors.ReverterError as err:
                raise errors.PluginError(str(err))

    def _log_save_errors(self, ex_errs):
        """Log errors due to bad Augeas save.

        :param list ex_errs: Existing errors before save

        """
        # Check for the root of save problems
        new_errs = self.aug.match("/augeas//error")
        # logger.error("During Save - %s", mod_conf)
        logger.error("Unable to save files: %s. Attempted Save Notes: %s",
                     ", ".join(err[13:len(err) - 6] for err in new_errs
                               # Only new errors caused by recent save
                               if err not in ex_errs), self.save_notes)

    # Wrapper functions for Reverter class
    def recovery_routine(self):
        """Revert all previously modified files.

        Reverts all modified files that have not been saved as a checkpoint

        :raises .errors.PluginError: If unable to recover the configuration

        """
        try:
            self.reverter.recovery_routine()
        except errors.ReverterError as err:
            raise errors.PluginError(str(err))
        # Need to reload configuration after these changes take effect
        self.aug.load()

    def revert_challenge_config(self):
        """Used to cleanup challenge configurations.

        :raises .errors.PluginError: If unable to revert the challenge config.

        """
        try:
            self.reverter.revert_temporary_config()
        except errors.ReverterError as err:
            raise errors.PluginError(str(err))
        self.aug.load()

    def rollback_checkpoints(self, rollback=1):
        """Rollback saved checkpoints.

        :param int rollback: Number of checkpoints to revert

        :raises .errors.PluginError: If there is a problem with the input or
            the function is unable to correctly revert the configuration

        """
        try:
            self.reverter.rollback_checkpoints(rollback)
        except errors.ReverterError as err:
            raise errors.PluginError(str(err))
        self.aug.load()

    def view_config_changes(self):
        """Show all of the configuration changes that have taken place.

        :raises .errors.PluginError: If there is a problem while processing
            the checkpoints directories.

        """
        try:
            self.reverter.view_config_changes()
        except errors.ReverterError as err:
            raise errors.PluginError(str(err))
