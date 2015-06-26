"""Class of Augeas Configurators."""
import logging

import augeas

from letsencrypt import reverter
from letsencrypt.plugins import common

logger = logging.getLogger(__name__)


class AugeasConfigurator(common.Plugin):
    """Base Augeas Configurator class.

    :ivar config: Configuration.
    :type config: :class:`~letsencrypt.interfaces.IConfig`

    :ivar aug: Augeas object
    :type aug: :class:`augeas.Augeas`

    :ivar str save_notes: Human-readable configuration change notes
    :ivar reverter: saves and reverts checkpoints
    :type reverter: :class:`letsencrypt.reverter.Reverter`

    """

    def __init__(self, *args, **kwargs):
        super(AugeasConfigurator, self).__init__(*args, **kwargs)

        # Set Augeas flags to not save backup (we do it ourselves)
        # Set Augeas to not load anything by default
        my_flags = augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD
        self.aug = augeas.Augeas(flags=my_flags)
        self.save_notes = ""

        # See if any temporary changes need to be recovered
        # This needs to occur before VirtualHost objects are setup...
        # because this will change the underlying configuration and potential
        # vhosts
        self.reverter = reverter.Reverter(self.config)
        self.reverter.recovery_routine()

    def check_parsing_errors(self, lens):
        """Verify Augeas can parse all of the lens files.

        :param str lens: lens to check for errors

        """
        error_files = self.aug.match("/augeas//error")

        for path in error_files:
            # Check to see if it was an error resulting from the use of
            # the httpd lens
            lens_path = self.aug.get(path + "/lens")
            # As aug.get may return null
            if lens_path and lens in lens_path:
                logger.error(
                    "There has been an error in parsing the file (%s): %s",
                    # Strip off /augeas/files and /error
                    path[13:len(path) - 6], self.aug.get(path + "/message"))

    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.

        This function first checks for save errors, if none are found,
        all configuration changes made will be saved. According to the
        function parameters.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (ie. challenges)

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
            return False

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

            # Create Checkpoint
            if temporary:
                self.reverter.add_to_temp_checkpoint(
                    save_files, self.save_notes)
            else:
                self.reverter.add_to_checkpoint(save_files, self.save_notes)

        if title and not temporary:
            self.reverter.finalize_checkpoint(title)

        self.aug.set("/augeas/save", save_state)
        self.save_notes = ""
        self.aug.save()

        return True

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

        """
        self.reverter.recovery_routine()
        # Need to reload configuration after these changes take effect
        self.aug.load()

    def revert_challenge_config(self):
        """Used to cleanup challenge configurations."""
        self.reverter.revert_temporary_config()
        self.aug.load()

    def rollback_checkpoints(self, rollback=1):
        """Rollback saved checkpoints.

        :param int rollback: Number of checkpoints to revert

        """
        self.reverter.rollback_checkpoints(rollback)
        self.aug.load()

    def view_config_changes(self):
        """Show all of the configuration changes that have taken place."""
        self.reverter.view_config_changes()
