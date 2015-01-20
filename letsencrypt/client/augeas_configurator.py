"""Class of Augeas Configurators."""
import logging
import os
import sys
import shutil
import time

import augeas

from letsencrypt.client import CONFIG
from letsencrypt.client import le_util


class AugeasConfigurator(object):
    """Base Augeas Configurator class.

    :ivar aug: Augeas object
    :type aug: :class:`augeas.Augeas`

    :ivar str save_notes: Human-readable configuration change notes
    :ivar dict direc: dictionary containing save directory paths

    """

    def __init__(self, direc=None):
        """Initialize Augeas Configurator.

        :param dict direc: location of save directories
            (used mostly for testing)

        """

        if not direc:
            direc = {"backup": CONFIG.BACKUP_DIR,
                     "temp": CONFIG.TEMP_CHECKPOINT_DIR,
                     "progress": CONFIG.IN_PROGRESS_DIR}

        self.direc = direc
        # TODO improve this, if possible:
        # incl should not be given here in this form as the files to look for are defined in httpd.aug
        # same for excl (and also, excl seems not to work, it will still read stuff from .old files)
        # but at least the stuff below does NOT read all the files in /etc/* - if you change stuff,
        # be careful not to reintroduce this bad behaviour!
        self.aug = augeas.Augeas(flags=augeas.Augeas.NO_MODL_AUTOLOAD | augeas.Augeas.SAVE_BACKUP)
        self.aug.add_transform('Httpd',
                               incl=['/etc/apache2/*', '/etc/httpd/*', ],
                               excl=['*.old', ])
        self.aug.load()
        self.save_notes = ""

    def check_parsing_errors(self, lens):
        """Verify Augeas can parse all of the lens files.

        :param str lens: lens to check for errors

        """
        error_files = self.aug.match("/augeas//error")

        for path in error_files:
            # Check to see if it was an error resulting from the use of
            # the httpd lens
            lens_path = self.aug.get(path + '/lens')
            # As aug.get may return null
            if lens_path and lens in lens_path:
                # Strip off /augeas/files and /error
                logging.error('There has been an error in parsing the file: %s',
                              path[13:len(path) - 6])
                logging.error(self.aug.get(path + '/message'))

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
            # Check for the root of save problems
            new_errs = self.aug.match("/augeas//error")
            # logging.error("During Save - %s", mod_conf)
            # Only print new errors caused by recent save
            for err in new_errs:
                if err not in ex_errs:
                    logging.error(
                        "Unable to save file - %s", err[13:len(err) - 6])
            logging.error("Attempted Save Notes")
            logging.error(self.save_notes)
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

            valid, message = self.check_tempfile_saves(save_files)

            if not valid:
                logging.fatal(message)
                # What is the protocol in this situation?
                # This shouldn't happen if the challenge codebase is correct
                return False

            # Create Checkpoint
            if temporary:
                self.add_to_checkpoint(self.direc["temp"], save_files)
            else:
                self.add_to_checkpoint(self.direc["progress"], save_files)

        if title and not temporary and os.path.isdir(self.direc["progress"]):
            success = self._finalize_checkpoint(self.direc["progress"], title)
            if not success:
                # This should never happen
                # This will be hopefully be cleaned up on the recovery
                # routine startup
                sys.exit(9)

        self.aug.set("/augeas/save", save_state)
        self.save_notes = ""
        self.aug.save()

        return True

    def revert_challenge_config(self):
        """Reload users original configuration files after a challenge.

        This function should reload the users original configuration files
        for all saves with temporary=True

        """
        if os.path.isdir(self.direc["temp"]):
            result = self._recover_checkpoint(self.direc["temp"])
            if result != 0:
                # We have a partial or incomplete recovery
                logging.fatal("Incomplete or failed recovery for %s",
                              self.direc["temp"])
                sys.exit(67)
            # Remember to reload Augeas
            self.aug.load()

    def rollback_checkpoints(self, rollback=1):
        """Revert 'rollback' number of configuration checkpoints.

        :param int rollback: Number of checkpoints to reverse

        """
        try:
            rollback = int(rollback)
        except ValueError:
            logging.error("Rollback argument must be a positive integer")
        # Sanity check input
        if rollback < 1:
            logging.error("Rollback argument must be a positive integer")
            return

        backups = os.listdir(self.direc["backup"])
        backups.sort()

        if len(backups) < rollback:
            logging.error("Unable to rollback %d checkpoints, only %d exist",
                          rollback, len(backups))

        while rollback > 0 and backups:
            cp_dir = self.direc["backup"] + backups.pop()
            result = self._recover_checkpoint(cp_dir)
            if result != 0:
                logging.fatal("Failed to load checkpoint during rollback")
                sys.exit(39)
            rollback -= 1

        self.aug.load()

    def display_checkpoints(self):
        """Displays all saved checkpoints.

        All checkpoints are printed to the console.

        Note: Any 'IN_PROGRESS' checkpoints will be removed by the cleanup
        script found in the constructor, before this function would ever be
        called.

        """
        backups = os.listdir(self.direc["backup"])
        backups.sort(reverse=True)

        if not backups:
            print ("Letsencrypt has not saved any backups of your "
                   "apache configuration")
        # Make sure there isn't anything unexpected in the backup folder
        # There should only be timestamped (float) directories
        try:
            for bkup in backups:
                float(bkup)
        except ValueError:
            assert False, "Invalid files in %s" % self.direc["backup"]

        for bkup in backups:
            print time.ctime(float(bkup))
            cur_dir = self.direc["backup"] + bkup
            with open(os.path.join(cur_dir, "CHANGES_SINCE")) as changes_fd:
                print changes_fd.read()

            print "Affected files:"
            with open(os.path.join(cur_dir, "FILEPATHS")) as paths_fd:
                filepaths = paths_fd.read().splitlines()
                for path in filepaths:
                    print "  %s" % path

            try:
                with open(os.path.join(cur_dir, "NEW_FILES")) as new_fd:
                    print "New Configuration Files:"
                    filepaths = new_fd.read().splitlines()
                    for path in filepaths:
                        print "  %s" % path
            except (IOError, OSError) as exc:
                print exc
            print ""

    def add_to_checkpoint(self, cp_dir, save_files):
        """Add save files to checkpoint directory.

        :param str cp_dir: Checkpoint directory filepath
        :param set save_files: set of files to save

        """
        le_util.make_or_verify_dir(cp_dir, 0o755, os.geteuid())

        existing_filepaths = []
        filepaths_path = os.path.join(cp_dir, "FILEPATHS")

        # Open up FILEPATHS differently depending on if it already exists
        if os.path.isfile(filepaths_path):
            op_fd = open(filepaths_path, 'r+')
            existing_filepaths = op_fd.read().splitlines()
        else:
            op_fd = open(filepaths_path, 'w')

        idx = len(existing_filepaths)
        for filename in save_files:
            if filename not in existing_filepaths:
                # Tag files with index so multiple files can
                # have the same filename
                logging.debug("Creating backup of %s", filename)
                shutil.copy2(filename, os.path.join(
                    cp_dir, os.path.basename(filename) + "_" + str(idx)))
                op_fd.write(filename + '\n')
                idx += 1
        op_fd.close()

        with open(os.path.join(cp_dir, "CHANGES_SINCE"), 'a') as notes_fd:
            notes_fd.write(self.save_notes)

    def _recover_checkpoint(self, cp_dir):
        """Recover a specific checkpoint.

        Recover a specific checkpoint provided by cp_dir
        Note: this function does not reload augeas.

        :param str cp_dir: checkpoint directory file path

        :returns: 0 success, 1 Unable to revert, -1 Unable to delete
        :rtype: int

        """
        if os.path.isfile(os.path.join(cp_dir, "FILEPATHS")):
            try:
                with open(os.path.join(cp_dir, "FILEPATHS")) as paths_fd:
                    filepaths = paths_fd.read().splitlines()
                    for idx, path in enumerate(filepaths):
                        shutil.copy2(os.path.join(
                            cp_dir,
                            os.path.basename(path) + '_' + str(idx)), path)
            except (IOError, OSError):
                # This file is required in all checkpoints.
                logging.error("Unable to recover files from %s", cp_dir)
                return 1

        # Remove any newly added files if they exist
        self._remove_contained_files(os.path.join(cp_dir, "NEW_FILES"))

        try:
            shutil.rmtree(cp_dir)
        except OSError:
            logging.error("Unable to remove directory: %s", cp_dir)
            return -1

        return 0

    def check_tempfile_saves(self, save_files):  # pylint: disable=no-self-use
        """Verify save isn't overwriting any temporary files.

        :param set save_files: Set of files about to be saved.

        :returns: Success, error message
        :rtype: bool, str

        """
        temp_path = "%sFILEPATHS" % self.direc["temp"]
        if os.path.isfile(temp_path):
            with open(temp_path, 'r') as protected_fd:
                protected_files = protected_fd.read().splitlines()
                for filename in protected_files:
                    if filename in save_files:
                        return False, ("Attempting to overwrite challenge "
                                       "file - %s" % filename)

        return True, ""

    # pylint: disable=no-self-use, anomalous-backslash-in-string
    def register_file_creation(self, temporary, *files):
        """Register the creation of all files during letsencrypt execution.

        Call this method before writing to the file to make sure that the
        file will be cleaned up if the program exits unexpectedly.
        (Before a save occurs)

        :param bool temporary: If the file creation registry is for
            a temp or permanent save.

        :param \*files: file paths (str) to be registered

        """
        if temporary:
            cp_dir = self.direc["temp"]
        else:
            cp_dir = self.direc["progress"]

        le_util.make_or_verify_dir(cp_dir)
        try:
            with open(os.path.join(cp_dir, "NEW_FILES"), 'a') as new_fd:
                for file_path in files:
                    new_fd.write("%s\n" % file_path)
        except (IOError, OSError):
            logging.error("ERROR: Unable to register file creation")

    def recovery_routine(self):
        """Revert all previously modified files.

        First, any changes found in self.direc["temp"] are removed,
        then IN_PROGRESS changes are removed The order is important.
        IN_PROGRESS is unable to add files that are already added by a TEMP
        change.  Thus TEMP must be rolled back first because that will be the
        'latest' occurrence of the file.

        """
        self.revert_challenge_config()
        if os.path.isdir(self.direc["progress"]):
            result = self._recover_checkpoint(self.direc["progress"])
            if result != 0:
                # We have a partial or incomplete recovery
                # Not as egregious
                # TODO: Additional tests? recovery
                logging.fatal("Incomplete or failed recovery for %s",
                              self.direc["progress"])
                sys.exit(68)

            # Need to reload configuration after these changes take effect
            self.aug.load()

    # pylint: disable=no-self-use
    def _remove_contained_files(self, file_list):
        """Erase all files contained within file_list.

        :param str file_list: file containing list of file paths to be deleted

        :returns: Success
        :rtype: bool

        """
        # Check to see that file exists to differentiate can't find file_list
        # and can't remove filepaths within file_list errors.
        if not os.path.isfile(file_list):
            return False
        try:
            with open(file_list, 'r') as list_fd:
                filepaths = list_fd.read().splitlines()
                for path in filepaths:
                    # Files are registered before they are added... so
                    # check to see if file exists first
                    if os.path.lexists(path):
                        os.remove(path)
                    else:
                        logging.warn(
                            "File: %s - Could not be found to be deleted\n"
                            "Program was probably shut down unexpectedly, " % path)
        except (IOError, OSError):
            logging.fatal(
                "Unable to remove filepaths contained within %s", file_list)
            sys.exit(41)

        return True

    # pylint: disable=no-self-use
    def _finalize_checkpoint(self, cp_dir, title):
        """Move IN_PROGRESS checkpoint to timestamped checkpoint.

        Adds title to cp_dir CHANGES_SINCE
        Move cp_dir to Backups directory and rename with timestamp

        :param cp_dir: "IN PROGRESS" directory
        :type cp_dir: str

        :returns: Success
        :rtype: bool

        """
        final_dir = os.path.join(self.direc["backup"], str(time.time()))
        changes_since_path = os.path.join(cp_dir, "CHANGES_SINCE")
        changes_since_tmp_path = os.path.join(cp_dir, "CHANGES_SINCE.tmp")

        try:
            with open(changes_since_tmp_path, 'w') as changes_tmp:
                changes_tmp.write("-- %s --\n" % title)
                with open(changes_since_path, 'r') as changes_orig:
                    changes_tmp.write(changes_orig.read())

            shutil.move(changes_since_tmp_path, changes_since_path)

        except (IOError, OSError):
            logging.error("Unable to finalize checkpoint - adding title")
            return False
        try:
            os.rename(cp_dir, final_dir)
        except OSError:
            logging.error(
                "Unable to finalize checkpoint, %s -> %s", cp_dir, final_dir)
            return False
        return True
