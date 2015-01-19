"""Reverter class saves configuration checkpoints and allows for recovery."""
import logging
import os
import shutil
import sys
import time

from letsencrypt.client import CONFIG
from letsencrypt.client import errors
from letsencrypt.client import le_util

class Reverter(object):
    """Reverter Class - save and revert configuration checkpoints"""
    def __init__(self, direc=None):
        if not direc:
            direc = {"backup": CONFIG.BACKUP_DIR,
                     "temp": CONFIG.TEMP_CHECKPOINT_DIR,
                     "progress": CONFIG.IN_PROGRESS_DIR}
        self.direc = direc

    def revert_temporary_config(self):
        """Reload users original configuration files after a temporary save.

        This function should reinstall the users original configuration files
        for all saves with temporary=True

        :raises :class:`errors.LetsEncryptReverterError`:
            Unable to revert config

        """
        if os.path.isdir(self.direc["temp"]):
            result = self._recover_checkpoint(self.direc["temp"])
            if result != 0:
                # We have a partial or incomplete recovery
                logging.fatal("Incomplete or failed recovery for %s",
                              self.direc["temp"])
                raise errors.LetsEncryptReverterError(
                    "Unable to revert temporary config")

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

    def view_config_changes(self):
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
                   "configuration")
        # Make sure there isn't anything unexpected in the backup folder
        # There should only be timestamped (float) directories
        try:
            for bkup in backups:
                float(bkup)
        except ValueError:
            assert False, "Invalid files in %s" % self.direc['backup']

        for bkup in backups:
            print time.ctime(float(bkup))
            cur_dir = self.direc['backup'] + bkup
            with open(os.path.join(cur_dir, 'CHANGES_SINCE')) as changes_fd:
                print changes_fd.read()

            print "Affected files:"
            with open(os.path.join(cur_dir, 'FILEPATHS')) as paths_fd:
                filepaths = paths_fd.read().splitlines()
                for path in filepaths:
                    print "  %s" % path

            try:
                if os.path.isfile(os.path.join(cur_dir, 'NEW_FILES')):
                    with open(os.path.join(cur_dir, 'NEW_FILES')) as new_fd:
                        print "New Configuration Files:"
                        filepaths = new_fd.read().splitlines()
                        for path in filepaths:
                            print "  %s" % path
            except (IOError, OSError) as err:
                logging.warn(str(err))
            print ""

    def add_to_temp_checkpoint(self, save_files, save_notes):
        """Add files to temporary checkpoint

        param set save_files: set of filepaths to save
        param str save_notes: notes about changes during the save

        """
        self._add_to_checkpoint_dir(self.direc['temp'], save_files, save_notes)

    def add_to_checkpoint(self, save_files, save_notes):
        """Add files to a permanent checkpoint

        :param set save_files: set of filepaths to save
        :param str save_notes: notes about changes during the save

        """
        self._add_to_checkpoint_dir(
            self.direc['progress'], save_files, save_notes)

    def _add_to_checkpoint_dir(self, cp_dir, save_files, save_notes):
        """Add save files to checkpoint directory.

        :param str cp_dir: Checkpoint directory filepath
        :param set save_files: set of files to save
        :param str save_notes: notes about changes made during the save

        """
        self._check_tempfile_saves(save_files)
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
            notes_fd.write(save_notes)

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

    def _check_tempfile_saves(self, save_files):  # pylint: disable=no-self-use
        """Verify save isn't overwriting any temporary files.

        :param set save_files: Set of files about to be saved.

        :raises :class:`letsencrypt.client.errors.LetsEncryptReverterError`:
            when save is attempting to overwrite a temporary file.

        """
        temp_path = "%sFILEPATHS" % self.direc["temp"]
        if os.path.isfile(temp_path):
            with open(temp_path, 'r') as protected_fd:
                protected_files = protected_fd.read().splitlines()
                for filename in protected_files:
                    if filename in save_files:
                        raise errors.LetsEncryptReverterError(
                            "Attempting to overwrite challenge "
                            "file - %s" % filename)

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

        le_util.make_or_verify_dir(cp_dir, 0o755, os.geteuid())
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
        self.revert_temporary_config()
        if os.path.isdir(self.direc["progress"]):
            result = self._recover_checkpoint(self.direc["progress"])
            if result != 0:
                # We have a partial or incomplete recovery
                # Not as egregious
                # TODO: Additional tests? recovery
                logging.fatal("Incomplete or failed recovery for %s",
                              self.direc["progress"])
                sys.exit(68)

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
                            "LE probably shut down unexpectedly", path)
        except (IOError, OSError):
            logging.fatal(
                "Unable to remove filepaths contained within %s", file_list)
            sys.exit(41)

        return True

    # pylint: disable=no-self-use
    def finalize_checkpoint(self, title):
        """Move IN_PROGRESS checkpoint to timestamped checkpoint.

        Adds title to self.direc['progress'] CHANGES_SINCE
        Move self.direc['progress'] to Backups directory and rename with timestamp

        """
        # Check to make sure an "in progress" directory exists
        if not os.path.isdir(self.direc['progress']):
            return

        final_dir = os.path.join(self.direc['backup'], str(time.time()))
        changes_since_path = os.path.join(
            self.direc['progress'], 'CHANGES_SINCE')
        changes_since_tmp_path = os.path.join(
            self.direc['progress'], 'CHANGES_SINCE.tmp')

        try:
            with open(changes_since_tmp_path, 'w') as changes_tmp:
                changes_tmp.write("-- %s --\n" % title)
                with open(changes_since_path, 'r') as changes_orig:
                    changes_tmp.write(changes_orig.read())

            shutil.move(changes_since_tmp_path, changes_since_path)

        except (IOError, OSError):
            logging.error("Unable to finalize checkpoint - adding title")
            raise errors.LetsEncryptReverterError("Unable to add title")
        try:
            os.rename(self.direc['progress'], final_dir)
        except OSError:
            logging.error(
                "Unable to finalize checkpoint, %s -> %s", cp_dir, final_dir)
            raise errors.LetsEncryptReverterError(
                "Unable to finalize checkpoint renaming")
