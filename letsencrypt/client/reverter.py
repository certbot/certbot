"""Reverter class saves configuration checkpoints and allows for recovery."""
import logging
import os
import shutil
import time

import zope.component

from letsencrypt.client import display
from letsencrypt.client import errors
from letsencrypt.client import interfaces
from letsencrypt.client import le_util


class Reverter(object):
    """Reverter Class - save and revert configuration checkpoints."""

    def __init__(self, config, direc=None):
        """Initialize Reverter.

        :param config: Configuration.
        :type config: :class:`letsencrypt.client.interfaces.IConfig`

        """
        if direc is None:
            direc = {'backup': config.BACKUP_DIR,
                     'temp': config.TEMP_CHECKPOINT_DIR,
                     'progress': config.IN_PROGRESS_DIR}
        self.direc = direc

    def revert_temporary_config(self):
        """Reload users original configuration files after a temporary save.

        This function should reinstall the users original configuration files
        for all saves with temporary=True

        :raises :class:`errors.LetsEncryptReverterError`:
            Unable to revert config

        """
        if os.path.isdir(self.direc['temp']):
            try:
                self._recover_checkpoint(self.direc['temp'])
            except errors.LetsEncryptReverterError:
                # We have a partial or incomplete recovery
                logging.fatal("Incomplete or failed recovery for %s",
                              self.direc['temp'])
                raise errors.LetsEncryptReverterError(
                    "Unable to revert temporary config")

    def rollback_checkpoints(self, rollback=1):
        """Revert 'rollback' number of configuration checkpoints.

        :param int rollback: Number of checkpoints to reverse. A str num will be
           cast to an integer. So '2' is also acceptable.

        :raises :class:`letsencrypt.client.errors.LetsEncryptReverterError`: If
            there is a problem with the input or if the function is unable to
            correctly revert the configuration checkpoints.

        """
        try:
            rollback = int(rollback)
        except ValueError:
            logging.error("Rollback argument must be a positive integer")
            raise errors.LetsEncryptReverterError("Invalid Input")
        # Sanity check input
        if rollback < 0:
            logging.error("Rollback argument must be a positive integer")
            raise errors.LetsEncryptReverterError("Invalid Input")

        backups = os.listdir(self.direc['backup'])
        backups.sort()

        if len(backups) < rollback:
            logging.warning("Unable to rollback %d checkpoints, only %d exist",
                            rollback, len(backups))

        while rollback > 0 and backups:
            cp_dir = os.path.join(self.direc['backup'], backups.pop())
            try:
                self._recover_checkpoint(cp_dir)
            except errors.LetsEncryptReverterError:
                logging.fatal("Failed to load checkpoint during rollback")
                raise errors.LetsEncryptReverterError(
                    "Unable to load checkpoint during rollback")
            rollback -= 1

    def view_config_changes(self):
        """Displays all saved checkpoints.

        All checkpoints are printed to the console.

        .. todo:: Decide on a policy for error handling, OSError IOError...

        """
        backups = os.listdir(self.direc['backup'])
        backups.sort(reverse=True)

        if not backups:
            logging.info("The Let's Encrypt client has not saved any backups "
                         "of your configuration")
            return
        # Make sure there isn't anything unexpected in the backup folder
        # There should only be timestamped (float) directories
        try:
            for bkup in backups:
                float(bkup)
        except ValueError:
            raise errors.LetsEncryptReverterError(
                "Invalid directories in {0}".format(self.direc['backup']))

        output = []
        for bkup in backups:
            output.append(time.ctime(float(bkup)))
            cur_dir = os.path.join(self.direc['backup'], bkup)
            with open(os.path.join(cur_dir, "CHANGES_SINCE")) as changes_fd:
                output.append(changes_fd.read())

            output.append("Affected files:")
            with open(os.path.join(cur_dir, "FILEPATHS")) as paths_fd:
                filepaths = paths_fd.read().splitlines()
                for path in filepaths:
                    output.append("  {0}".format(path))

            if os.path.isfile(os.path.join(cur_dir, "NEW_FILES")):
                with open(os.path.join(cur_dir, "NEW_FILES")) as new_fd:
                    output.append("New Configuration Files:")
                    filepaths = new_fd.read().splitlines()
                    for path in filepaths:
                        output.append("  {0}".format(path))

            output.append(os.linesep)

        zope.component.getUtility(interfaces.IDisplay).generic_notification(
            os.linesep.join(output), display.HEIGHT)

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
        # Check to make sure we are not overwriting a temp file
        self._check_tempfile_saves(save_files)
        self._add_to_checkpoint_dir(
            self.direc['progress'], save_files, save_notes)

    def _add_to_checkpoint_dir(self, cp_dir, save_files, save_notes):
        """Add save files to checkpoint directory.

        :param str cp_dir: Checkpoint directory filepath
        :param set save_files: set of files to save
        :param str save_notes: notes about changes made during the save

        :raises IOError: If unable to open cp_dir + FILEPATHS file
        :raises :class:`letsencrypt.client.errors.LetsEncryptReverterError: If
            unable to add checkpoint

        """
        le_util.make_or_verify_dir(cp_dir, 0o755, os.geteuid())

        op_fd, existing_filepaths = self._read_and_append(
            os.path.join(cp_dir, "FILEPATHS"))

        idx = len(existing_filepaths)

        for filename in save_files:
            # No need to copy/index already existing files
            # The oldest copy already exists in the directory...
            if filename not in existing_filepaths:
                # Tag files with index so multiple files can
                # have the same filename
                logging.debug("Creating backup of %s", filename)
                try:
                    shutil.copy2(filename, os.path.join(
                        cp_dir, os.path.basename(filename) + "_" + str(idx)))
                    op_fd.write(filename + '\n')
                # http://stackoverflow.com/questions/4726260/effective-use-of-python-shutil-copy2
                except IOError:
                    op_fd.close()
                    logging.error(
                        "Unable to add file %s to checkpoint %s",
                        filename, cp_dir)
                    raise errors.LetsEncryptReverterError(
                        "Unable to add file {0} to checkpoint "
                        "{1}".format(filename, cp_dir))
                idx += 1
        op_fd.close()

        with open(os.path.join(cp_dir, "CHANGES_SINCE"), 'a') as notes_fd:
            notes_fd.write(save_notes)

    def _read_and_append(self, filepath):  # pylint: disable=no-self-use
        """Reads the file lines and returns a fd.

        Read the file returning the lines, and a pointer to the end of the file.

        """
        # Open up filepath differently depending on if it already exists
        if os.path.isfile(filepath):
            op_fd = open(filepath, 'r+')
            lines = op_fd.read().splitlines()
        else:
            lines = []
            op_fd = open(filepath, 'w')

        return op_fd, lines

    def _recover_checkpoint(self, cp_dir):
        """Recover a specific checkpoint.

        Recover a specific checkpoint provided by cp_dir
        Note: this function does not reload augeas.

        :param str cp_dir: checkpoint directory file path

        :raises errors.LetsEncryptReverterError: If unable to recover checkpoint

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
                raise errors.LetsEncryptReverterError(
                    "Unable to recover files from %s" % cp_dir)

        # Remove any newly added files if they exist
        self._remove_contained_files(os.path.join(cp_dir, "NEW_FILES"))

        try:
            shutil.rmtree(cp_dir)
        except OSError:
            logging.error("Unable to remove directory: %s", cp_dir)
            raise errors.LetsEncryptReverterError(
                "Unable to remove directory: %s" % cp_dir)

    def _check_tempfile_saves(self, save_files):
        """Verify save isn't overwriting any temporary files.

        :param set save_files: Set of files about to be saved.

        :raises :class:`letsencrypt.client.errors.LetsEncryptReverterError`:
            when save is attempting to overwrite a temporary file.

        """
        protected_files = []

        # Get temp modified files
        temp_path = os.path.join(self.direc['temp'], "FILEPATHS")
        if os.path.isfile(temp_path):
            with open(temp_path, 'r') as protected_fd:
                protected_files.extend(protected_fd.read().splitlines())

        # Get temp new files
        new_path = os.path.join(self.direc['temp'], "NEW_FILES")
        if os.path.isfile(new_path):
            with open(new_path, 'r') as protected_fd:
                protected_files.extend(protected_fd.read().splitlines())

        # Verify no save_file is in protected_files
        for filename in protected_files:
            if filename in save_files:
                raise errors.LetsEncryptReverterError(
                    "Attempting to overwrite challenge "
                    "file - %s" % filename)

    def register_file_creation(self, temporary, *files):
        r"""Register the creation of all files during letsencrypt execution.

        Call this method before writing to the file to make sure that the
        file will be cleaned up if the program exits unexpectedly.
        (Before a save occurs)

        :param bool temporary: If the file creation registry is for
            a temp or permanent save.
        :param \*files: file paths (str) to be registered

        :raises :class:`letsencrypt.client.errors.LetsEncryptReverterError`: If
            call does not contain necessary parameters or if the file creation
            is unable to be registered.

        """
        # Make sure some files are provided... as this is an error
        # Made this mistake in my initial implementation of apache.dvsni.py
        if not files:
            raise errors.LetsEncryptReverterError(
                "Forgot to provide files to registration call")

        if temporary:
            cp_dir = self.direc['temp']
        else:
            cp_dir = self.direc['progress']

        le_util.make_or_verify_dir(cp_dir, 0o755, os.geteuid())

        # Append all new files (that aren't already registered)
        new_fd = None
        try:
            new_fd, ex_files = self._read_and_append(
                os.path.join(cp_dir, "NEW_FILES"))

            for path in files:
                if path not in ex_files:
                    new_fd.write("{0}{1}".format(path, os.linesep))
        except (IOError, OSError):
            logging.error("Unable to register file creation(s) - %s", files)
            raise errors.LetsEncryptReverterError(
                "Unable to register file creation(s) - {0}".format(files))
        finally:
            if new_fd is not None:
                new_fd.close()

    def recovery_routine(self):
        """Revert all previously modified files.

        First, any changes found in self.direc['temp'] are removed,
        then IN_PROGRESS changes are removed The order is important.
        IN_PROGRESS is unable to add files that are already added by a TEMP
        change.  Thus TEMP must be rolled back first because that will be the
        'latest' occurrence of the file.

        """
        self.revert_temporary_config()
        if os.path.isdir(self.direc['progress']):
            try:
                self._recover_checkpoint(self.direc['progress'])
            except errors.LetsEncryptReverterError:
                # We have a partial or incomplete recovery
                logging.fatal("Incomplete or failed recovery for IN_PROGRESS "
                              "checkpoint - %s",
                              self.direc['progress'])
                raise errors.LetsEncryptReverterError(
                    "Incomplete or failed recovery for IN_PROGRESS checkpoint "
                    "- %s" % self.direc['progress'])

    def _remove_contained_files(self, file_list):  # pylint: disable=no-self-use
        """Erase all files contained within file_list.

        :param str file_list: file containing list of file paths to be deleted

        :returns: Success
        :rtype: bool

        :raises :class:`letsencrypt.client.errors.LetsEncryptReverterError`: If
            all files within file_list cannot be removed

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
                        logging.warning(
                            "File: %s - Could not be found to be deleted%s"
                            "LE probably shut down unexpectedly",
                            os.linesep, path)
        except (IOError, OSError):
            logging.fatal(
                "Unable to remove filepaths contained within %s", file_list)
            raise errors.LetsEncryptReverterError(
                "Unable to remove filepaths contained within "
                "{0}".format(file_list))

        return True

    def finalize_checkpoint(self, title):
        """Move IN_PROGRESS checkpoint to timestamped checkpoint.

        Adds title to self.direc['progress'] CHANGES_SINCE
        Move self.direc['progress'] to Backups directory and
        rename the directory as a timestamp

        :param str title: Title describing checkpoint

        :raises :class:`letsencrypt.client.errors.LetsEncryptReverterError`

        """
        # Check to make sure an "in progress" directory exists
        if not os.path.isdir(self.direc['progress']):
            logging.warning("No IN_PROGRESS checkpoint to finalize")
            return

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

        self._timestamp_progress_dir()

    def _timestamp_progress_dir(self):
        """Timestamp the checkpoint."""
        # It is possible save checkpoints faster than 1 per second resulting in
        # collisions in the naming convention.
        cur_time = time.time()
        for _ in range(10):
            final_dir = os.path.join(self.direc['backup'], str(cur_time))
            try:
                os.rename(self.direc['progress'], final_dir)
                return
            except OSError:
                # It is possible if the checkpoints are made extremely quickly
                # that will result in a name collision.
                # If so, increment and try again
                cur_time += .01

        # After 10 attempts... something is probably wrong here...
        logging.error(
            "Unable to finalize checkpoint, %s -> %s",
            self.direc['progress'], final_dir)
        raise errors.LetsEncryptReverterError(
            "Unable to finalize checkpoint renaming")
