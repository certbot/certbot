import os
import sys
import shutil
import time

import augeas

from letsencrypt.client import CONFIG
from letsencrypt.client import configurator
from letsencrypt.client import le_util
from letsencrypt.client import logger


class AugeasConfigurator(configurator.Configurator):
    """Base Augeas Configurator class.

    TODO: Fix generic exception handling.
    TODO: Go through and make sure to use os.path.join

    """

    def __init__(self):
        super(AugeasConfigurator, self).__init__()
        # TODO: this instantiation can be optimized to only load
        #       relevant files - I believe -> NO_MODL_AUTOLOAD
        # Set Augeas flags to save backup
        self.aug = augeas.Augeas(flags=augeas.Augeas.NONE)
        self.save_notes = ""

    def check_parsing_errors(self, lens):
        """Verify Augeas can parse all of the lens files.

        :param lens: lens to check for errors
        :type lens: str

        """
        error_files = self.aug.match("/augeas//error")

        for path in error_files:
            # Check to see if it was an error resulting from the use of
            # the httpd lens
            lens_path = self.aug.get(path + '/lens')
            # As aug.get may return null
            if lens_path and lens in lens_path:
                # Strip off /augeas/files and /error
                logger.error('There has been an error in parsing the file: '
                             '%s' % path[13:len(path) - 6])
                logger.error(self.aug.get(path + '/message'))

    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.

        This function first checks for save errors, if none are found,
        all configuration changes made will be saved. According to the
        function parameters.

        :param title: The title of the save. If a title is given, the
                      configuration will be saved as a new checkpoint
                      and put in a timestamped directory.
        :type title: str

        :param temporary: Indicates whether the changes made will be quickly
                          reversed in the future (ie. challenges)
        :type temporary: bool

        """
        save_state = self.aug.get("/augeas/save")
        self.aug.set("/augeas/save", "noop")
        # Existing Errors
        ex_errs = self.aug.match("/augeas//error")
        try:
            # This is a noop save
            self.aug.save()
        except:
            # Check for the root of save problems
            new_errs = self.aug.match("/augeas//error")
            # logger.error("During Save - " + mod_conf)
            # Only print new errors caused by recent save
            for err in new_errs:
                if err not in ex_errs:
                    logger.error("Unable to save file - "
                                 "%s" % err[13:len(err)-6])
            logger.error("Attempted Save Notes")
            logger.error(self.save_notes)
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
                logger.fatal(message)
                # What is the protocol in this situation?
                # This shouldn't happen if the challenge codebase is correct
                return False

            # Create Checkpoint
            if temporary:
                self.add_to_checkpoint(CONFIG.TEMP_CHECKPOINT_DIR, save_files)
            else:
                self.add_to_checkpoint(CONFIG.IN_PROGRESS_DIR, save_files)

        if title and not temporary and os.path.isdir(CONFIG.IN_PROGRESS_DIR):
            success = finalize_checkpoint(CONFIG.IN_PROGRESS_DIR, title)
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
        if os.path.isdir(CONFIG.TEMP_CHECKPOINT_DIR):
            result = self._recover_checkpoint(CONFIG.TEMP_CHECKPOINT_DIR)
            if result != 0:
                # We have a partial or incomplete recovery
                logger.fatal("Incomplete or failed recovery for "
                             "%s" % CONFIG.TEMP_CHECKPOINT_DIR)
                sys.exit(67)
            # Remember to reload Augeas
            self.aug.load()

    def rollback_checkpoints(self, rollback=1):
        """Revert 'rollback' number of configuration checkpoints.

        :param rollback: Number of checkpoints to reverse
        :type rollback: int

        """
        try:
            rollback = int(rollback)
        except:
            logger.error("Rollback argument must be a positive integer")
        # Sanity check input
        if rollback < 1:
            logger.error("Rollback argument must be a positive integer")
            return

        backups = os.listdir(CONFIG.BACKUP_DIR)
        backups.sort()

        if len(backups) < rollback:
            logger.error(("Unable to rollback %d checkpoints, only "
                         "%d exist") % (rollback, len(backups)))

        while rollback > 0 and backups:
            cp_dir = CONFIG.BACKUP_DIR + backups.pop()
            result = self._recover_checkpoint(cp_dir)
            if result != 0:
                logger.fatal("Failed to load checkpoint during rollback")
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
        backups = os.listdir(CONFIG.BACKUP_DIR)
        backups.sort(reverse=True)

        if not backups:
            print ("Letsencrypt has not saved any backups of your "
                   "apache configuration")
        # Make sure there isn't anything unexpected in the backup folder
        # There should only be timestamped (float) directories
        try:
            for bkup in backups:
                float(bkup)
        except:
            assert False, "Invalid files in %s" % CONFIG.BACKUP_DIR

        for bkup in backups:
            print time.ctime(float(bkup))
            with open(
                    CONFIG.BACKUP_DIR + bkup + "/CHANGES_SINCE") as changes_fd:
                print changes_fd.read()

            print "Affected files:"
            with open(
                    CONFIG.BACKUP_DIR + bkup + "/FILEPATHS") as paths_fd:
                filepaths = paths_fd.read().splitlines()
                for path in filepaths:
                    print "  %s" % path

            try:
                with open(
                        CONFIG.BACKUP_DIR + bkup + "/NEW_FILES") as new_fd:
                    print "New Configuration Files:"
                    filepaths = new_fd.read().splitlines()
                    for path in filepaths:
                        print "  %s" % path
            except:
                pass
            print ""

    def add_to_checkpoint(self, cp_dir, save_files):
        """Add save files to checkpoint directory.

        :param cp_dir: Checkpoint directory filepath
        :type cp_dir: str

        :param save_files: set of files to save
        :type save_files: set

        """
        le_util.make_or_verify_dir(cp_dir, 0o755)

        existing_filepaths = []
        op_fd = None
        # Open up FILEPATHS differently depending on if it already exists
        if os.path.isfile(cp_dir + "FILEPATHS"):
            op_fd = open(cp_dir + "FILEPATHS", 'r+')
            existing_filepaths = op_fd.read().splitlines()
        else:
            op_fd = open(cp_dir + "FILEPATHS", 'w')

        idx = len(existing_filepaths)
        for filename in save_files:
            if filename not in existing_filepaths:
                # Tag files with index so multiple files can
                # have the same filename
                logger.debug("Creating backup of %s" % filename)
                shutil.copy2(filename, cp_dir + os.path.basename(filename)
                             + "_" + str(idx))
                op_fd.write(filename + '\n')
                idx += 1
        op_fd.close()

        with open(cp_dir + "CHANGES_SINCE", 'a') as notes_fd:
            notes_fd.write(self.save_notes)

    def _recover_checkpoint(self, cp_dir):
        """Recover a specific checkpoint.

        Recover a specific checkpoint provided by cp_dir
        Note: this function does not reload augeas.

        :param cp_dir: checkpoint directory file path
        :type cp_dir: str

        :returns: 0 success, 1 Unable to revert, -1 Unable to delete
        :rtype: int

        """
        if os.path.isfile(cp_dir + "/FILEPATHS"):
            try:
                with open(cp_dir + "/FILEPATHS") as paths_fd:
                    filepaths = paths_fd.read().splitlines()
                    for idx, path in enumerate(filepaths):
                        shutil.copy2(cp_dir + '/' + os.path.basename(path)
                                     + '_' + str(idx), path)
            except:
                # This file is required in all checkpoints.
                logger.error("Unable to recover files from %s" % cp_dir)
                return 1

        # Remove any newly added files if they exist
        self._remove_contained_files(os.path.join(cp_dir, "/NEW_FILES"))

        try:
            shutil.rmtree(cp_dir)
        except:
            logger.error("Unable to remove directory: %s" % cp_dir)
            return -1

        return 0

    def check_tempfile_saves(self, save_files):
        """Verify save isn't overwriting any temporary files.

        :param save_files: Set of files about to be saved.
        :type save_files: set

        :returns: Success, error message
        :rtype: bool, str

        """
        temp_path = "%sFILEPATHS" % CONFIG.TEMP_CHECKPOINT_DIR
        if os.path.isfile(temp_path):
            with open(temp_path, 'r') as protected_fd:
                protected_files = protected_fd.read().splitlines()
                for filename in protected_files:
                    if filename in save_files:
                        return False, ("Attempting to overwrite challenge "
                                       "file - %s" % filename)

        return True, ""

    def register_file_creation(self, temporary, *files):
        """Register the creation of all files during letsencrypt execution.

        Call this method before writing to the file to make sure that the
        file will be cleaned up if the program exits unexpectedly.
        (Before a save occurs)

        :param temporary: If the file creation registry is for a temp or
        permanent save.
        :type temporary: bool

        :param *files: file paths to be registered
        :type *files: str

        """
        if temporary:
            cp_dir = CONFIG.TEMP_CHECKPOINT_DIR
        else:
            cp_dir = CONFIG.IN_PROGRESS_DIR

        le_util.make_or_verify_dir(cp_dir)
        try:
            with open(os.path.join(cp_dir, "NEW_FILES"), 'a') as new_fd:
                for file_path in files:
                    new_fd.write("%s\n" % file_path)
        except:
            logger.error("ERROR: Unable to register file creation")

    def recovery_routine(self):
        """Revert all previously modified files.

        First, any changes found in CONFIG.TEMP_CHECKPOINT_DIR are removed,
        then IN_PROGRESS changes are removed The order is important.
        IN_PROGRESS is unable to add files that are already added by a TEMP
        change.  Thus TEMP must be rolled back first because that will be the
        'latest' occurrence of the file.

        """
        self.revert_challenge_config()
        if os.path.isdir(CONFIG.IN_PROGRESS_DIR):
            result = self._recover_checkpoint(CONFIG.IN_PROGRESS_DIR)
            if result != 0:
                # We have a partial or incomplete recovery
                # Not as egregious
                # TODO: Additional tests? recovery
                logger.fatal("Incomplete or failed recovery for %s" %
                             CONFIG.IN_PROGRESS_DIR)
                sys.exit(68)

            # Need to reload configuration after these changes take effect
            self.aug.load()

    def _remove_contained_files(self, file_list):
        """Erase all files contained within file_list.

        :param file_list: file containing list of file paths to be deleted
        :type file_list: str

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
                        logger.warn((
                            "File: %s - Could not be found to be deleted\n"
                            "Program was probably shut down unexpectedly, "
                            "in which case this is not a problem") % path)
        except IOError:
            logger.fatal(
                "Unable to remove filepaths contained within %s" % file_list)
            sys.exit(41)

        return True


def finalize_checkpoint(cp_dir, title):
    """Move IN_PROGRESS checkpoint to timestamped checkpoint.

    Adds title to cp_dir CHANGES_SINCE
    Move cp_dir to Backups directory and rename with timestamp

    :param cp_dir: "IN PROGRESS" directory
    :type cp_dir: str

    :returns: Success
    :rtype: bool

    """
    final_dir = os.path.join(CONFIG.BACKUP_DIR, str(time.time()))
    try:
        with open(cp_dir + "CHANGES_SINCE.tmp", 'w') as changes_tmp:
            changes_tmp.write("-- %s --\n" % title)
            with open(cp_dir + "CHANGES_SINCE", 'r') as changes_orig:
                changes_tmp.write(changes_orig.read())
        shutil.move(os.path.join(cp_dir, "CHANGES_SINCE.tmp"),
                    os.path.join(cp_dir, "CHANGES_SINCE"))
    except:
        logger.error("Unable to finalize checkpoint - adding title")
        return False
    try:
        os.rename(cp_dir, final_dir)
    except:
        logger.error("Unable to finalize checkpoint, %s -> %s" %
                     (cp_dir, final_dir))
        return False
    return True
