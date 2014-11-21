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

    def __init__(self):
        super(AugeasConfigurator, self).__init__()
        # TODO: this instantiation can be optimized to only load
        #       relevant files - I believe -> NO_MODL_AUTOLOAD
        # Set Augeas flags to save backup
        self.aug = augeas.Augeas(flags=augeas.Augeas.NONE)
        self.save_notes = ""

    def check_parsing_errors(self, lens):
        """
        This function checks to see if Augeas was unable to parse any of the
        lens files
        """
        error_files = self.aug.match("/augeas//error")

        for e in error_files:
            # Check to see if it was an error resulting from the use of
            # the httpd lens
            lens_path = self.aug.get(e + '/lens')
            # As aug.get may return null
            if lens_path and lens in lens_path:
                # Strip off /augeas/files and /error
                logger.error('There has been an error in parsing the file: %s' % e[13:len(e) - 6])
                logger.error(self.aug.get(e + '/message'))


    def save(self, title=None, temporary=False):
        """
        Saves all changes to the configuration files
        This function is not transactional
        TODO: Instead rely on challenge to backup all files before modifications

        title:     string - The title of the save. If a title is given, the
                            configuration will be saved as a new checkpoint
                            and put in a timestamped directory.
                            `title` has no effect if temporary is true.
        temporary: boolean - Indicates whether the changes made will be
                             quickly reversed in the future (challenges)
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
                    logger.error("Unable to save file - %s" % err[13:len(err)-6])
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
            for p in save_paths:
                save_files.add(self.aug.get(p)[6:])

            valid, message = self.check_tempfile_saves(save_files, temporary)

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
            success = self.__finalize_checkpoint(CONFIG.IN_PROGRESS_DIR, title)
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
        """
        This function should reload the users original configuration files
        for all saves with reversible=True
        """
        if os.path.isdir(CONFIG.TEMP_CHECKPOINT_DIR):
            result = self.__recover_checkpoint(CONFIG.TEMP_CHECKPOINT_DIR)
            changes = True
            if result != 0:
                # We have a partial or incomplete recovery
                logger.fatal("Incomplete or failed recovery for %s" % CONFIG.TEMP_CHECKPOINT_DIR)
                sys.exit(67)
            # Remember to reload Augeas
            self.aug.load()


    def rollback_checkpoints(self, rollback = 1):
        """ Revert 'rollback' number of configuration checkpoints """
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
            logger.error("Unable to rollback %d checkpoints, only %d exist" % (rollback, len(backups)))

        while rollback > 0 and backups:
            cp_dir = CONFIG.BACKUP_DIR + backups.pop()
            result = self.__recover_checkpoint(cp_dir)
            if result != 0:
                logger.fatal("Failed to load checkpoint during rollback")
                sys.exit(39)
            rollback -= 1

        self.aug.load()

    def display_checkpoints(self):
        """
        Displays all saved checkpoints
        Note: Any 'IN_PROGRESS' checkpoints will be removed by the cleanup
        script found in the constructor, before this function would ever be
        called
        """
        backups = os.listdir(CONFIG.BACKUP_DIR)
        backups.sort(reverse=True)

        if not backups:
            print "Letsencrypt has not saved any backups of your apache configuration"
        # Make sure there isn't anything unexpected in the backup folder
        # There should only be timestamped (float) directories
        try:
            for bu in backups:
                float(bu)
        except:
            assert False, "Invalid files in %s" % CONFIG.BACKUP_DIR

        for bu in backups:
            print time.ctime(float(bu))
            with open(CONFIG.BACKUP_DIR + bu + "/CHANGES_SINCE") as f:
                print f.read()

            print "Affected files:"
            with open(CONFIG.BACKUP_DIR + bu + "/FILEPATHS") as f:
                filepaths = f.read().splitlines()
                for fp in filepaths:
                    print "  %s" % fp

            try:
                with open(CONFIG.BACKUP_DIR + bu + "/NEW_FILES") as f:
                    print "New Configuration Files:"
                    filepaths = f.read().splitlines()
                    for fp in filepaths:
                        print "  %s" % fp
            except:
                pass
            print ""

    def __finalize_checkpoint(self, cp_dir, title):
        """
        Add title to cp_dir CHANGES_SINCE
        Move cp_dir to Backups directory and rename with timestamp
        """
        final_dir = CONFIG.BACKUP_DIR + str(time.time())
        try:
            with open(cp_dir + "CHANGES_SINCE.tmp", 'w') as ft:
                ft.write("-- %s --\n" % title)
                with open(cp_dir + "CHANGES_SINCE", 'r') as f:
                  ft.write(f.read())
            shutil.move(cp_dir + "CHANGES_SINCE.tmp", cp_dir + "CHANGES_SINCE")
        except:
            logger.error("Unable to finalize checkpoint - adding title")
            return False
        try:
            os.rename(cp_dir, final_dir)
        except:
            logger.error("Unable to finalize checkpoint, %s -> %s" % (cp_dir, final_dir))
            return False
        return True

    def add_to_checkpoint(self, cp_dir, save_files):
        le_util.make_or_verify_dir(cp_dir, 0755)

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
                shutil.copy2(filename, cp_dir + os.path.basename(filename) + "_" + str(idx))
                op_fd.write(filename + '\n')
                idx += 1
        op_fd.close()

        with open(cp_dir + "CHANGES_SINCE", 'a') as notes_fd:
            notes_fd.write(self.save_notes)



    def __recover_checkpoint(self, cp_dir):
        """
        Recover a specific checkpoint provided by cp_dir
        Note: this function does not reload augeas.

        returns: 0 success, 1 Unable to revert, -1 Unable to delete
        """

        if os.path.isfile(cp_dir + "/FILEPATHS"):
            try:
                with open(cp_dir + "/FILEPATHS") as f:
                    filepaths = f.read().splitlines()
                    for idx, fp in enumerate(filepaths):
                        shutil.copy2(cp_dir + '/' + os.path.basename(fp) + '_' + str(idx), fp)
            except:
                # This file is required in all checkpoints.
                logger.error("Unable to recover files from %s" % cp_dir)
                return 1

        # Remove any newly added files if they exist
        self.__remove_contained_files(cp_dir + "/NEW_FILES")

        try:
            shutil.rmtree(cp_dir)
        except:
            logger.error("Unable to remove directory: %s" % cp_dir)
            return -1

        return 0

    def check_tempfile_saves(self, save_files, temporary):
        temp_path = "%sFILEPATHS" % CONFIG.TEMP_CHECKPOINT_DIR
        if os.path.isfile(temp_path):
            with open(temp_path, 'r') as protected_fd:
                protected_files = protected_fd.read().splitlines()
                for filename in protected_files:
                    if filename in save_files:
                        return False, "Attempting to overwrite challenge file - %s" % filename

        return True, "Successful"


    def register_file_creation(self, temporary, *files):
        """
        This is used to register the creation of all files during Letsencrypt
        execution. Call this method before writing to the file to make sure
        that the file will be cleaned up if the program exits unexpectedly.
        (Before a save occurs)
        """
        if temporary:
            cp_dir = CONFIG.TEMP_CHECKPOINT_DIR
        else:
            cp_dir = CONFIG.IN_PROGRESS_DIR

        le_util.make_or_verify_dir(cp_dir)
        try:
            with open(cp_dir + "NEW_FILES", 'a') as fd:
                for f in files:
                    fd.write("%s\n" % f)
        except:
            logger.error("ERROR: Unable to register file creation")


    def recovery_routine(self):
        """
        Revert all previously modified files. First, any changes found in
        CONFIG.TEMP_CHECKPOINT_DIR are removed, then IN_PROGRESS changes are removed
        The order is important. IN_PROGRESS is unable to add files that are
        already added by a TEMP change.  Thus TEMP must be rolled back first
        because that will be the 'latest' occurrence of the file.
        """
        self.revert_challenge_config()
        if os.path.isdir(CONFIG.IN_PROGRESS_DIR):
            result = self.__recover_checkpoint(CONFIG.IN_PROGRESS_DIR)
            if result != 0:
                # We have a partial or incomplete recovery
                # Not as egregious
                # TODO: Additional tests? recovery
                logger.fatal("Incomplete or failed recovery for %s" % CONFIG.IN_PROGRESS_DIR)
                sys.exit(68)

            # Need to reload configuration after these changes take effect
            self.aug.load()


    def __remove_contained_files(self, file_list):
        """
        Erase any files contained within the text file, file_list
        """
        # Check to see that file exists to differentiate can't find file_list
        # and can't remove filepaths within file_list errors.
        if not os.path.isfile(file_list):
            return False
        try:
            with open(file_list, 'r') as f:
                filepaths = f.read().splitlines()
                for fp in filepaths:
                    # Files are registered before they are added... so check to see if file
                    # exists first
                    if os.path.lexists(fp):
                        os.remove(fp)
                    else:
                        logger.warn("File: %s - Could not be found to be deleted\nProgram was probably shut down unexpectedly, in which case this is not a problem" % fp)
        except IOError:
            logger.fatal("Unable to remove filepaths contained within %s" % file_list)
            sys.exit(41)

        return True
