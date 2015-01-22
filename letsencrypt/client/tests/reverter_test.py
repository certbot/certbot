"""Test letsencrypt.client.reverter."""
import logging
import os
import shutil
import tempfile
import unittest

class ReverterTest(unittest.TestCase):
    """Test the Reverter Class."""
    def setUp(self):
        from letsencrypt.client.reverter import Reverter

        # Disable spurious errors... we are trying to test for them
        logging.disable(logging.CRITICAL)

        self.work_dir = tempfile.mkdtemp("work")
        backup = os.path.join(self.work_dir, "backup")
        self.direc = {'backup': backup,
                      'temp': os.path.join(self.work_dir, "temp"),
                      'progress': os.path.join(backup, "progress")}

        self.reverter = Reverter(self.direc)

        self.dir1 = tempfile.mkdtemp("dir1")
        self.dir2 = tempfile.mkdtemp("dir2")
        self.config1 = os.path.join(self.dir1, "config.txt")
        self.config2 = os.path.join(self.dir2, "config.txt")
        with open(self.config1, 'w') as file_fd:
            file_fd.write("directive-dir1")
        with open(self.config2, 'w') as file_fd:
            file_fd.write("directive-dir2")

        self.sets = [set([self.config1]),
                     set([self.config2]),
                     set([self.config1, self.config2])]

    def tearDown(self):
        shutil.rmtree(self.work_dir)
        shutil.rmtree(self.dir1)
        shutil.rmtree(self.dir2)

    def test_basic_add_to_temp_checkpoint(self):
        # These shouldn't conflict even though they are both named config.txt
        self.reverter.add_to_temp_checkpoint(self.sets[0], "save1")
        self.reverter.add_to_temp_checkpoint(self.sets[1], "save2")

        self.assertTrue(os.path.isdir(self.reverter.direc['temp']))
        self.assertEqual(get_save_notes(self.direc['temp']), "save1save2")
        self.assertFalse(os.path.isfile(
            os.path.join(self.direc['temp'], "NEW_FILES")))

        self.assertEqual(
            get_filepaths(self.direc['temp']),
            "{0}\n{1}\n".format(self.config1, self.config2))

    def test_checkpoint_conflict(self):
        """Make sure that checkpoint errors are thrown appropriately."""
        from letsencrypt.client.errors import LetsEncryptReverterError

        config3 = os.path.join(self.dir1, "config3.txt")
        self.reverter.register_file_creation(True, config3)
        update_file(config3, "This is a new file!")

        self.reverter.add_to_checkpoint(self.sets[2], "save1")
        # This shouldn't throw an error
        self.reverter.add_to_temp_checkpoint(self.sets[0], "save2")
        # Raise error
        self.assertRaises(
            LetsEncryptReverterError, self.reverter.add_to_checkpoint,
            self.sets[2], "save3")
        # Should not cause an error
        self.reverter.add_to_checkpoint(self.sets[1], "save4")

        # Check to make sure new files are also checked...
        self.assertRaises(
            LetsEncryptReverterError,
            self.reverter.add_to_checkpoint,
            set([config3]), "invalid save")

    def test_multiple_saves_and_rollback(self):
        self.reverter.add_to_temp_checkpoint(self.sets[0], "save1")
        update_file(self.config1, "updated-directive")
        self.reverter.add_to_temp_checkpoint(self.sets[0], "save2-updated dir")
        update_file(self.config1, "new directive change that we won't keep")

        self.reverter.revert_temporary_config()
        self.assertEqual(read_in(self.config1), "directive-dir1")

    def test_recovery_routine_temp_and_perm(self):
        # Register a new perm checkpoint file
        config3 = os.path.join(self.dir1, "config3.txt")
        self.reverter.register_file_creation(False, config3)
        update_file(config3, "This is a new perm file!")

        # Add changes to perm checkpoint
        self.reverter.add_to_checkpoint(self.sets[0], "perm save1")
        update_file(self.config1, "updated perm config1")
        self.reverter.add_to_checkpoint(self.sets[1], "perm save2")
        update_file(self.config2, "updated perm config2")

        # Add changes to a temporary checkpoint
        self.reverter.add_to_temp_checkpoint(self.sets[0], "temp save1")
        update_file(self.config1, "second update now temp config1")

        # Register a new temp checkpoint file
        config4 = os.path.join(self.dir2, "config4.txt")
        self.reverter.register_file_creation(True, config4)
        update_file(config4, "New temporary file!")

        # Now erase everything
        self.reverter.recovery_routine()

        # Now Run tests
        # These were new files.. they should be removed
        self.assertFalse(os.path.isfile(config3))
        self.assertFalse(os.path.isfile(config4))

        # Check to make sure everything got rolled back appropriately
        self.assertEqual(read_in(self.config1), "directive-dir1")
        self.assertEqual(read_in(self.config2), "directive-dir2")

    def test_rollback_improper_inputs(self):
        from letsencrypt.client.errors import LetsEncryptReverterError
        self.assertRaises(
            LetsEncryptReverterError,
            self.reverter.rollback_checkpoints, "-1")
        self.assertRaises(
            LetsEncryptReverterError,
            self.reverter.rollback_checkpoints, -1000)
        self.assertRaises(
            LetsEncryptReverterError,
            self.reverter.rollback_checkpoints, "one")

    def test_rollback_finalize_checkpoint_valid_inputs(self):
        config3 = self._setup_three_checkpoints()

        # Check resulting backup directory
        self.assertEqual(len(os.listdir(self.direc['backup'])), 3)
        # Check rollbacks
        # First rollback
        self.reverter.rollback_checkpoints(1)
        self.assertEqual(read_in(self.config1), "update config1")
        self.assertEqual(read_in(self.config2), "update config2")
        # config3 was not included in checkpoint
        self.assertEqual(read_in(config3), "Final form config3")

        # Second rollback
        self.reverter.rollback_checkpoints(1)
        self.assertEqual(read_in(self.config1), "update config1")
        self.assertEqual(read_in(self.config2), "directive-dir2")
        self.assertFalse(os.path.isfile(config3))

        # One dir left... check title
        all_dirs = os.listdir(self.direc['backup'])
        self.assertEqual(len(all_dirs), 1)
        self.assertTrue(
            "First Checkpoint" in get_save_notes(
                os.path.join(self.direc['backup'], all_dirs[0])))
        # Final rollback
        self.reverter.rollback_checkpoints(1)
        self.assertEqual(read_in(self.config1), "directive-dir1")

    def test_multi_rollback(self):
        config3 = self._setup_three_checkpoints()
        self.reverter.rollback_checkpoints(3)

        self.assertEqual(read_in(self.config1), "directive-dir1")
        self.assertEqual(read_in(self.config2), "directive-dir2")
        self.assertFalse(os.path.isfile(config3))

    def test_view_config_changes(self):
        """This is not strict as this is subject to change."""
        self._setup_three_checkpoints()
        # Just make sure it doesn't throw any errors.
        self.reverter.view_config_changes()

    def _setup_three_checkpoints(self):
        """Generate some finalized checkpoints."""
        # Checkpoint1 - config1
        self.reverter.add_to_checkpoint(self.sets[0], "first save")
        self.reverter.finalize_checkpoint("First Checkpoint")

        update_file(self.config1, "update config1")

        # Checkpoint2 - new file config3, update config2
        config3 = os.path.join(self.dir1, "config3.txt")
        self.reverter.register_file_creation(False, config3)
        update_file(config3, "directive-config3")
        self.reverter.add_to_checkpoint(self.sets[1], "second save")
        self.reverter.finalize_checkpoint("Second Checkpoint")

        update_file(self.config2, "update config2")
        update_file(config3, "update config3")

        # Checkpoint3 - update config1, config2
        self.reverter.add_to_checkpoint(self.sets[2], "third save")
        self.reverter.finalize_checkpoint("Third Checkpoint - Save both")

        update_file(self.config1, "Final form config1")
        update_file(self.config2, "Final form config2")
        update_file(config3, "Final form config3")

        return config3


def get_save_notes(dir):
    """Read save notes"""
    return read_in(os.path.join(dir, 'CHANGES_SINCE'))


def get_filepaths(dir):
    """Get Filepaths"""
    return read_in(os.path.join(dir, 'FILEPATHS'))


def read_in(path):
    """Read in a file, return the str"""
    with open(path, 'r') as file_fd:
        return file_fd.read()


def update_file(filename, str):
    """Update a file with a new value."""
    with open(filename, 'w') as file_fd:
        file_fd.write(str)


if __name__ == '__main__':
    unittest.main()