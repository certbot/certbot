"""Test letsencrypt.reverter."""
import csv
import itertools
import logging
import os
import shutil
import tempfile
import unittest

import mock

from letsencrypt import errors


class ReverterCheckpointLocalTest(unittest.TestCase):
    # pylint: disable=too-many-instance-attributes, too-many-public-methods
    """Test the Reverter Class."""
    def setUp(self):
        from letsencrypt.reverter import Reverter

        # Disable spurious errors... we are trying to test for them
        logging.disable(logging.CRITICAL)

        self.config = setup_work_direc()
        self.reverter = Reverter(self.config)

        tup = setup_test_files()
        self.config1, self.config2, self.dir1, self.dir2, self.sets = tup

    def tearDown(self):
        shutil.rmtree(self.config.work_dir)
        shutil.rmtree(self.dir1)
        shutil.rmtree(self.dir2)

        logging.disable(logging.NOTSET)

    def test_basic_add_to_temp_checkpoint(self):
        # These shouldn't conflict even though they are both named config.txt
        self.reverter.add_to_temp_checkpoint(self.sets[0], "save1")
        self.reverter.add_to_temp_checkpoint(self.sets[1], "save2")

        self.assertTrue(os.path.isdir(self.config.temp_checkpoint_dir))
        self.assertEqual(get_save_notes(
            self.config.temp_checkpoint_dir), "save1save2")
        self.assertFalse(os.path.isfile(
            os.path.join(self.config.temp_checkpoint_dir, "NEW_FILES")))

        self.assertEqual(
            get_filepaths(self.config.temp_checkpoint_dir),
            "{0}\n{1}\n".format(self.config1, self.config2))

    def test_add_to_checkpoint_copy_failure(self):
        with mock.patch("letsencrypt.reverter.shutil.copy2") as mock_copy2:
            mock_copy2.side_effect = IOError("bad copy")
            self.assertRaises(
                errors.ReverterError, self.reverter.add_to_checkpoint,
                self.sets[0], "save1")

    def test_checkpoint_conflict(self):
        """Make sure that checkpoint errors are thrown appropriately."""
        config3 = os.path.join(self.dir1, "config3.txt")
        self.reverter.register_file_creation(True, config3)
        update_file(config3, "This is a new file!")

        self.reverter.add_to_checkpoint(self.sets[2], "save1")
        # This shouldn't throw an error
        self.reverter.add_to_temp_checkpoint(self.sets[0], "save2")
        # Raise error
        self.assertRaises(errors.ReverterError, self.reverter.add_to_checkpoint,
                          self.sets[2], "save3")
        # Should not cause an error
        self.reverter.add_to_checkpoint(self.sets[1], "save4")

        # Check to make sure new files are also checked...
        self.assertRaises(errors.ReverterError, self.reverter.add_to_checkpoint,
                          set([config3]), "invalid save")

    def test_multiple_saves_and_temp_revert(self):
        self.reverter.add_to_temp_checkpoint(self.sets[0], "save1")
        update_file(self.config1, "updated-directive")
        self.reverter.add_to_temp_checkpoint(self.sets[0], "save2-updated dir")
        update_file(self.config1, "new directive change that we won't keep")

        self.reverter.revert_temporary_config()
        self.assertEqual(read_in(self.config1), "directive-dir1")

    def test_multiple_registration_fail_and_revert(self):

        config3 = os.path.join(self.dir1, "config3.txt")
        update_file(config3, "Config3")
        config4 = os.path.join(self.dir2, "config4.txt")
        update_file(config4, "Config4")

        # Test multiple registrations and two registrations at once
        self.reverter.register_file_creation(True, self.config1)
        self.reverter.register_file_creation(True, self.config2)
        self.reverter.register_file_creation(True, config3, config4)

        # Simulate Let's Encrypt crash... recovery routine is run
        self.reverter.recovery_routine()

        self.assertFalse(os.path.isfile(self.config1))
        self.assertFalse(os.path.isfile(self.config2))
        self.assertFalse(os.path.isfile(config3))
        self.assertFalse(os.path.isfile(config4))

    def test_multiple_registration_same_file(self):
        self.reverter.register_file_creation(True, self.config1)
        self.reverter.register_file_creation(True, self.config1)
        self.reverter.register_file_creation(True, self.config1)
        self.reverter.register_file_creation(True, self.config1)

        files = get_new_files(self.config.temp_checkpoint_dir)

        self.assertEqual(len(files), 1)

    def test_register_file_creation_write_error(self):
        m_open = mock.mock_open()
        with mock.patch("letsencrypt.reverter.open", m_open, create=True):
            m_open.side_effect = OSError("bad open")
            self.assertRaises(
                errors.ReverterError, self.reverter.register_file_creation,
                True, self.config1)

    def test_bad_registration(self):
        # Made this mistake and want to make sure it doesn't happen again...
        self.assertRaises(
            errors.ReverterError, self.reverter.register_file_creation,
            "filepath")

    def test_register_undo_command(self):
        coms = [
            ["a2dismod", "ssl"],
            ["a2dismod", "rewrite"],
            ["cleanslate"]
        ]
        for com in coms:
            self.reverter.register_undo_command(True, com)

        act_coms = get_undo_commands(self.config.temp_checkpoint_dir)

        for a_com, com in itertools.izip(act_coms, coms):
            self.assertEqual(a_com, com)

    def test_bad_register_undo_command(self):
        m_open = mock.mock_open()
        with mock.patch("letsencrypt.reverter.open", m_open, create=True):
            m_open.side_effect = OSError("bad open")
            self.assertRaises(
                errors.ReverterError, self.reverter.register_undo_command,
                True, ["command"])

    @mock.patch("letsencrypt.le_util.run_script")
    def test_run_undo_commands(self, mock_run):
        mock_run.side_effect = ["", errors.SubprocessError]
        coms = [
            ["invalid_command"],
            ["a2dismod", "ssl"],
        ]
        for com in coms:
            self.reverter.register_undo_command(True, com)

        self.reverter.revert_temporary_config()

        self.assertEqual(mock_run.call_count, 2)

    def test_recovery_routine_in_progress_failure(self):
        self.reverter.add_to_checkpoint(self.sets[0], "perm save")

        # pylint: disable=protected-access
        self.reverter._recover_checkpoint = mock.MagicMock(
            side_effect=errors.ReverterError)
        self.assertRaises(errors.ReverterError, self.reverter.recovery_routine)

    def test_recover_checkpoint_revert_temp_failures(self):

        mock_recover = mock.MagicMock(
            side_effect=errors.ReverterError("e"))

        # pylint: disable=protected-access
        self.reverter._recover_checkpoint = mock_recover

        self.reverter.add_to_temp_checkpoint(self.sets[0], "config1 save")

        self.assertRaises(
            errors.ReverterError, self.reverter.revert_temporary_config)

    def test_recover_checkpoint_rollback_failure(self):
        mock_recover = mock.MagicMock(
            side_effect=errors.ReverterError("e"))
        # pylint: disable=protected-access
        self.reverter._recover_checkpoint = mock_recover

        self.reverter.add_to_checkpoint(self.sets[0], "config1 save")
        self.reverter.finalize_checkpoint("Title")

        self.assertRaises(
            errors.ReverterError, self.reverter.rollback_checkpoints, 1)

    def test_recover_checkpoint_copy_failure(self):
        self.reverter.add_to_temp_checkpoint(self.sets[0], "save1")

        with mock.patch("letsencrypt.reverter.shutil.copy2") as mock_copy2:
            mock_copy2.side_effect = OSError("bad copy")
            self.assertRaises(
                errors.ReverterError, self.reverter.revert_temporary_config)

    def test_recover_checkpoint_rm_failure(self):
        self.reverter.add_to_temp_checkpoint(self.sets[0], "temp save")

        with mock.patch("letsencrypt.reverter.shutil.rmtree") as mock_rmtree:
            mock_rmtree.side_effect = OSError("Cannot remove tree")
            self.assertRaises(
                errors.ReverterError, self.reverter.revert_temporary_config)

    @mock.patch("letsencrypt.reverter.logger.warning")
    def test_recover_checkpoint_missing_new_files(self, mock_warn):
        self.reverter.register_file_creation(
            True, os.path.join(self.dir1, "missing_file.txt"))
        self.reverter.revert_temporary_config()
        self.assertEqual(mock_warn.call_count, 1)

    @mock.patch("letsencrypt.reverter.os.remove")
    def test_recover_checkpoint_remove_failure(self, mock_remove):
        self.reverter.register_file_creation(True, self.config1)
        mock_remove.side_effect = OSError("Can't remove")
        self.assertRaises(
            errors.ReverterError, self.reverter.revert_temporary_config)

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


class TestFullCheckpointsReverter(unittest.TestCase):
    # pylint: disable=too-many-instance-attributes
    """Tests functions having to deal with full checkpoints."""
    def setUp(self):
        from letsencrypt.reverter import Reverter
        # Disable spurious errors...
        logging.disable(logging.CRITICAL)

        self.config = setup_work_direc()
        self.reverter = Reverter(self.config)

        tup = setup_test_files()
        self.config1, self.config2, self.dir1, self.dir2, self.sets = tup

    def tearDown(self):
        shutil.rmtree(self.config.work_dir)
        shutil.rmtree(self.dir1)
        shutil.rmtree(self.dir2)

        logging.disable(logging.NOTSET)

    def test_rollback_improper_inputs(self):
        self.assertRaises(
            errors.ReverterError, self.reverter.rollback_checkpoints, "-1")
        self.assertRaises(
            errors.ReverterError, self.reverter.rollback_checkpoints, -1000)
        self.assertRaises(
            errors.ReverterError, self.reverter.rollback_checkpoints, "one")

    def test_rollback_finalize_checkpoint_valid_inputs(self):

        config3 = self._setup_three_checkpoints()

        # Check resulting backup directory
        self.assertEqual(len(os.listdir(self.config.backup_dir)), 3)
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
        all_dirs = os.listdir(self.config.backup_dir)
        self.assertEqual(len(all_dirs), 1)
        self.assertTrue(
            "First Checkpoint" in get_save_notes(
                os.path.join(self.config.backup_dir, all_dirs[0])))
        # Final rollback
        self.reverter.rollback_checkpoints(1)
        self.assertEqual(read_in(self.config1), "directive-dir1")

    def test_finalize_checkpoint_no_in_progress(self):
        # No need to warn for this... just make sure there are no errors.
        self.reverter.finalize_checkpoint("No checkpoint...")

    @mock.patch("letsencrypt.reverter.shutil.move")
    def test_finalize_checkpoint_cannot_title(self, mock_move):
        self.reverter.add_to_checkpoint(self.sets[0], "perm save")
        mock_move.side_effect = OSError("cannot move")

        self.assertRaises(
            errors.ReverterError, self.reverter.finalize_checkpoint, "Title")

    @mock.patch("letsencrypt.reverter.os.rename")
    def test_finalize_checkpoint_no_rename_directory(self, mock_rename):

        self.reverter.add_to_checkpoint(self.sets[0], "perm save")
        mock_rename.side_effect = OSError

        self.assertRaises(
            errors.ReverterError, self.reverter.finalize_checkpoint, "Title")

    @mock.patch("letsencrypt.reverter.logger")
    def test_rollback_too_many(self, mock_logger):
        # Test no exist warning...
        self.reverter.rollback_checkpoints(1)
        self.assertEqual(mock_logger.warning.call_count, 1)

        # Test Generic warning
        mock_logger.warning.call_count = 0
        self._setup_three_checkpoints()
        self.reverter.rollback_checkpoints(4)
        self.assertEqual(mock_logger.warning.call_count, 1)

    def test_multi_rollback(self):
        config3 = self._setup_three_checkpoints()
        self.reverter.rollback_checkpoints(3)

        self.assertEqual(read_in(self.config1), "directive-dir1")
        self.assertEqual(read_in(self.config2), "directive-dir2")
        self.assertFalse(os.path.isfile(config3))

    @mock.patch("letsencrypt.reverter.zope.component.getUtility")
    def test_view_config_changes(self, mock_output):
        """This is not strict as this is subject to change."""
        self._setup_three_checkpoints()

        # Make sure it doesn't throw any errors
        self.reverter.view_config_changes()

        # Make sure notification is output
        self.assertEqual(mock_output().notification.call_count, 1)

    @mock.patch("letsencrypt.reverter.logger")
    def test_view_config_changes_no_backups(self, mock_logger):
        self.reverter.view_config_changes()
        self.assertTrue(mock_logger.info.call_count > 0)

    def test_view_config_changes_bad_backups_dir(self):
        # There shouldn't be any "in progess directories when this is called
        # It must just be clean checkpoints
        os.makedirs(os.path.join(self.config.backup_dir, "in_progress"))

        self.assertRaises(
            errors.ReverterError, self.reverter.view_config_changes)

    def test_view_config_changes_for_logging(self):
        self._setup_three_checkpoints()

        config_changes = self.reverter.view_config_changes(for_logging=True)

        self.assertTrue("First Checkpoint" in config_changes)
        self.assertTrue("Second Checkpoint" in config_changes)
        self.assertTrue("Third Checkpoint" in config_changes)

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


def setup_work_direc():
    """Setup directories.

    :returns: Mocked :class:`letsencrypt.interfaces.IConfig`

    """
    work_dir = tempfile.mkdtemp("work")
    backup_dir = os.path.join(work_dir, "backup")

    return mock.MagicMock(
        work_dir=work_dir, backup_dir=backup_dir,
        temp_checkpoint_dir=os.path.join(work_dir, "temp"),
        in_progress_dir=os.path.join(backup_dir, "in_progress_dir"))


def setup_test_files():
    """Setup sample configuration files."""
    dir1 = tempfile.mkdtemp("dir1")
    dir2 = tempfile.mkdtemp("dir2")
    config1 = os.path.join(dir1, "config.txt")
    config2 = os.path.join(dir2, "config.txt")
    with open(config1, "w") as file_fd:
        file_fd.write("directive-dir1")
    with open(config2, "w") as file_fd:
        file_fd.write("directive-dir2")

    sets = [set([config1]),
            set([config2]),
            set([config1, config2])]

    return config1, config2, dir1, dir2, sets


def get_save_notes(dire):
    """Read save notes"""
    return read_in(os.path.join(dire, "CHANGES_SINCE"))


def get_filepaths(dire):
    """Get Filepaths"""
    return read_in(os.path.join(dire, "FILEPATHS"))


def get_new_files(dire):
    """Get new files."""
    return read_in(os.path.join(dire, "NEW_FILES")).splitlines()


def get_undo_commands(dire):
    """Get new files."""
    with open(os.path.join(dire, "COMMANDS")) as csvfile:
        return list(csv.reader(csvfile))


def read_in(path):
    """Read in a file, return the str"""
    with open(path, "r") as file_fd:
        return file_fd.read()


def update_file(filename, string):
    """Update a file with a new value."""
    with open(filename, "w") as file_fd:
        file_fd.write(string)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
