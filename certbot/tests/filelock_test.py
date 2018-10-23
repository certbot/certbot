"""Tests for certbot.filelock."""
import subprocess
import unittest
import os
import sys

from certbot import errors
from certbot.tests import util as test_util

from certbot.filelock import lock_for_dir
from certbot.filelock import lock_for_file

def subprocess_acquire_lock_dir(dir_path):
    """Test a lock is correctly acquired on a directory."""
    command = (
        '{0} -c "from certbot.filelock import lock_for_dir; '
        'lock = lock_for_dir(\'{1}\'); lock.acquire();"'
        .format(sys.executable, os.path.normpath(dir_path).replace('\\', '\\\\')))
    return subprocess.call(command, shell=True)

def subprocess_acquire_lock_file(file_path):
    """Test a lock is correctly acquired on a file."""
    command = (
        '{0} -c "from certbot.filelock import lock_for_file; '
        'lock = lock_for_file(\'{1}\'); lock.acquire();"'
        .format(sys.executable, os.path.normpath(file_path).replace('\\', '\\\\')))
    return subprocess.call(command, shell=True)

class LockDirTest(test_util.TempDirTestCase):
    def test_protected_lock_dir(self):
        with lock_for_dir(self.tempdir):
            self.assertNotEqual(subprocess_acquire_lock_dir(self.tempdir), 0)

class LockFileTest(test_util.TempDirTestCase):
    def setUp(self):
        super(LockFileTest, self).setUp()
        self.tempfile = os.path.normpath(os.path.join(self.tempdir, 'target'))
        open(self.tempfile, 'a').close()

    def tearDown(self):
        os.unlink(self.tempfile)
        super(LockFileTest, self).tearDown()

    def test_protected_lock_file(self):
        with lock_for_file(self.tempfile):
            self.assertNotEqual(subprocess_acquire_lock_file(self.tempfile), 0)

    def test_unprotected_lock_file(self):
        lock = lock_for_file(self.tempfile)
        try:
            lock.acquire()
        finally:
            lock.release()

        self.assertEqual(subprocess_acquire_lock_file(self.tempfile), 0)

    def test_unacquired_lock_file(self):
        try:
            lock = lock_for_file(self.tempfile)
            self.assertEqual(subprocess_acquire_lock_file(self.tempfile), 0)
        finally:
            lock.release()

    def test_multilock(self):
        lock = lock_for_file(self.tempfile)
        with lock:
            with lock:
                self.assertNotEqual(subprocess_acquire_lock_file(self.tempfile), 0)
            self.assertNotEqual(subprocess_acquire_lock_file(self.tempfile), 0)

        self.assertEqual(subprocess_acquire_lock_file(self.tempfile), 0)

    def test_raise_exception(self):
        with lock_for_file(self.tempfile):
            lock2 = lock_for_file(self.tempfile)
            try:
                with self.assertRaises(errors.LockError):
                    lock2.acquire()
            finally:
                lock2.release()

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
