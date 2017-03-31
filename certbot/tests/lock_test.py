"""Tests for certbot.lock."""
import functools
import multiprocessing
import os
import unittest

import mock

from certbot import errors
from certbot.tests import util as test_util


class LockDirTest(test_util.TempDirTestCase):
    """Tests for certbot.lock.lock_dir."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.lock import lock_dir
        return lock_dir(*args, **kwargs)

    def test_it(self):
        assert_raises = functools.partial(
            self.assertRaises, errors.LockError, self._call, self.tempdir)
        lock_path = os.path.join(self.tempdir, '.certbot.lock')
        lock_and_call(assert_raises, lock_path)


class LockFileTest(test_util.TempDirTestCase):
    """Tests for certbot.lock.LockFile."""
    @classmethod
    def _call(cls, *args, **kwargs):
        from certbot.lock import LockFile
        return LockFile(*args, **kwargs)

    def setUp(self):
        super(LockFileTest, self).setUp()
        self.lock_path = os.path.join(self.tempdir, 'test.lock')

    def test_contention(self):
        assert_raises = functools.partial(
            self.assertRaises, errors.LockError, self._call, self.lock_path)
        lock_and_call(assert_raises, self.lock_path)

    def test_race(self):
        should_delete = [True, False]
        stat = os.stat

        def delete_and_stat(path):
            """Wrap os.stat and maybe delete the file first."""
            if path == self.lock_path and should_delete.pop(0):
                os.remove(path)
            return stat(path)

        with mock.patch('certbot.lock.os.stat') as mock_stat:
            mock_stat.side_effect = delete_and_stat
            self._call(self.lock_path)
        self.assertFalse(should_delete)

    def test_locked_repr(self):
        lock_file = self._call(self.lock_path)
        locked_repr = repr(lock_file)
        self._test_repr_common(lock_file, locked_repr)
        self.assertTrue('acquired' in locked_repr)

    def test_released_repr(self):
        lock_file = self._call(self.lock_path)
        lock_file.release()
        released_repr = repr(lock_file)
        self._test_repr_common(lock_file, released_repr)
        self.assertTrue('released' in released_repr)

    def _test_repr_common(self, lock_file, lock_repr):
        self.assertTrue(lock_file.__class__.__name__ in lock_repr)
        self.assertTrue(self.lock_path in lock_repr)

    def test_removed(self):
        lock_file = self._call(self.lock_path)
        lock_file.release()
        self.assertFalse(os.path.exists(self.lock_path))

    @mock.patch('certbot.lock.fcntl.lockf')
    def test_unexpected_lockf_err(self, mock_lockf):
        msg = 'hi there'
        mock_lockf.side_effect = IOError(msg)
        try:
            self._call(self.lock_path)
        except IOError as err:
            self.assertTrue(msg in str(err))
        else:  # pragma: no cover
            self.fail('IOError not raised')

    @mock.patch('certbot.lock.os.stat')
    def test_unexpected_stat_err(self, mock_stat):
        msg = 'hi there'
        mock_stat.side_effect = OSError(msg)
        try:
            self._call(self.lock_path)
        except OSError as err:
            self.assertTrue(msg in str(err))
        else:  # pragma: no cover
            self.fail('OSError not raised')


def lock_and_call(func, lock_path):
    """Grab a lock at lock_path and call func.

    :param callable func: object to call after acquiring the lock
    :param str lock_path: path to the lock file to acquire

    """
    # start child and wait for it to grab the lock
    cv = multiprocessing.Condition()
    cv.acquire()
    child_args = (cv, lock_path,)
    child = multiprocessing.Process(target=hold_lock, args=child_args)
    child.start()
    cv.wait()

    # call func and terminate the child
    func()
    cv.notify()
    cv.release()
    child.join()
    assert child.exitcode == 0


def hold_lock(cv, lock_path):  # pragma: no cover
    """Acquire a file lock at lock_path and wait to release it.

    :param multiprocessing.Condition cv: condition for syncronization
    :param str lock_path: path to the file lock

    """
    from certbot.lock import LockFile
    lock_file = LockFile(lock_path)
    cv.acquire()
    cv.notify()
    cv.wait()
    lock_file.release()


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
