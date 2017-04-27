"""Tests to ensure the lock order is preserved."""
import contextlib
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile

from certbot import lock

from certbot.tests import util as test_util


logger = logging.getLogger(__name__)


def main():
    """Run the lock tests."""
    logging.basicConfig(format='%(message)s', level=logging.INFO)
    with temporary_dir() as temp_dir:
        subdirs = create_subdirs(temp_dir)
        base_cmd = set_up_certbot_cmd(subdirs)
        for subcommand in ('certonly', 'install', 'run'):
            cmd = base_cmd + [subcommand]
            logger.info('Testing command: %s', ' '.join(cmd))
            test_command(cmd, subdirs)
    logger.info('Lock test ran successfully.')


@contextlib.contextmanager
def temporary_dir():
    """Context manager for creating and destroying a temp directory."""
    temp_dir = tempfile.mkdtemp()
    logger.debug('Created temporary directory: %s', temp_dir)
    yield temp_dir
    shutil.rmtree(temp_dir)


def create_subdirs(parent_dir):
    """Creates four subdirectories for Certbot and the chosen plugin.

    These directories are created under parent_dir.

    :param str parent_dir: path to create directories in

    :returns: paths to four directories created under paren_dir
    :rtype: `list` of `str`

    """
    created = []
    for name in ('foo', 'bar', 'baz', 'qux',):
        full_path = os.path.join(parent_dir, name)
        os.mkdir(full_path)
        created.append(full_path)
    return created


def set_up_certbot_cmd(dirs):
    """Build the Certbot command to run for testing.

    The directory paths in dirs are used in the order that locks are
    acquired. If you run the returned command when all locks are held,
    Certbot should error trying to acquire the first directory in dirs.
    If you release the lock on that directory, it should then error
    trying to acquire the lock on the second directory. This continues
    until all directories in dirs has been used. If dirs contains too
    many or too few directories, this function raises an error.

    The resulting command is set up so Nginx can be used and a basic
    Nginx configuration is placed in that directory by this function.

    :param iterable dirs: directories to be used

    :returns: certbot command to execute for testing
    :rtype: `list` of `str`

    """
    assert len(dirs) == 4, 'Unexpected number of directories!'
    logs_dir, config_dir, work_dir, nginx_dir = dirs
    set_up_nginx_dir(nginx_dir)
    cmd = 'certbot --cert-path {0} '.format(test_util.vector_path('cert.pem'))
    cmd += '--key-path {0} '.format(test_util.vector_path('rsa512_key.pem'))
    cmd += '--logs-dir {0} --config-dir {1} '.format(logs_dir, config_dir)
    cmd += '--work-dir {} '.format(work_dir)
    cmd += '--nginx-server-root {} '.format(nginx_dir)
    cmd += '--debug --nginx --verbose '
    return cmd.split()


def set_up_nginx_dir(root_path):
    """Create a basic Nginx configuration in nginx_dir.

    :param str root_path: where the Nginx server root should be placed

    """
    # Get the root of the git repository
    repo_root = check_call('git rev-parse --show-toplevel'.split()).strip()
    conf_script = os.path.join(
        repo_root, 'certbot-nginx', 'tests', 'boulder-integration.conf.sh')
    os.environ['root'] = root_path
    with open(os.path.join(root_path, 'nginx.conf'), 'w') as f:
        f.write(check_call(['/bin/sh', conf_script]))
    del os.environ['root']


def test_command(command, directories):
    """Assert Certbot acquires locks in a specific order.

    command is run repeatedly testing that Certbot acquires locks on
    directories in the order they appear in the parameter directories.

    :param list command: Certbot command to execute
    :param list directories: list of directories Certbot should fail
        to acquire the lock on in sorted order

    """
    locks = [lock.lock_dir(directory) for directory in directories]
    for dir_path, dir_lock in zip(directories, locks):
        check_error(command, dir_path)
        dir_lock.release()


def check_error(command, dir_path):
    """Run command and verify it fails to acquire the lock for dir_path.

    :param str command: certbot command to run
    :param str dir_path: path to directory containing the lock Certbot
        should fail on

    """
    ret, out, err = subprocess_call(command)
    if ret == 0:
        report_failure("Certbot didn't exit with a nonzero status!", out, err)

    match = re.search("Please see the logfile '(.*)' for more details", err)
    if match is not None:
        # Get error output from more verbose logfile
        with open(match.group(1)) as f:
            err = f.read()

    pattern = 'A lock on {}.* is held by another process'.format(dir_path)
    if not re.search(pattern, err):
        err_msg = 'Directory path {} not error output!'.format(dir_path)
        report_failure(err_msg, out, err)


def check_call(args):
    """Simple imitation of subprocess.check_call.

    This function is only available in subprocess in Python 2.7+.

    :param list args: program and it's arguments to be run

    :returns: stdout output
    :rtype: str

    """
    exit_code, out, err = subprocess_call(args)
    if exit_code:
        report_failure('Command exited with a nonzero status!', out, err)
    return out


def report_failure(err_msg, out, err):
    """Report a subprocess failure and exit.

    :param str err_msg: error message to report
    :param str out: stdout output
    :param str err: stderr output

    """
    logger.fatal(err_msg)
    log_output(logging.INFO, out, err)
    sys.exit(err_msg)


def subprocess_call(args):
    """Run a command with subprocess and return the result.

    :param list args: program and it's arguments to be run

    :returns: return code, stdout output, stderr output
    :rtype: tuple

    """
    process = subprocess.Popen(args, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, universal_newlines=True)
    out, err = process.communicate()
    logger.debug('Return code was %d', process.returncode)
    log_output(logging.DEBUG, out, err)
    return process.returncode, out, err


def log_output(level, out, err):
    """Logs stdout and stderr output at the requested level.

    :param int level: logging level to use
    :param str out: stdout output
    :param str err: stderr output

    """
    if out:
        logger.log(level, 'Stdout output was:\n%s', out)
    if err:
        logger.log(level, 'Stderr output was:\n%s', err)


if __name__ == "__main__":
    main()
