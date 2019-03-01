"""Tests to ensure the lock order is preserved."""
from __future__ import print_function

import atexit
import datetime
import functools
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.backends import default_backend
# TODO: once mypy has cryptography types bundled, type: ignore can be removed.
# See https://github.com/python/typeshed/tree/master/third_party/2/cryptography
from cryptography.hazmat.primitives import serialization, hashes  # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa

from certbot import lock
from certbot import util

from certbot.tests import util as test_util


logger = logging.getLogger(__name__)


def main():
    """Run the lock tests."""
    dirs, base_cmd = set_up()
    for subcommand in ('certonly', 'install', 'renew', 'run',):
        logger.info('Testing subcommand: %s', subcommand)
        test_command(base_cmd + [subcommand], dirs)
    logger.info('Lock test ran successfully.')


def set_up():
    """Prepare tests to be run.

    Logging is set up and temporary directories are set up to contain a
    basic Certbot and Nginx configuration. The directories are returned
    in the order they should be locked by Certbot. If the Nginx plugin
    is expected to work on the system, the Nginx directory is included,
    otherwise, it is not.

    A Certbot command is also created that uses the temporary
    directories. The returned command can be used to test different
    subcommands by appending the desired command to the end.

    :returns: directories and command
    :rtype: `tuple` of `list`

    """
    logging.basicConfig(format='%(message)s', level=logging.INFO)
    config_dir, logs_dir, work_dir, nginx_dir = set_up_dirs()
    command = set_up_command(config_dir, logs_dir, work_dir, nginx_dir)

    dirs = [logs_dir, config_dir, work_dir]
    # Travis and Circle CI set CI to true so we
    # will always test Nginx's lock during CI
    if os.environ.get('CI') == 'true' or util.exe_exists('nginx'):
        dirs.append(nginx_dir)
    else:
        logger.warning('Skipping Nginx lock tests')

    return dirs, command


def set_up_dirs():
    """Set up directories for tests.

    A temporary directory is created to contain the config, log, work,
    and nginx directories. A sample renewal configuration is created in
    the config directory and a basic Nginx config is placed in the Nginx
    directory. The temporary directory containing all of these
    directories is deleted when the program exits.

    :return value: config, log, work, and nginx directories
    :rtype: `tuple` of `str`

    """
    temp_dir = tempfile.mkdtemp()
    logger.debug('Created temporary directory: %s', temp_dir)
    atexit.register(functools.partial(shutil.rmtree, temp_dir))

    config_dir = os.path.join(temp_dir, 'config')
    logs_dir = os.path.join(temp_dir, 'logs')
    work_dir = os.path.join(temp_dir, 'work')
    nginx_dir = os.path.join(temp_dir, 'nginx')

    for directory in (config_dir, logs_dir, work_dir, nginx_dir,):
        os.mkdir(directory)

    test_util.make_lineage(config_dir, 'sample-renewal.conf')
    set_up_nginx_dir(nginx_dir)

    return config_dir, logs_dir, work_dir, nginx_dir


def set_up_nginx_dir(root_path):
    """Create a basic Nginx configuration in nginx_dir.

    :param str root_path: where the Nginx server root should be placed

    """
    # Get the root of the git repository
    repo_root = check_call('git rev-parse --show-toplevel'.split()).strip()
    conf_script = os.path.join(
        repo_root, 'certbot-nginx', 'tests', 'boulder-integration.conf.sh')
    # Prepare self-signed certificates for Nginx
    key_path, cert_path = setup_certificate(root_path)
    # Generate Nginx configuration
    with open(os.path.join(root_path, 'nginx.conf'), 'w') as f:
        f.write(check_call(['/bin/sh', conf_script, root_path, key_path, cert_path]))


def set_up_command(config_dir, logs_dir, work_dir, nginx_dir):
    """Build the Certbot command to run for testing.

    You can test different subcommands by appending the desired command
    to the returned list.

    :param str config_dir: path to the configuration directory
    :param str logs_dir: path to the logs directory
    :param str work_dir: path to the work directory
    :param str nginx_dir: path to the nginx directory

    :returns: certbot command to execute for testing
    :rtype: `list` of `str`

    """
    return (
        'certbot --cert-path {0} --key-path {1} --config-dir {2} '
        '--logs-dir {3} --work-dir {4} --nginx-server-root {5} --debug '
        '--force-renewal --nginx --verbose '.format(
            test_util.vector_path('cert.pem'),
            test_util.vector_path('rsa512_key.pem'),
            config_dir, logs_dir, work_dir, nginx_dir).split())


def setup_certificate(workspace):
    """Generate a self-signed certificate for nginx.
    :param workspace: path of folder where to put the certificate
    :return: tuple containing the key path and certificate path
    :rtype: `tuple`
    """
    # Generate key
    # See comment on cryptography import about type: ignore
    private_key = rsa.generate_private_key(  # type: ignore
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'nginx.wtf')
    ])
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        1
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).sign(private_key, hashes.SHA256(), default_backend())

    key_path = os.path.join(workspace, 'cert.key')
    with open(key_path, 'wb') as file_handle:
        file_handle.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    cert_path = os.path.join(workspace, 'cert.pem')
    with open(cert_path, 'wb') as file_handle:
        file_handle.write(certificate.public_bytes(serialization.Encoding.PEM))

    return key_path, cert_path


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

    pattern = 'A lock on {0}.* is held by another process'.format(dir_path)
    if not re.search(pattern, err):
        err_msg = 'Directory path {0} not in error output!'.format(dir_path)
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
    logger.critical(err_msg)
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
    if os.name != 'nt':
        main()
    else:
        print(
            'Warning: lock_test cannot be executed on Windows, '
            'as it relies on a Nginx distribution for Linux.')
