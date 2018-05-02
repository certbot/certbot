"""Utility functions for use in the Postfix installer."""
import logging
import subprocess

from certbot import errors
from certbot import util as certbot_util
from certbot.plugins import util as plugins_util

logger = logging.getLogger(__name__)

COMMAND = "postfix"

class PostfixUtilBase(object):
    """A base class for wrapping Postfix command line utilities."""

    def __init__(self, executable, config_dir=None):
        """Sets up the Postfix utility class.

        :param str executable: name or path of the Postfix utility
        :param str config_dir: path to an alternative Postfix config

        :raises .NoInstallationError: when the executable isn't found

        """
        self.executable = executable
        verify_exe_exists(executable)
        self._set_base_command(config_dir)
        self.config_dir = None

    def _set_base_command(self, config_dir):
        self._base_command = [self.executable]
        if config_dir is not None:
            self._base_command.extend(('-c', config_dir,))

    def _call(self, extra_args=None):
        """Runs the Postfix utility and returns the result.

        :param list extra_args: additional arguments for the command

        :returns: data written to stdout and stderr
        :rtype: `tuple` of `str`

        :raises subprocess.CalledProcessError: if the command fails

        """
        args = list(self._base_command)
        if extra_args is not None:
            args.extend(extra_args)
        return check_all_output(args)

    def _get_output(self, extra_args=None):
        """Runs the Postfix utility and returns only stdout output.

        This function relies on self._call for running the utility.

        :param list extra_args: additional arguments for the command

        :returns: data written to stdout
        :rtype: str

        :raises subprocess.CalledProcessError: if the command fails

        """
        return self._call(extra_args)[0]

class PostfixUtil(PostfixUtilBase):
    """Wrapper around Postfix CLI tool.
    """

    def __init__(self, config_dir=None):
        super(PostfixUtil, self).__init__(COMMAND, config_dir)

    def test(self):
        """Make sure the configuration is valid.

        :raises .MisconfigurationError: if the config is invalid
        """
        try:
            self._call(["check"])
        except subprocess.CalledProcessError as e:
            logger.debug("Could not check postfix configuration:\n%s",
                         e)
            raise errors.MisconfigurationError(
                "Postfix failed internal configuration check.")

    def restart(self):
        """Restart or refresh the server content.

        :raises .PluginError: when server cannot be restarted

        """
        logger.info("Reloading Postfix configuration...")
        if self._is_running():
            self._reload()
        else:
            self._start()


    def _is_running(self):
        """Is Postfix currently running?

        Uses the 'postfix status' command to determine if Postfix is
        currently running using the specified configuration files.

        :returns: True if Postfix is running, otherwise, False
        :rtype: bool

        """
        try:
            self._call(["status"])
        except subprocess.CalledProcessError:
            return False
        return True

    def _start(self):
        """Instructions Postfix to start running.

        :raises .PluginError: when Postfix cannot start

        """
        try:
            self._call(["start"])
        except subprocess.CalledProcessError:
            raise errors.PluginError("Postfix failed to start")

    def _reload(self):
        """Instructs Postfix to reload its configuration.

        If Postfix isn't currently running, this method will fail.

        :raises .PluginError: when Postfix cannot reload
        """
        try:
            self._call(["reload"])
        except subprocess.CalledProcessError:
            raise errors.PluginError(
                "Postfix failed to reload its configuration")

def check_all_output(*args, **kwargs):
    """A version of subprocess.check_output that also captures stderr.

    This is the same as :func:`subprocess.check_output` except output
    written to stderr is also captured and returned to the caller. The
    return value is a tuple of two strings (rather than byte strings).
    To accomplish this, the caller cannot set the stdout, stderr, or
    universal_newlines parameters to :class:`subprocess.Popen`.

    Additionally, if the command exits with a nonzero status, output is
    not included in the raised :class:`subprocess.CalledProcessError`
    because Python 2.6 does not support this. Instead, the failure
    including the output is logged.

    :param tuple args: positional arguments for Popen
    :param dict kwargs: keyword arguments for Popen

    :returns: data written to stdout and stderr
    :rtype: `tuple` of `str`

    :raises ValueError: if arguments are invalid
    :raises subprocess.CalledProcessError: if the command fails

    """
    for keyword in ('stdout', 'stderr', 'universal_newlines',):
        if keyword in kwargs:
            raise ValueError(
                keyword + ' argument not allowed, it will be overridden.')

    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.PIPE
    kwargs['universal_newlines'] = True

    process = subprocess.Popen(*args, **kwargs)
    output, err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get('args')
        if cmd is None:
            cmd = args[0]
        logger.debug(
            "'%s' exited with %d. stdout output was:\n%s\nstderr output was:\n%s",
            cmd, retcode, output, err)
        raise subprocess.CalledProcessError(retcode, cmd)
    return (output, err)


def verify_exe_exists(exe, message=None):
    """Ensures an executable with the given name is available.

    If an executable isn't found for the given path or name, extra
    directories are added to the user's PATH to help find system
    utilities that may not be available in the default cron PATH.

    :param str exe: executable path or name
    :param str message: Error message to print.

    :raises .NoInstallationError: when the executable isn't found

    """
    if message is None:
        message = "Cannot find executable '{0}'.".format(exe)
    if not (certbot_util.exe_exists(exe) or plugins_util.path_surgery(exe)):
        raise errors.NoInstallationError(message)

def report_master_overrides(name, overrides, acceptable_overrides=None):
    """If the value for a parameter |name| is overridden by other services,
    report a warning to notify the user.

    :param str name: The name of the parameter that is being overridden.
    :param list overrides: The values that other services are setting for |name|.
        Each override is a tuple: (service name, value)
    :param list acceptable_overrides: Override values that are acceptable. For instance, if
        another service is overriding our parameter with a more secure option, we don't have
        to warn. If this is set to None, warnings are reported for *all* overrides!
    """
    error_string = ""
    for override in overrides:
        service, value = override
        # If this override is acceptable:
        if acceptable_overrides is not None and \
            is_acceptable_value(name, value, acceptable_overrides):
            continue
        error_string += "  {1}: {2}\n".format(service, value)
    if len(error_string) > 0:
        raise errors.PluginError("{0} is overridden with less secure options by the "
             "following services in master.cf:\n" + error_string)

def is_acceptable_value(parameter, value, acceptable):
    """ Returns whether the `value` for this `parameter` is acceptable,
    given a string or tuple `acceptable`
    """
    # If it's a tuple, there's multiple acceptable options.
    # Only set a param if it's not acceptable.
    if isinstance(acceptable, tuple):
        if value not in acceptable:
            return False
    # Check if param value is a comma-separated list of protocols.
    elif 'protocols' in parameter:
        return _has_acceptable_tls_versions(value)
    # Otherwise, just check whether the value is equal to acceptable.
    return value == acceptable

def _has_acceptable_tls_versions(parameter_string):
    """
    Checks to see if the comma-separated list of TLS protocols to exclude is acceptable.
    Sample string: "!SSLv2, !SSLv3"
    """
    for bad_version in ("SSLv2", "SSLv3"): # TODO: subtract acceptable from tls-verions constant
        if "!" + bad_version not in parameter_string:
            return False
    return True

