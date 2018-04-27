"""Utility functions for use in the Postfix installer."""
import logging
import subprocess

from certbot import errors
from certbot import util as certbot_util
from certbot.plugins import util as plugins_util

from certbot_postfix import constants

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

    def update_dir(self, config_dir):
        """Updates the directory of the configuration files for Postfix.

        :param str config_dir: The path containing the Postfix configuration files.
        """
        self.config_dir = config_dir
        self._set_base_command(config_dir)

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

def _get_formatted_protocols(min_tls_version, delimiter=":"):
    """Enforces the minimum TLS version in a way that Postfix can understand. For instance,
    if the min_tls_version is TLS1.1, then Postfix expects: "!SSLv2:!SSLv3:!TLSv1"

    :param str min_tls_version: SSL/TLS version that we expect to be in ACCEPTABLE_TLS_VERSIONS.
    :param str delimiter: delimiter for the SSL/TLS declarations.
    :rtype str: Protocol declaration, formatted correctly in a Postfix-y way. For instance:
        TLSv1.1 => !SSLv2:!SSLv3:!TLSv1
        TLSv1   => !SSLv2:!SSLv3
    """
    if min_tls_version not in constants.ACCEPTABLE_TLS_VERSIONS:
        return None
    return delimiter.join(["!" + version
        for version in constants.TLS_VERSIONS[0:constants.TLS_VERSIONS.index(min_tls_version)]])

def _get_formatted_policy_for_domain(address_domain, tls_policy):
    """Parses TLS policy specification into a format that Postfix expects. In particular:
        <domain> <tls_security_level> protocols=<protocols>
    For instance, let's say we have an entry for mail.example.com with a minimum TLS version of 1.1:
        mail.example.com encrypt protocols=!SSLv2:!SSLv3:!TLSv1
    :param address_domain str: The domain we're configuring this policy for.
    :param tls_policy dict: TLS policy information.
    :rtype str: Properly formatted Postfix TLS policy specification for this domain.
    """
    mx_list = tls_policy.mxs
    if len(mx_list) == 0:
        matches = ""
    else:
        matches = 'match=' + ':'.join(mx_list)
    entry = address_domain + " secure " + matches
    protocols_value = _get_formatted_protocols(tls_policy.min_tls_version)
    if protocols_value is not None:
        entry += " protocols=" + protocols_value
    else:
        logger.warn('Unknown minimum TLS version: %s', tls_policy.min_tls_version)
    return entry

def write_domainwise_tls_policies(policy, policy_file):
    """Writes domainwise tls policies to policy_file in a format that Postfix
    can parse.
    :param policy: A TLSPolicy object that wraps the STARTTLS Policy List.
    :param str policy_file: The filepath to the Postfix tls_policy file that should be written.
    """
    policy_lines = []
    for address_domain, tls_policy in policy.policies_iter():
        policy_lines.append(_get_formatted_policy_for_domain(address_domain, tls_policy))
    with open(policy_file, "w") as f:
        f.write("\n".join(policy_lines) + "\n")

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
    for override in overrides:
        if acceptable_overrides is None or override not in acceptable_overrides:
            logger.warning("Parameter {0} is overridden as {1} for service {2} in " +
                           "master configuration file!", name, override[1], override[0])

