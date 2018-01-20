"""Zimbra Installer"""
import logging
import os
import shutil
import subprocess

import pwd

import zope.interface

from certbot import errors
from certbot import interfaces
from certbot import util

from certbot.plugins import common

logger = logging.getLogger(__name__)

@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class ZimbraInstaller(common.Installer):
    """Zimbra installer
    """

    description = "Zimbra Mail Server plugin - Alpha"

    def __init__(self, *args, **kwargs):
        super(ZimbraInstaller, self).__init__(*args, **kwargs)

        self._zimbra_temp_path = None
        self._zimbra_temp_crt = None
        self._zimbra_temp_key = None
        self._zimbra_temp_ca = None

        self._zimbra_cert_path = None
        self._zimbra_cert_crt = None
        self._zimbra_cert_key = None
        self._zimbra_cert_ca = None

        self._zimbra_user = None
        self._deploy_cert = None

    @classmethod
    def add_parser_arguments(cls, add):
        add("zimbra-root", default="/opt/zimbra",
            help="Zimbra root directory.")

    def prepare(self):  # type: ignore
        """Prepare the plugin.

        Finish up any additional initialization.

        :raises .PluginError:
            when full initialization cannot be completed.
        :raises .MisconfigurationError:
            when full initialization cannot be completed. Plugin will
            be displayed on a list of available plugins.
        :raises .NoInstallationError:
            when the necessary programs/files cannot be located. Plugin
            will NOT be displayed on a list of available plugins.
        :raises .NotSupportedError:
            when the installation is recognized, but the version is not
            currently supported.

        """
        if not util.exe_exists("{0}/bin/zmcontrol".format(self.conf('zimbra-root'))):
            raise errors.NoInstallationError

        # Prevent two Zimbra plugins from modifying a config at once
        try:
            util.lock_dir_until_exit(self.conf('zimbra-root'))
        except (OSError, errors.LockError):
            logger.debug('Encountered error:', exc_info=True)
            raise errors.PluginError(
                'Unable to lock %s', self.conf('zimbra-root'))

        self._zimbra_temp_path = os.path.join(self.conf('zimbra-root'), 'certbot-tmp')
        self._zimbra_temp_crt = os.path.join(self._zimbra_temp_path, 'commercial.crt')
        self._zimbra_temp_key = os.path.join(self._zimbra_temp_path, 'commercial.key')
        self._zimbra_temp_ca = os.path.join(self._zimbra_temp_path, 'commercial_ca.crt')

        self._zimbra_cert_path = os.path.join(self.conf('zimbra-root'), 'ssl/zimbra/commercial')
        self._zimbra_cert_crt = os.path.join(self._zimbra_cert_path, 'commercial.crt')
        self._zimbra_cert_key = os.path.join(self._zimbra_cert_path, 'commercial.key')
        self._zimbra_cert_ca = os.path.join(self._zimbra_cert_path, 'commercial_ca.crt')

        try:
            self._zimbra_user = pwd.getpwnam('zimbra')
        except KeyError:
            raise errors.PluginError("Zimbra user not found")

        self._exec_zimbra(['bin/zmcontrol', '-v'])

    def more_info(self):  # type: ignore
        """Human-readable string to help the user.

        Should describe the steps taken and any relevant info to help the user
        decide which plugin to use.

        :rtype str:

        """
        return ""

    def get_all_names(self):
        """Returns all names that may be authenticated.

        :rtype: `collections.Iterable` of `str`

        """
        return []

    #pylint: disable=unused-argument
    def deploy_cert(self, domain, cert_path, key_path, chain_path, fullchain_path):
        """Deploy certificate.

        :param str domain: domain to deploy certificate file
        :param str cert_path: absolute path to the certificate file
        :param str key_path: absolute path to the private key file
        :param str chain_path: absolute path to the certificate chain file
        :param str fullchain_path: absolute path to the certificate fullchain
            file (cert plus chain)

        :raises .PluginError: when cert cannot be deployed

        """

        self._deploy_cert = {
            'cert_path': cert_path,
            'key_path': key_path,
            'chain_path': chain_path,
            'fullchain_path': fullchain_path
        }

    def supported_enhancements(self):  # type: ignore
        """Returns a `collections.Iterable` of supported enhancements.

        :returns: supported enhancements which should be a subset of
            :const:`~certbot.constants.ENHANCEMENTS`
        :rtype: :class:`collections.Iterable` of :class:`str`

        """
        return []

    #pylint: disable=unused-argument
    def enhance(self, domain, enhancement, options=None):
        """Perform a configuration enhancement.

        :param str domain: domain for which to provide enhancement
        :param str enhancement: An enhancement as defined in
            :const:`~certbot.constants.ENHANCEMENTS`
        :param options: Flexible options parameter for enhancement.
            Check documentation of
            :const:`~certbot.constants.ENHANCEMENTS`
            for expected options for each enhancement.

        :raises .PluginError: If Enhancement is not supported, or if
            an error occurs during the enhancement.

        """
        raise errors.PluginError(
                "Unsupported enhancement: {0}".format(enhancement))

    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.

        Both title and temporary are needed because a save may be
        intended to be permanent, but the save is not ready to be a full
        checkpoint.

        It is assumed that at most one checkpoint is finalized by this
        method. Additionally, if an exception is raised, it is assumed a
        new checkpoint was not finalized.

        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory. `title` has no effect if temporary is true.

        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (challenges)

        :raises .PluginError: when save is unsuccessful

        """
        save_files = [self._zimbra_cert_crt, self._zimbra_cert_key, self._zimbra_cert_ca]
        self.add_to_checkpoint(save_files, "", temporary)

        # Copy the certificate and deploy
        if os.path.isdir(self._zimbra_temp_path):
            shutil.rmtree(self._zimbra_temp_path)

        util.make_or_verify_dir(self._zimbra_temp_path, mode=0o755, uid=self._zimbra_user.pw_uid)
        shutil.copyfile(self._deploy_cert['cert_path'], self._zimbra_temp_crt)
        shutil.copyfile(self._deploy_cert['key_path'], self._zimbra_temp_key)
        shutil.copyfile(self._deploy_cert['chain_path'], self._zimbra_temp_ca)
        os.chown(self._zimbra_temp_crt, self._zimbra_user.pw_uid, self._zimbra_user.pw_gid)
        os.chown(self._zimbra_temp_key, self._zimbra_user.pw_uid, self._zimbra_user.pw_gid)
        os.chown(self._zimbra_temp_ca, self._zimbra_user.pw_uid, self._zimbra_user.pw_gid)

        if os.path.isfile(self._zimbra_cert_crt):
            os.remove(self._zimbra_cert_crt)
        if os.path.isfile(self._zimbra_cert_key):
            os.remove(self._zimbra_cert_key)
        if os.path.isfile(self._zimbra_cert_ca):
            os.remove(self._zimbra_cert_ca)

        shutil.copyfile(self._deploy_cert['cert_path'], self._zimbra_cert_crt)
        shutil.copyfile(self._deploy_cert['key_path'], self._zimbra_cert_key)
        shutil.copyfile(self._deploy_cert['chain_path'], self._zimbra_cert_ca)
        os.chown(self._zimbra_cert_crt, self._zimbra_user.pw_uid, self._zimbra_user.pw_gid)
        os.chown(self._zimbra_cert_key, self._zimbra_user.pw_uid, self._zimbra_user.pw_gid)
        os.chown(self._zimbra_cert_ca, self._zimbra_user.pw_uid, self._zimbra_user.pw_gid)

        self._exec_zimbra(['bin/zmcertmgr', 'deploycrt', 'comm',
            self._zimbra_temp_crt, self._zimbra_temp_ca])

        shutil.rmtree(self._zimbra_temp_path)

        if title and not temporary:
            self.finalize_checkpoint(title)

    def rollback_checkpoints(self, rollback=1):
        """Revert `rollback` number of configuration checkpoints.

        :raises .PluginError: when configuration cannot be fully reverted

        """
        super(ZimbraInstaller, self).rollback_checkpoints(rollback)

    def recovery_routine(self):  # type: ignore
        """Revert configuration to most recent finalized checkpoint.

        Remove all changes (temporary and permanent) that have not been
        finalized. This is useful to protect against crashes and other
        execution interruptions.

        :raises .errors.PluginError: If unable to recover the configuration

        """
        super(ZimbraInstaller, self).recovery_routine()

    def config_test(self):  # type: ignore
        """Make sure the configuration is valid.

        :raises .MisconfigurationError: when the config is not in a usable state

        """
        pass

    def restart(self):  # type: ignore
        """Restart or refresh the server content.

        :raises .PluginError: when server cannot be restarted

        """
        self._exec_zimbra(['bin/zmcontrol', 'restart'])

    def _exec_zimbra(self, args):
        """Execute a command with the zimbra user and home directory

        :param list args: command and arguments
        """
        def subprocess_preexec():
            """Set the user and group id before executing command
            """
            os.setgid(self._zimbra_user.pw_gid)
            os.setuid(self._zimbra_user.pw_uid)

        child = subprocess.Popen(args, preexec_fn=subprocess_preexec,
            cwd=self.conf('zimbra-root'), stdout=subprocess.PIPE)
        child.wait()

