"""FTP and SFTP plugin."""

import ftputil
import logging
import os
import pysftp
import shutil
import tempfile
import urlparse

import zope.component
import zope.interface

from acme import challenges

from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt.plugins import common


logger = logging.getLogger(__name__)


class Authenticator(common.Plugin):
    """FTP and SFTP Authenticator.

    This plugin uploads the challenge responses required by the ACME
    protocol to a remote server using FTP or SFTP.

    .. todo:: Support for `~.challenges.TLSSNI01`.

    """
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)
    hidden = True

    description = "Configure an HTTP server using FTP or SFTP"

    # a disclaimer about your current IP being transmitted to Let's
    # Encrypt's servers.
    IP_DISCLAIMER = """\
NOTE: The IP of this machine will be publicly logged as having \
requested this certificate. If you're running letsencrypt in FTP mode \
on a machine that is not your server, please ensure you're okay with that.

Are you OK with your IP being logged?
"""

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.full_roots = {}
        self._cleanup_funcs = []
        self._tmpdir = tempfile.mkdtemp()

    @classmethod
    def add_parser_arguments(cls, add):
        # --webroot-path and --webroot-map are added in cli.py because they
        # are parsed in conjunction with --domains
        add("public-ip-logging-ok", action="store_true",
            help="Automatically allows public IP logging.")

    def prepare(self):  # pylint: disable=missing-docstring
        path_map = self.conf("webroot-map")

        if not path_map:
            raise errors.PluginError("--{0} must be set".format(
                self.option_name("webroot-path")))
        for name, path in path_map.items():
            self.full_roots[name] = os.path.join(
                path, challenges.HTTP01.URI_ROOT_PATH)

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ("This plugin tries to solve http-01 challenges automatically "
                "by copying files using FTP or SFTP to the webroot of a "
                "remote HTTP server.")

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        assert self.full_roots, \
            "FTP plugin appears to be missing FTP webroot map"

        if achalls and not self.conf("public-ip-logging-ok"):
            if not zope.component.getUtility(interfaces.IDisplay).yesno(
                    self.IP_DISCLAIMER, "Yes", "No"):
                raise errors.PluginError("Must agree to IP logging to proceed")

        return [self._perform_single(achall) for achall in achalls]

    def _path_for_achall(self, achall):
        try:
            path = self.full_roots[achall.domain]
        except IndexError:
            raise errors.PluginError(
                "Missing --ftp-webroot-path for domain: {1}".format(
                    achall.domain))
        return os.path.join(path, achall.chall.encode("token"))

    def _perform_single(self, achall):
        path = self._path_for_achall(achall)
        path_parts = self._split_path(path)

        if path_parts.scheme == "sftp":
            return self._perform_single_sftp(achall, path_parts)
        elif path_parts.scheme == "ftp":
            return self._perform_single_ftp(achall, path_parts)
        else:
            raise errors.PluginError(
                "unknown webroot URI scheme: {0.scheme}".format(path_parts)
            )

    def _perform_single_ftp(self, achall, path_parts):
        hostname = path_parts.hostname
        username = path_parts.username
        password = path_parts.password
        path = path_parts.path
        if path[0] == '/':
            path = path[1:]

        response, validation = achall.response_and_validation()

        dirname, filename = os.path.split(path)
        tmpfile = os.path.join(self._tmpdir, filename)
        with open(tmpfile, "w") as fp:
            fp.write(validation.encode())

        with ftputil.FTPHost(hostname, username, password) as ftp:
            ftp.makedirs(dirname)
            ftp.chdir(dirname)
            ftp.upload(tmpfile, filename)

        def cleanup():
            with ftputil.FTPHost(hostname, username, password) as ftp:
                ftp.unlink(path)

        self._register_cleanup_func(cleanup)
        return response

    def _perform_single_sftp(self, achall, path_parts):
        hostname = path_parts.hostname
        username = path_parts.username
        path = path_parts.path
        if path[0] == '/':
            path = path[1:]

        response, validation = achall.response_and_validation()

        dirname, filename = os.path.split(path)
        tmpfile = os.path.join(self._tmpdir, filename)
        with open(tmpfile, "w") as fp:
            fp.write(validation.encode())

        with pysftp.Connection(hostname, username=username) as sftp:
            sftp.makedirs(dirname, mode=022)
            with sftp.cd(dirname):
                sftp.put(tmpfile)

        # TODO: register a cleanup function
        return response

    def _register_cleanup_func(self, func):
        """Registers a new cleanup function to be executed when the
        plugin has finished its job.
        """
        self._cleanup_funcs.append(func)

    def _split_path(self, path):
        parts = urlparse.urlparse(path)
        if not parts.scheme:
            # No scheme was given, assume sftp
            return urlparse.urlparse("sftp://" + path)
        return parts

    def cleanup(self, achalls):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        for func in reversed(self._cleanup_funcs):
            func()
        shutil.rmtree(self._tmpdir)
