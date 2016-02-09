"""Webroot plugin."""
import errno
import logging
import os

import zope.interface

from acme import challenges

from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt.plugins import common


logger = logging.getLogger(__name__)


class Authenticator(common.Plugin):
    """Webroot Authenticator."""
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)

    description = "Webroot Authenticator"

    MORE_INFO = """\
Authenticator plugin that performs http-01 challenge by saving
necessary validation resources to appropriate paths on the file
system. It expects that there is some other HTTP server configured
to serve all files under specified web root ({0})."""

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return self.MORE_INFO.format(self.conf("path"))

    @classmethod
    def add_parser_arguments(cls, add):
        # --webroot-path and --webroot-map are added in cli.py because they
        # are parsed in conjunction with --domains
        pass

    def get_chall_pref(self, domain):  # pragma: no cover
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.full_roots = {}

    def prepare(self):  # pylint: disable=missing-docstring
        path_map = self.conf("map")

        if not path_map:
            raise errors.PluginError("--{0} must be set".format(
                self.option_name("path")))
        for name, path in path_map.items():
            if not os.path.isdir(path):
                raise errors.PluginError(path + " does not exist or is not a directory")
            self.full_roots[name] = os.path.join(path, challenges.HTTP01.URI_ROOT_PATH)

            logger.debug("Creating root challenges validation dir at %s",
                         self.full_roots[name])

            # Change the permissions to be writable (GH #1389)
            # Umask is used instead of chmod to ensure the client can also
            # run as non-root (GH #1795)
            old_umask = os.umask(0o022)

            try:
                # This is coupled with the "umask" call above because
                # os.makedirs's "mode" parameter may not always work:
                # https://stackoverflow.com/questions/5231901/permission-problems-when-creating-a-dir-with-os-makedirs-python
                os.makedirs(self.full_roots[name], 0o0755)

                # Set owner as parent directory if possible
                try:
                    stat_path = os.stat(path)
                    os.chown(self.full_roots[name], stat_path.st_uid,
                             stat_path.st_gid)
                except OSError as exception:
                    if exception.errno == errno.EACCES:
                        logger.debug("Insufficient permissions to change owner and uid - ignoring")
                    else:
                        raise errors.PluginError(
                            "Couldn't create root for {0} http-01 "
                            "challenge responses: {1}", name, exception)

            except OSError as exception:
                if exception.errno != errno.EEXIST:
                    raise errors.PluginError(
                        "Couldn't create root for {0} http-01 "
                        "challenge responses: {1}", name, exception)
            finally:
                os.umask(old_umask)

    def perform(self, achalls):  # pylint: disable=missing-docstring
        assert self.full_roots, "Webroot plugin appears to be missing webroot map"
        return [self._perform_single(achall) for achall in achalls]

    def _path_for_achall(self, achall):
        try:
            path = self.full_roots[achall.domain]
        except KeyError:
            raise errors.PluginError("Missing --webroot-path for domain: {0}"
                                     .format(achall.domain))
        if not os.path.exists(path):
            raise errors.PluginError("Mysteriously missing path {0} for domain: {1}"
                                     .format(path, achall.domain))
        return os.path.join(path, achall.chall.encode("token"))

    def _perform_single(self, achall):
        response, validation = achall.response_and_validation()

        path = self._path_for_achall(achall)
        logger.debug("Attempting to save validation to %s", path)

        # Change permissions to be world-readable, owner-writable (GH #1795)
        old_umask = os.umask(0o022)

        try:
            with open(path, "w") as validation_file:
                validation_file.write(validation.encode())
        finally:
            os.umask(old_umask)

        return response

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        for achall in achalls:
            path = self._path_for_achall(achall)
            logger.debug("Removing %s", path)
            os.remove(path)
