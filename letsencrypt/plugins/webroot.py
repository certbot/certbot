"""Webroot plugin.

Content-Type
------------

This plugin requires your webserver to use a specific `Content-Type`
header in the HTTP response.

Apache2
~~~~~~~

.. note:: Instructions written and tested for Debian Jessie. Other
   operating systems might use something very similar, but you might
   still need to readjust some commands.

Create ``/etc/apache2/conf-available/letsencrypt-simplehttp.conf``, with
the following contents::

  <IfModule mod_headers.c>
    <LocationMatch "/.well-known/acme-challenge/*">
      Header set Content-Type "application/jose+json"
    </LocationMatch>
  </IfModule>

and then run ``a2enmod headers; a2enconf letsencrypt``; depending on the
output you will have to either ``service apache2 restart`` or ``service
apache2 reload``.

nginx
~~~~~

Use the following snippet in your ``server{...}`` stanza::

  location ~ /.well-known/acme-challenge/(.*) {
    default_type application/jose+json;
  }

and reload your daemon.

"""
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
        add("path", help="public_html / webroot path")

    def get_chall_pref(self, domain):  # pragma: no cover
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.full_root = None

    def prepare(self):  # pylint: disable=missing-docstring
        path = self.conf("path")
        if path is None:
            raise errors.PluginError("--{0} must be set".format(
                self.option_name("path")))
        if not os.path.isdir(path):
            raise errors.PluginError(
                path + " does not exist or is not a directory")
        self.full_root = os.path.join(path, challenges.HTTP01.URI_ROOT_PATH)

        logger.debug("Creating root challenges validation dir at %s",
                     self.full_root)
        try:
            os.makedirs(self.full_root)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise errors.PluginError(
                    "Couldn't create root for http-01 "
                    "challenge responses: {0}", exception)

    def perform(self, achalls):  # pylint: disable=missing-docstring
        assert self.full_root is not None
        return [self._perform_single(achall) for achall in achalls]

    def _path_for_achall(self, achall):
        return os.path.join(self.full_root, achall.chall.encode("token"))

    def _perform_single(self, achall):
        response, validation = achall.response_and_validation()
        path = self._path_for_achall(achall)
        logger.debug("Attempting to save validation to %s", path)
        with open(path, "w") as validation_file:
            validation_file.write(validation.encode())
        return response

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        for achall in achalls:
            path = self._path_for_achall(achall)
            logger.debug("Removing %s", path)
            os.remove(path)
