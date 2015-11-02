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
Authenticator plugin that performs SimpleHTTP challenge by saving
necessary validation resources to appropriate paths on the file
system. It expects that there is some other HTTP server configured
to serve all files under specified web root ({0})."""

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return self.MORE_INFO.format(self.conf("path"))

    @classmethod
    def add_parser_arguments(cls, add):
        add("path", help="public_html / webroot path")
        add("domain-path", help="domain:public_html / webroot path", action="append")

    def get_chall_pref(self, domain):  # pragma: no cover
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.SimpleHTTP]

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.full_root = None
        self.domain_roots = {}

    def prepare(self):  # pylint: disable=missing-docstring
        path = self.conf("path")
        domain_paths = self.conf("domain-path")
        if path is None:
            if not domain_paths:
                raise errors.PluginError("--{0} or --{1} must be set".format(
                    self.option_name("path"), self.option_name("domain-path")))
            else:
                for s in domain_paths:
                    items = filter(None, s.split(':', 2))
                    if len(items) != 2:
                        raise errors.PluginError(
                            "--{0} '{1}' incorrect value, must be domain:path".format(
                                self.option_name("domain-path"), s))
                    (domain, _path) = items
                    self.domain_roots[domain] = _path

        if path:
            self.full_root = self._make_full_root(path)
        else:
            for domain, path in self.domain_roots.items():
                self.domain_roots[domain] = self._make_full_root(path)

    def _make_full_root(self, path):
        if not os.path.isdir(path):
            raise errors.PluginError(
                path + " does not exist or is not a directory")
        full_root = os.path.join(
            path, challenges.SimpleHTTPResponse.URI_ROOT_PATH)

        logger.debug("Creating root challenges validation dir at %s",
                     full_root)
        try:
            os.makedirs(full_root)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise errors.PluginError(
                    "Couldn't create root for SimpleHTTP "
                    "challenge responses: {0}", exception)

        return full_root

    def perform(self, achalls):  # pylint: disable=missing-docstring
        return [self._perform_single(achall) for achall in achalls]

    def _path_for_achall(self, achall):
        full_root = self.full_root
        if not full_root:
            if achall.domain not in self.domain_roots:
                raise errors.PluginError(
                    "Cannot find path for domain: {0}".format(achall.domain))
            full_root = self.domain_roots[achall.domain]
        return os.path.join(full_root, achall.chall.encode("token"))

    def _perform_single(self, achall):
        response, validation = achall.gen_response_and_validation(tls=False)
        path = self._path_for_achall(achall)
        logger.debug("Attempting to save validation to %s", path)
        with open(path, "w") as validation_file:
            validation_file.write(validation.json_dumps())
        return response

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        for achall in achalls:
            path = self._path_for_achall(achall)
            logger.debug("Removing %s", path)
            os.remove(path)
