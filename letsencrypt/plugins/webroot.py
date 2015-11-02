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
import shlex

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

    def get_chall_pref(self, domain):  # pragma: no cover
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.SimpleHTTP]

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.default_root = None
        self.domain_roots = {}

    def prepare(self):  # pylint: disable=missing-docstring
        path = self.conf("path")
        if path is None:
            raise errors.PluginError("--{0} must be set".format(
                self.option_name("path")))
        self._parse_path_argument(path)
        if self.default_root:
            self.default_root = self._make_full_root(self.default_root)
        for domain, path in self.domain_roots.items():
            self.domain_roots[domain] = self._make_full_root(path)

    def _parse_path_argument(self, path):
        self.default_root = None
        self.domain_roots = {}
        error = 'argument --{0}: '.format(self.option_name('path'))

        def _split_path(s):
            lex = shlex.shlex(s, posix=True)
            lex.whitespace_split = True
            lex.whitespace += ','
            lex.commenters = ''
            return list(lex)

        def _split_domain_path(s):
            lex = shlex.shlex(s, posix=True)
            lex.whitespace_split = True
            lex.whitespace = ':'
            lex.commenters = ''
            res = list(lex)
            if len(res) == 1:
                return res
            else:
                return (res[0], ':'.join(res[1:]))

        try:
            items = _split_path(path)
        except ValueError as e:
            raise errors.PluginError(error + e.message)

        if not items:
            raise errors.PluginError(error + 'expected one argument')

        for item in items:
            res = _split_domain_path(item)
            if len(res) == 1:
                path = res[0]
                if self.default_root:
                    raise errors.PluginError(error + 'default path already defined')
                self.default_root = path
            else:
                domain, path = res
                if domain in self.domain_roots:
                    raise errors.PluginError(
                        error + 'path for domain {0} already defined'.format(domain))
                self.domain_roots[domain] = path

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
        full_root = self.domain_roots.get(achall.domain, self.default_root)
        if not full_root:
            raise errors.PluginError("Cannot find path for domain: {0}".format(achall.domain))
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
