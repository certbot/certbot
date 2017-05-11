"""Webroot plugin."""
import argparse
import collections
import errno
import json
import logging
import os

import six
import zope.component
import zope.interface

from acme import challenges

from certbot import cli
from certbot import errors
from certbot import interfaces
from certbot.display import util as display_util
from certbot.display import ops
from certbot.plugins import common


logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """Webroot Authenticator."""

    description = "Place files in webroot directory"

    MORE_INFO = """\
Authenticator plugin that performs http-01 challenge by saving
necessary validation resources to appropriate paths on the file
system. It expects that there is some other HTTP server configured
to serve all files under specified web root ({0})."""

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return self.MORE_INFO.format(self.conf("path"))

    @classmethod
    def add_parser_arguments(cls, add):
        add("path", "-w", default=[], action=_WebrootPathAction,
            help="public_html / webroot path. This can be specified multiple "
                 "times to handle different domains; each domain will have "
                 "the webroot path that preceded it.  For instance: `-w "
                 "/var/www/example -d example.com -d www.example.com -w "
                 "/var/www/thing -d thing.net -d m.thing.net` (default: Ask)")
        add("map", default={}, action=_WebrootMapAction,
            help="JSON dictionary mapping domains to webroot paths; this "
                 "implies -d for each entry. You may need to escape this from "
                 "your shell. E.g.: --webroot-map "
                 '\'{"eg1.is,m.eg1.is":"/www/eg1/", "eg2.is":"/www/eg2"}\' '
                 "This option is merged with, but takes precedence over, -w / "
                 "-d entries. At present, if you put webroot-map in a config "
                 "file, it needs to be on a single line, like: webroot-map = "
                 '{"example.com":"/var/www"}.')

    def get_chall_pref(self, domain):  # pragma: no cover
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.full_roots = {}
        self.performed = collections.defaultdict(set)

    def prepare(self):  # pylint: disable=missing-docstring
        pass

    def perform(self, achalls):  # pylint: disable=missing-docstring
        self._set_webroots(achalls)

        self._create_challenge_dirs()

        return [self._perform_single(achall) for achall in achalls]

    def _set_webroots(self, achalls):
        if self.conf("path"):
            webroot_path = self.conf("path")[-1]
            logger.info("Using the webroot path %s for all unmatched domains.",
                        webroot_path)
            for achall in achalls:
                self.conf("map").setdefault(achall.domain, webroot_path)
        else:
            known_webroots = list(set(six.itervalues(self.conf("map"))))
            for achall in achalls:
                if achall.domain not in self.conf("map"):
                    new_webroot = self._prompt_for_webroot(achall.domain,
                                                           known_webroots)
                    # Put the most recently input
                    # webroot first for easy selection
                    try:
                        known_webroots.remove(new_webroot)
                    except ValueError:
                        pass
                    known_webroots.insert(0, new_webroot)
                    self.conf("map")[achall.domain] = new_webroot

    def _prompt_for_webroot(self, domain, known_webroots):
        webroot = None

        while webroot is None:
            webroot = self._prompt_with_webroot_list(domain, known_webroots)

            if webroot is None:
                webroot = self._prompt_for_new_webroot(domain)

        return webroot

    def _prompt_with_webroot_list(self, domain, known_webroots):
        display = zope.component.getUtility(interfaces.IDisplay)
        path_flag = "--" + self.option_name("path")

        while True:
            code, index = display.menu(
                "Select the webroot for {0}:".format(domain),
                ["Enter a new webroot"] + known_webroots,
                help_label="Help", cli_flag=path_flag, force_interactive=True)
            if code == display_util.CANCEL:
                raise errors.PluginError(
                    "Every requested domain must have a "
                    "webroot when using the webroot plugin.")
            elif code == display_util.HELP:
                display.notification(
                    "To use the webroot plugin, you need to have an "
                    "HTTP server running on this system serving files "
                    "for the requested domain. Additionally, this "
                    "server should be serving all files contained in a "
                    "public_html or webroot directory. The webroot "
                    "plugin works by temporarily saving necessary "
                    "resources in the HTTP server's webroot directory "
                    "to pass domain validation challenges.",
                    force_interactive=True)
            else:  # code == display_util.OK
                return None if index == 0 else known_webroots[index - 1]

    def _prompt_for_new_webroot(self, domain):
        code, webroot = ops.validated_directory(
            _validate_webroot,
            "Input the webroot for {0}:".format(domain),
            force_interactive=True)
        if code == display_util.HELP:
            # Displaying help is not currently implemented
            return None
        elif code == display_util.CANCEL or code == display_util.ESC:
            return None
        else:  # code == display_util.OK
            return _validate_webroot(webroot)

    def _create_challenge_dirs(self):
        path_map = self.conf("map")
        if not path_map:
            raise errors.PluginError(
                "Missing parts of webroot configuration; please set either "
                "--webroot-path and --domains, or --webroot-map. Run with "
                " --help webroot for examples.")
        for name, path in path_map.items():
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
                    logger.info("Unable to change owner and uid of webroot directory")
                    logger.debug("Error was: %s", exception)

            except OSError as exception:
                if exception.errno != errno.EEXIST:
                    raise errors.PluginError(
                        "Couldn't create root for {0} http-01 "
                        "challenge responses: {1}", name, exception)
            finally:
                os.umask(old_umask)

    def _get_validation_path(self, root_path, achall):
        return os.path.join(root_path, achall.chall.encode("token"))

    def _perform_single(self, achall):
        response, validation = achall.response_and_validation()

        root_path = self.full_roots[achall.domain]
        validation_path = self._get_validation_path(root_path, achall)
        logger.debug("Attempting to save validation to %s", validation_path)

        # Change permissions to be world-readable, owner-writable (GH #1795)
        old_umask = os.umask(0o022)

        try:
            with open(validation_path, "wb") as validation_file:
                validation_file.write(validation.encode())
        finally:
            os.umask(old_umask)

        self.performed[root_path].add(achall)

        return response

    def cleanup(self, achalls):  # pylint: disable=missing-docstring
        for achall in achalls:
            root_path = self.full_roots.get(achall.domain, None)
            if root_path is not None:
                validation_path = self._get_validation_path(root_path, achall)
                logger.debug("Removing %s", validation_path)
                os.remove(validation_path)
                self.performed[root_path].remove(achall)

        for root_path, achalls in six.iteritems(self.performed):
            if not achalls:
                try:
                    os.rmdir(root_path)
                    logger.debug("All challenges cleaned up, removing %s",
                                 root_path)
                except OSError as exc:
                    logger.info(
                        "Unable to clean up challenge directory %s", root_path)
                    logger.debug("Error was: %s", exc)


class _WebrootMapAction(argparse.Action):
    """Action class for parsing webroot_map."""

    def __call__(self, parser, namespace, webroot_map, option_string=None):
        for domains, webroot_path in six.iteritems(json.loads(webroot_map)):
            webroot_path = _validate_webroot(webroot_path)
            namespace.webroot_map.update(
                (d, webroot_path) for d in cli.add_domains(namespace, domains))


class _WebrootPathAction(argparse.Action):
    """Action class for parsing webroot_path."""

    def __init__(self, *args, **kwargs):
        super(_WebrootPathAction, self).__init__(*args, **kwargs)
        self._domain_before_webroot = False

    def __call__(self, parser, namespace, webroot_path, option_string=None):
        if self._domain_before_webroot:
            raise errors.PluginError(
                "If you specify multiple webroot paths, "
                "one of them must precede all domain flags")

        if namespace.webroot_path:
            # Apply previous webroot to all matched
            # domains before setting the new webroot path
            prev_webroot = namespace.webroot_path[-1]
            for domain in namespace.domains:
                namespace.webroot_map.setdefault(domain, prev_webroot)
        elif namespace.domains:
            self._domain_before_webroot = True

        namespace.webroot_path.append(_validate_webroot(webroot_path))


def _validate_webroot(webroot_path):
    """Validates and returns the absolute path of webroot_path.

    :param str webroot_path: path to the webroot directory

    :returns: absolute path of webroot_path
    :rtype: str

    """
    if not os.path.isdir(webroot_path):
        raise errors.PluginError(webroot_path + " does not exist or is not a directory")

    return os.path.abspath(webroot_path)
