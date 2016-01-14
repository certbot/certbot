#!/usr/bin/env python
"""peep ("prudently examine every package") verifies that packages conform to a
trusted, locally stored hash and only then installs them::

    peep install -r requirements.txt

This makes your deployments verifiably repeatable without having to maintain a
local PyPI mirror or use a vendor lib. Just update the version numbers and
hashes in requirements.txt, and you're all set.

"""
# This is here so embedded copies of peep.py are MIT-compliant:
# Copyright (c) 2013 Erik Rose
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
from __future__ import print_function
try:
    xrange = xrange
except NameError:
    xrange = range
from base64 import urlsafe_b64encode, urlsafe_b64decode
from binascii import hexlify
import cgi
from collections import defaultdict
from functools import wraps
from hashlib import sha256
from itertools import chain, islice
import mimetypes
from optparse import OptionParser
from os.path import join, basename, splitext, isdir
from pickle import dumps, loads
import re
import sys
from shutil import rmtree, copy
from sys import argv, exit
from tempfile import mkdtemp
import traceback
try:
    from urllib2 import build_opener, HTTPHandler, HTTPSHandler, HTTPError
except ImportError:
    from urllib.request import build_opener, HTTPHandler, HTTPSHandler
    from urllib.error import HTTPError
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse  # 3.4
# TODO: Probably use six to make urllib stuff work across 2/3.

from pkg_resources import require, VersionConflict, DistributionNotFound

# We don't admit our dependency on pip in setup.py, lest a naive user simply
# say `pip install peep.tar.gz` and thus pull down an untrusted copy of pip
# from PyPI. Instead, we make sure it's installed and new enough here and spit
# out an error message if not:


def activate(specifier):
    """Make a compatible version of pip importable. Raise a RuntimeError if we
    couldn't."""
    try:
        for distro in require(specifier):
            distro.activate()
    except (VersionConflict, DistributionNotFound):
        raise RuntimeError('The installed version of pip is too old; peep '
                           'requires ' + specifier)

# Before 0.6.2, the log module wasn't there, so some
# of our monkeypatching fails. It probably wouldn't be
# much work to support even earlier, though.
activate('pip>=0.6.2')

import pip
from pip.commands.install import InstallCommand
try:
    from pip.download import url_to_path  # 1.5.6
except ImportError:
    try:
        from pip.util import url_to_path  # 0.7.0
    except ImportError:
        from pip.util import url_to_filename as url_to_path  # 0.6.2
from pip.index import PackageFinder, Link
try:
    from pip.log import logger
except ImportError:
    from pip import logger  # 6.0
from pip.req import parse_requirements
try:
    from pip.utils.ui import DownloadProgressBar, DownloadProgressSpinner
except ImportError:
    class NullProgressBar(object):
        def __init__(self, *args, **kwargs):
            pass

        def iter(self, ret, *args, **kwargs):
            return ret

    DownloadProgressBar = DownloadProgressSpinner = NullProgressBar

__version__ = 2, 5, 0

try:
    from pip.index import FormatControl  # noqa
    FORMAT_CONTROL_ARG = 'format_control'

    # The line-numbering bug will be fixed in pip 8. All 7.x releases had it.
    PIP_MAJOR_VERSION = int(pip.__version__.split('.')[0])
    PIP_COUNTS_COMMENTS = PIP_MAJOR_VERSION >= 8
except ImportError:
    FORMAT_CONTROL_ARG = 'use_wheel'  # pre-7
    PIP_COUNTS_COMMENTS = True


ITS_FINE_ITS_FINE = 0
SOMETHING_WENT_WRONG = 1
# "Traditional" for command-line errors according to optparse docs:
COMMAND_LINE_ERROR = 2

ARCHIVE_EXTENSIONS = ('.tar.bz2', '.tar.gz', '.tgz', '.tar', '.zip')

MARKER = object()


class PipException(Exception):
    """When I delegated to pip, it exited with an error."""

    def __init__(self, error_code):
        self.error_code = error_code


class UnsupportedRequirementError(Exception):
    """An unsupported line was encountered in a requirements file."""


class DownloadError(Exception):
    def __init__(self, link, exc):
        self.link = link
        self.reason = str(exc)

    def __str__(self):
        return 'Downloading %s failed: %s' % (self.link, self.reason)


def encoded_hash(sha):
    """Return a short, 7-bit-safe representation of a hash.

    If you pass a sha256, this results in the hash algorithm that the Wheel
    format (PEP 427) uses, except here it's intended to be run across the
    downloaded archive before unpacking.

    """
    return urlsafe_b64encode(sha.digest()).decode('ascii').rstrip('=')


def path_and_line(req):
    """Return the path and line number of the file from which an
    InstallRequirement came.

    """
    path, line = (re.match(r'-r (.*) \(line (\d+)\)$',
                           req.comes_from).groups())
    return path, int(line)


def hashes_above(path, line_number):
    """Yield hashes from contiguous comment lines before line ``line_number``.

    """
    def hash_lists(path):
        """Yield lists of hashes appearing between non-comment lines.

        The lists will be in order of appearance and, for each non-empty
        list, their place in the results will coincide with that of the
        line number of the corresponding result from `parse_requirements`
        (which changed in pip 7.0 to not count comments).

        """
        hashes = []
        with open(path) as file:
            for lineno, line in enumerate(file, 1):
                match = HASH_COMMENT_RE.match(line)
                if match:  # Accumulate this hash.
                    hashes.append(match.groupdict()['hash'])
                if not IGNORED_LINE_RE.match(line):
                    yield hashes  # Report hashes seen so far.
                    hashes = []
                elif PIP_COUNTS_COMMENTS:
                    # Comment: count as normal req but have no hashes.
                    yield []

    return next(islice(hash_lists(path), line_number - 1, None))


def run_pip(initial_args):
    """Delegate to pip the given args (starting with the subcommand), and raise
    ``PipException`` if something goes wrong."""
    status_code = pip.main(initial_args)

    # Clear out the registrations in the pip "logger" singleton. Otherwise,
    # loggers keep getting appended to it with every run. Pip assumes only one
    # command invocation will happen per interpreter lifetime.
    logger.consumers = []

    if status_code:
        raise PipException(status_code)


def hash_of_file(path):
    """Return the hash of a downloaded file."""
    with open(path, 'rb') as archive:
        sha = sha256()
        while True:
            data = archive.read(2 ** 20)
            if not data:
                break
            sha.update(data)
    return encoded_hash(sha)


def is_git_sha(text):
    """Return whether this is probably a git sha"""
    # Handle both the full sha as well as the 7-character abbreviation
    if len(text) in (40, 7):
        try:
            int(text, 16)
            return True
        except ValueError:
            pass
    return False


def filename_from_url(url):
    parsed = urlparse(url)
    path = parsed.path
    return path.split('/')[-1]


def requirement_args(argv, want_paths=False, want_other=False):
    """Return an iterable of filtered arguments.

    :arg argv: Arguments, starting after the subcommand
    :arg want_paths: If True, the returned iterable includes the paths to any
        requirements files following a ``-r`` or ``--requirement`` option.
    :arg want_other: If True, the returned iterable includes the args that are
        not a requirement-file path or a ``-r`` or ``--requirement`` flag.

    """
    was_r = False
    for arg in argv:
        # Allow for requirements files named "-r", don't freak out if there's a
        # trailing "-r", etc.
        if was_r:
            if want_paths:
                yield arg
            was_r = False
        elif arg in ['-r', '--requirement']:
            was_r = True
        else:
            if want_other:
                yield arg

# any line that is a comment or just whitespace
IGNORED_LINE_RE = re.compile(r'^(\s*#.*)?\s*$')

HASH_COMMENT_RE = re.compile(
    r"""
    \s*\#\s+                   # Lines that start with a '#'
    (?P<hash_type>sha256):\s+  # Hash type is hardcoded to be sha256 for now.
    (?P<hash>[^\s]+)           # Hashes can be anything except '#' or spaces.
    \s*                        # Suck up whitespace before the comment or
                               #   just trailing whitespace if there is no
                               #   comment. Also strip trailing newlines.
    (?:\#(?P<comment>.*))?     # Comments can be anything after a whitespace+#
                               #   and are optional.
    $""", re.X)


def peep_hash(argv):
    """Return the peep hash of one or more files, returning a shell status code
    or raising a PipException.

    :arg argv: The commandline args, starting after the subcommand

    """
    parser = OptionParser(
        usage='usage: %prog hash file [file ...]',
        description='Print a peep hash line for one or more files: for '
                    'example, "# sha256: '
                    'oz42dZy6Gowxw8AelDtO4gRgTW_xPdooH484k7I5EOY".')
    _, paths = parser.parse_args(args=argv)
    if paths:
        for path in paths:
            print('# sha256:', hash_of_file(path))
        return ITS_FINE_ITS_FINE
    else:
        parser.print_usage()
        return COMMAND_LINE_ERROR


class EmptyOptions(object):
    """Fake optparse options for compatibility with pip<1.2

    pip<1.2 had a bug in parse_requirements() in which the ``options`` kwarg
    was required. We work around that by passing it a mock object.

    """
    default_vcs = None
    skip_requirements_regex = None
    isolated_mode = False


def memoize(func):
    """Memoize a method that should return the same result every time on a
    given instance.

    """
    @wraps(func)
    def memoizer(self):
        if not hasattr(self, '_cache'):
            self._cache = {}
        if func.__name__ not in self._cache:
            self._cache[func.__name__] = func(self)
        return self._cache[func.__name__]
    return memoizer


def package_finder(argv):
    """Return a PackageFinder respecting command-line options.

    :arg argv: Everything after the subcommand

    """
    # We instantiate an InstallCommand and then use some of its private
    # machinery--its arg parser--for our own purposes, like a virus. This
    # approach is portable across many pip versions, where more fine-grained
    # ones are not. Ignoring options that don't exist on the parser (for
    # instance, --use-wheel) gives us a straightforward method of backward
    # compatibility.
    try:
        command = InstallCommand()
    except TypeError:
        # This is likely pip 1.3.0's "__init__() takes exactly 2 arguments (1
        # given)" error. In that version, InstallCommand takes a top=level
        # parser passed in from outside.
        from pip.baseparser import create_main_parser
        command = InstallCommand(create_main_parser())
    # The downside is that it essentially ruins the InstallCommand class for
    # further use. Calling out to pip.main() within the same interpreter, for
    # example, would result in arguments parsed this time turning up there.
    # Thus, we deepcopy the arg parser so we don't trash its singletons. Of
    # course, deepcopy doesn't work on these objects, because they contain
    # uncopyable regex patterns, so we pickle and unpickle instead. Fun!
    options, _ = loads(dumps(command.parser)).parse_args(argv)

    # Carry over PackageFinder kwargs that have [about] the same names as
    # options attr names:
    possible_options = [
        'find_links', FORMAT_CONTROL_ARG, 'allow_external', 'allow_unverified',
        'allow_all_external', ('allow_all_prereleases', 'pre'),
        'process_dependency_links']
    kwargs = {}
    for option in possible_options:
        kw, attr = option if isinstance(option, tuple) else (option, option)
        value = getattr(options, attr, MARKER)
        if value is not MARKER:
            kwargs[kw] = value

    # Figure out index_urls:
    index_urls = [options.index_url] + options.extra_index_urls
    if options.no_index:
        index_urls = []
    index_urls += getattr(options, 'mirrors', [])

    # If pip is new enough to have a PipSession, initialize one, since
    # PackageFinder requires it:
    if hasattr(command, '_build_session'):
        kwargs['session'] = command._build_session(options)

    return PackageFinder(index_urls=index_urls, **kwargs)


class DownloadedReq(object):
    """A wrapper around InstallRequirement which offers additional information
    based on downloading and examining a corresponding package archive

    These are conceptually immutable, so we can get away with memoizing
    expensive things.

    """
    def __init__(self, req, argv, finder):
        """Download a requirement, compare its hashes, and return a subclass
        of DownloadedReq depending on its state.

        :arg req: The InstallRequirement I am based on
        :arg argv: The args, starting after the subcommand

        """
        self._req = req
        self._argv = argv
        self._finder = finder

        # We use a separate temp dir for each requirement so requirements
        # (from different indices) that happen to have the same archive names
        # don't overwrite each other, leading to a security hole in which the
        # latter is a hash mismatch, the former has already passed the
        # comparison, and the latter gets installed.
        self._temp_path = mkdtemp(prefix='peep-')
        # Think of DownloadedReq as a one-shot state machine. It's an abstract
        # class that ratchets forward to being one of its own subclasses,
        # depending on its package status. Then it doesn't move again.
        self.__class__ = self._class()

    def dispose(self):
        """Delete temp files and dirs I've made. Render myself useless.

        Do not call further methods on me after calling dispose().

        """
        rmtree(self._temp_path)

    def _version(self):
        """Deduce the version number of the downloaded package from its filename."""
        # TODO: Can we delete this method and just print the line from the
        # reqs file verbatim instead?
        def version_of_archive(filename, package_name):
            # Since we know the project_name, we can strip that off the left, strip
            # any archive extensions off the right, and take the rest as the
            # version.
            for ext in ARCHIVE_EXTENSIONS:
                if filename.endswith(ext):
                    filename = filename[:-len(ext)]
                    break
            # Handle github sha tarball downloads.
            if is_git_sha(filename):
                filename = package_name + '-' + filename
            if not filename.lower().replace('_', '-').startswith(package_name.lower()):
                # TODO: Should we replace runs of [^a-zA-Z0-9.], not just _, with -?
                give_up(filename, package_name)
            return filename[len(package_name) + 1:]  # Strip off '-' before version.

        def version_of_wheel(filename, package_name):
            # For Wheel files (http://legacy.python.org/dev/peps/pep-0427/#file-
            # name-convention) we know the format bits are '-' separated.
            whl_package_name, version, _rest = filename.split('-', 2)
            # Do the alteration to package_name from PEP 427:
            our_package_name = re.sub(r'[^\w\d.]+', '_', package_name, re.UNICODE)
            if whl_package_name != our_package_name:
                give_up(filename, whl_package_name)
            return version

        def give_up(filename, package_name):
            raise RuntimeError("The archive '%s' didn't start with the package name "
                               "'%s', so I couldn't figure out the version number. "
                               "My bad; improve me." %
                               (filename, package_name))

        get_version = (version_of_wheel
                       if self._downloaded_filename().endswith('.whl')
                       else version_of_archive)
        return get_version(self._downloaded_filename(), self._project_name())

    def _is_always_unsatisfied(self):
        """Returns whether this requirement is always unsatisfied

        This would happen in cases where we can't determine the version
        from the filename.

        """
        # If this is a github sha tarball, then it is always unsatisfied
        # because the url has a commit sha in it and not the version
        # number.
        url = self._url()
        if url:
            filename = filename_from_url(url)
            if filename.endswith(ARCHIVE_EXTENSIONS):
                filename, ext = splitext(filename)
                if is_git_sha(filename):
                    return True
        return False

    @memoize  # Avoid hitting the file[cache] over and over.
    def _expected_hashes(self):
        """Return a list of known-good hashes for this package."""
        return hashes_above(*path_and_line(self._req))

    def _download(self, link):
        """Download a file, and return its name within my temp dir.

        This does no verification of HTTPS certs, but our checking hashes
        makes that largely unimportant. It would be nice to be able to use the
        requests lib, which can verify certs, but it is guaranteed to be
        available only in pip >= 1.5.

        This also drops support for proxies and basic auth, though those could
        be added back in.

        """
        # Based on pip 1.4.1's URLOpener but with cert verification removed
        def opener(is_https):
            if is_https:
                opener = build_opener(HTTPSHandler())
                # Strip out HTTPHandler to prevent MITM spoof:
                for handler in opener.handlers:
                    if isinstance(handler, HTTPHandler):
                        opener.handlers.remove(handler)
            else:
                opener = build_opener()
            return opener

        # Descended from unpack_http_url() in pip 1.4.1
        def best_filename(link, response):
            """Return the most informative possible filename for a download,
            ideally with a proper extension.

            """
            content_type = response.info().get('content-type', '')
            filename = link.filename  # fallback
            # Have a look at the Content-Disposition header for a better guess:
            content_disposition = response.info().get('content-disposition')
            if content_disposition:
                type, params = cgi.parse_header(content_disposition)
                # We use ``or`` here because we don't want to use an "empty" value
                # from the filename param:
                filename = params.get('filename') or filename
            ext = splitext(filename)[1]
            if not ext:
                ext = mimetypes.guess_extension(content_type)
                if ext:
                    filename += ext
            if not ext and link.url != response.geturl():
                ext = splitext(response.geturl())[1]
                if ext:
                    filename += ext
            return filename

        # Descended from _download_url() in pip 1.4.1
        def pipe_to_file(response, path, size=0):
            """Pull the data off an HTTP response, shove it in a new file, and
            show progress.

            :arg response: A file-like object to read from
            :arg path: The path of the new file
            :arg size: The expected size, in bytes, of the download. 0 for
                unknown or to suppress progress indication (as for cached
                downloads)

            """
            def response_chunks(chunk_size):
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk

            print('Downloading %s%s...' % (
                self._req.req,
                (' (%sK)' % (size / 1000)) if size > 1000 else ''))
            progress_indicator = (DownloadProgressBar(max=size).iter if size
                                  else DownloadProgressSpinner().iter)
            with open(path, 'wb') as file:
                for chunk in progress_indicator(response_chunks(4096), 4096):
                    file.write(chunk)

        url = link.url.split('#', 1)[0]
        try:
            response = opener(urlparse(url).scheme != 'http').open(url)
        except (HTTPError, IOError) as exc:
            raise DownloadError(link, exc)
        filename = best_filename(link, response)
        try:
            size = int(response.headers['content-length'])
        except (ValueError, KeyError, TypeError):
            size = 0
        pipe_to_file(response, join(self._temp_path, filename), size=size)
        return filename

    # Based on req_set.prepare_files() in pip bb2a8428d4aebc8d313d05d590f386fa3f0bbd0f
    @memoize  # Avoid re-downloading.
    def _downloaded_filename(self):
        """Download the package's archive if necessary, and return its
        filename.

        --no-deps is implied, as we have reimplemented the bits that would
        ordinarily do dependency resolution.

        """
        # Peep doesn't support requirements that don't come down as a single
        # file, because it can't hash them. Thus, it doesn't support editable
        # requirements, because pip itself doesn't support editable
        # requirements except for "local projects or a VCS url". Nor does it
        # support VCS requirements yet, because we haven't yet come up with a
        # portable, deterministic way to hash them. In summary, all we support
        # is == requirements and tarballs/zips/etc.

        # TODO: Stop on reqs that are editable or aren't ==.

        # If the requirement isn't already specified as a URL, get a URL
        # from an index:
        link = self._link() or self._finder.find_requirement(self._req, upgrade=False)

        if link:
            lower_scheme = link.scheme.lower()  # pip lower()s it for some reason.
            if lower_scheme == 'http' or lower_scheme == 'https':
                file_path = self._download(link)
                return basename(file_path)
            elif lower_scheme == 'file':
                # The following is inspired by pip's unpack_file_url():
                link_path = url_to_path(link.url_without_fragment)
                if isdir(link_path):
                    raise UnsupportedRequirementError(
                        "%s: %s is a directory. So that it can compute "
                        "a hash, peep supports only filesystem paths which "
                        "point to files" %
                        (self._req, link.url_without_fragment))
                else:
                    copy(link_path, self._temp_path)
                    return basename(link_path)
            else:
                raise UnsupportedRequirementError(
                    "%s: The download link, %s, would not result in a file "
                    "that can be hashed. Peep supports only == requirements, "
                    "file:// URLs pointing to files (not folders), and "
                    "http:// and https:// URLs pointing to tarballs, zips, "
                    "etc." % (self._req, link.url))
        else:
            raise UnsupportedRequirementError(
                "%s: couldn't determine where to download this requirement from."
                % (self._req,))

    def install(self):
        """Install the package I represent, without dependencies.

        Obey typical pip-install options passed in on the command line.

        """
        other_args = list(requirement_args(self._argv, want_other=True))
        archive_path = join(self._temp_path, self._downloaded_filename())
        # -U so it installs whether pip deems the requirement "satisfied" or
        # not. This is necessary for GitHub-sourced zips, which change without
        # their version numbers changing.
        run_pip(['install'] + other_args + ['--no-deps', '-U', archive_path])

    @memoize
    def _actual_hash(self):
        """Download the package's archive if necessary, and return its hash."""
        return hash_of_file(join(self._temp_path, self._downloaded_filename()))

    def _project_name(self):
        """Return the inner Requirement's "unsafe name".

        Raise ValueError if there is no name.

        """
        name = getattr(self._req.req, 'project_name', '')
        if name:
            return name
        raise ValueError('Requirement has no project_name.')

    def _name(self):
        return self._req.name

    def _link(self):
        try:
            return self._req.link
        except AttributeError:
            # The link attribute isn't available prior to pip 6.1.0, so fall
            # back to the now deprecated 'url' attribute.
            return Link(self._req.url) if self._req.url else None

    def _url(self):
        link = self._link()
        return link.url if link else None

    @memoize  # Avoid re-running expensive check_if_exists().
    def _is_satisfied(self):
        self._req.check_if_exists()
        return (self._req.satisfied_by and
                not self._is_always_unsatisfied())

    def _class(self):
        """Return the class I should be, spanning a continuum of goodness."""
        try:
            self._project_name()
        except ValueError:
            return MalformedReq
        if self._is_satisfied():
            return SatisfiedReq
        if not self._expected_hashes():
            return MissingReq
        if self._actual_hash() not in self._expected_hashes():
            return MismatchedReq
        return InstallableReq

    @classmethod
    def foot(cls):
        """Return the text to be printed once, after all of the errors from
        classes of my type are printed.

        """
        return ''


class MalformedReq(DownloadedReq):
    """A requirement whose package name could not be determined"""

    @classmethod
    def head(cls):
        return 'The following requirements could not be processed:\n'

    def error(self):
        return '* Unable to determine package name from URL %s; add #egg=' % self._url()


class MissingReq(DownloadedReq):
    """A requirement for which no hashes were specified in the requirements file"""

    @classmethod
    def head(cls):
        return ('The following packages had no hashes specified in the requirements file, which\n'
                'leaves them open to tampering. Vet these packages to your satisfaction, then\n'
                'add these "sha256" lines like so:\n\n')

    def error(self):
        if self._url():
            # _url() always contains an #egg= part, or this would be a
            # MalformedRequest.
            line = self._url()
        else:
            line = '%s==%s' % (self._name(), self._version())
        return '# sha256: %s\n%s\n' % (self._actual_hash(), line)


class MismatchedReq(DownloadedReq):
    """A requirement for which the downloaded file didn't match any of my hashes."""
    @classmethod
    def head(cls):
        return ("THE FOLLOWING PACKAGES DIDN'T MATCH THE HASHES SPECIFIED IN THE REQUIREMENTS\n"
                "FILE. If you have updated the package versions, update the hashes. If not,\n"
                "freak out, because someone has tampered with the packages.\n\n")

    def error(self):
        preamble = '    %s: expected' % self._project_name()
        if len(self._expected_hashes()) > 1:
            preamble += ' one of'
        padding = '\n' + ' ' * (len(preamble) + 1)
        return '%s %s\n%s got %s' % (preamble,
                                     padding.join(self._expected_hashes()),
                                     ' ' * (len(preamble) - 4),
                                     self._actual_hash())

    @classmethod
    def foot(cls):
        return '\n'


class SatisfiedReq(DownloadedReq):
    """A requirement which turned out to be already installed"""

    @classmethod
    def head(cls):
        return ("These packages were already installed, so we didn't need to download or build\n"
                "them again. If you installed them with peep in the first place, you should be\n"
                "safe. If not, uninstall them, then re-attempt your install with peep.\n")

    def error(self):
        return '   %s' % (self._req,)


class InstallableReq(DownloadedReq):
    """A requirement whose hash matched and can be safely installed"""


# DownloadedReq subclasses that indicate an error that should keep us from
# going forward with installation, in the order in which their errors should
# be reported:
ERROR_CLASSES = [MismatchedReq, MissingReq, MalformedReq]


def bucket(things, key):
    """Return a map of key -> list of things."""
    ret = defaultdict(list)
    for thing in things:
        ret[key(thing)].append(thing)
    return ret


def first_every_last(iterable, first, every, last):
    """Execute something before the first item of iter, something else for each
    item, and a third thing after the last.

    If there are no items in the iterable, don't execute anything.

    """
    did_first = False
    for item in iterable:
        if not did_first:
            did_first = True
            first(item)
        every(item)
    if did_first:
        last(item)


def _parse_requirements(path, finder):
    try:
        # list() so the generator that is parse_requirements() actually runs
        # far enough to report a TypeError
        return list(parse_requirements(
            path, options=EmptyOptions(), finder=finder))
    except TypeError:
        # session is a required kwarg as of pip 6.0 and will raise
        # a TypeError if missing. It needs to be a PipSession instance,
        # but in older versions we can't import it from pip.download
        # (nor do we need it at all) so we only import it in this except block
        from pip.download import PipSession
        return list(parse_requirements(
            path, options=EmptyOptions(), session=PipSession(), finder=finder))


def downloaded_reqs_from_path(path, argv):
    """Return a list of DownloadedReqs representing the requirements parsed
    out of a given requirements file.

    :arg path: The path to the requirements file
    :arg argv: The commandline args, starting after the subcommand

    """
    finder = package_finder(argv)
    return [DownloadedReq(req, argv, finder) for req in
            _parse_requirements(path, finder)]


def peep_install(argv):
    """Perform the ``peep install`` subcommand, returning a shell status code
    or raising a PipException.

    :arg argv: The commandline args, starting after the subcommand

    """
    output = []
    out = output.append
    reqs = []
    try:
        req_paths = list(requirement_args(argv, want_paths=True))
        if not req_paths:
            out("You have to specify one or more requirements files with the -r option, because\n"
                "otherwise there's nowhere for peep to look up the hashes.\n")
            return COMMAND_LINE_ERROR

        # We're a "peep install" command, and we have some requirement paths.
        reqs = list(chain.from_iterable(
            downloaded_reqs_from_path(path, argv)
            for path in req_paths))
        buckets = bucket(reqs, lambda r: r.__class__)

        # Skip a line after pip's "Cleaning up..." so the important stuff
        # stands out:
        if any(buckets[b] for b in ERROR_CLASSES):
            out('\n')

        printers = (lambda r: out(r.head()),
                    lambda r: out(r.error() + '\n'),
                    lambda r: out(r.foot()))
        for c in ERROR_CLASSES:
            first_every_last(buckets[c], *printers)

        if any(buckets[b] for b in ERROR_CLASSES):
            out('-------------------------------\n'
                'Not proceeding to installation.\n')
            return SOMETHING_WENT_WRONG
        else:
            for req in buckets[InstallableReq]:
                req.install()

            first_every_last(buckets[SatisfiedReq], *printers)

        return ITS_FINE_ITS_FINE
    except (UnsupportedRequirementError, DownloadError) as exc:
        out(str(exc))
        return SOMETHING_WENT_WRONG
    finally:
        for req in reqs:
            req.dispose()
        print(''.join(output))


def peep_port(paths):
    """Convert a peep requirements file to one compatble with pip-8 hashing.

    Loses comments and tromps on URLs, so the result will need a little manual
    massaging, but the hard part--the hash conversion--is done for you.

    """
    if not paths:
        print('Please specify one or more requirements files so I have '
              'something to port.\n')
        return COMMAND_LINE_ERROR
    for req in chain.from_iterable(
            _parse_requirements(path, package_finder(argv)) for path in paths):
        hashes = [hexlify(urlsafe_b64decode((hash + '=').encode('ascii'))).decode('ascii')
                  for hash in hashes_above(*path_and_line(req))]
        if not hashes:
            print(req.req)
        elif len(hashes) == 1:
            print('%s --hash=sha256:%s' % (req.req, hashes[0]))
        else:
            print('%s' % req.req, end='')
            for hash in hashes:
                print(' \\')
                print('    --hash=sha256:%s' % hash, end='')
            print()


def main():
    """Be the top-level entrypoint. Return a shell status code."""
    commands = {'hash': peep_hash,
                'install': peep_install,
                'port': peep_port}
    try:
        if len(argv) >= 2 and argv[1] in commands:
            return commands[argv[1]](argv[2:])
        else:
            # Fall through to top-level pip main() for everything else:
            return pip.main()
    except PipException as exc:
        return exc.error_code


def exception_handler(exc_type, exc_value, exc_tb):
    print('Oh no! Peep had a problem while trying to do stuff. Please write up a bug report')
    print('with the specifics so we can fix it:')
    print()
    print('https://github.com/erikrose/peep/issues/new')
    print()
    print('Here are some particulars you can copy and paste into the bug report:')
    print()
    print('---')
    print('peep:', repr(__version__))
    print('python:', repr(sys.version))
    print('pip:', repr(getattr(pip, '__version__', 'no __version__ attr')))
    print('Command line: ', repr(sys.argv))
    print(
        ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)))
    print('---')


if __name__ == '__main__':
    try:
        exit(main())
    except Exception:
        exception_handler(*sys.exc_info())
        exit(SOMETHING_WENT_WRONG)
