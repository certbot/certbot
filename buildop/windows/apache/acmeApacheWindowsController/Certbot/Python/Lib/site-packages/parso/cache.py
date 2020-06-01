import time
import os
import sys
import hashlib
import gc
import shutil
import platform
import errno
import logging

try:
    import cPickle as pickle
except:
    import pickle

from parso._compatibility import FileNotFoundError

LOG = logging.getLogger(__name__)

_CACHED_FILE_MINIMUM_SURVIVAL = 60 * 10  # 10 minutes
"""
Cached files should survive at least a few minutes.
"""
_CACHED_SIZE_TRIGGER = 600
"""
This setting limits the amount of cached files. It's basically a way to start
garbage collection.

The reasoning for this limit being as big as it is, is the following:

Numpy, Pandas, Matplotlib and Tensorflow together use about 500 files. This
makes Jedi use ~500mb of memory. Since we might want a bit more than those few
libraries, we just increase it a bit.
"""

_PICKLE_VERSION = 33
"""
Version number (integer) for file system cache.

Increment this number when there are any incompatible changes in
the parser tree classes.  For example, the following changes
are regarded as incompatible.

- A class name is changed.
- A class is moved to another module.
- A __slot__ of a class is changed.
"""

_VERSION_TAG = '%s-%s%s-%s' % (
    platform.python_implementation(),
    sys.version_info[0],
    sys.version_info[1],
    _PICKLE_VERSION
)
"""
Short name for distinguish Python implementations and versions.

It's like `sys.implementation.cache_tag` but for Python2
we generate something similar.  See:
http://docs.python.org/3/library/sys.html#sys.implementation
"""


def _get_default_cache_path():
    if platform.system().lower() == 'windows':
        dir_ = os.path.join(os.getenv('LOCALAPPDATA') or '~', 'Parso', 'Parso')
    elif platform.system().lower() == 'darwin':
        dir_ = os.path.join('~', 'Library', 'Caches', 'Parso')
    else:
        dir_ = os.path.join(os.getenv('XDG_CACHE_HOME') or '~/.cache', 'parso')
    return os.path.expanduser(dir_)


_default_cache_path = _get_default_cache_path()
"""
The path where the cache is stored.

On Linux, this defaults to ``~/.cache/parso/``, on OS X to
``~/Library/Caches/Parso/`` and on Windows to ``%LOCALAPPDATA%\\Parso\\Parso\\``.
On Linux, if environment variable ``$XDG_CACHE_HOME`` is set,
``$XDG_CACHE_HOME/parso`` is used instead of the default one.
"""

parser_cache = {}


class _NodeCacheItem(object):
    def __init__(self, node, lines, change_time=None):
        self.node = node
        self.lines = lines
        if change_time is None:
            change_time = time.time()
        self.change_time = change_time
        self.last_used = change_time


def load_module(hashed_grammar, file_io, cache_path=None):
    """
    Returns a module or None, if it fails.
    """
    p_time = file_io.get_last_modified()
    if p_time is None:
        return None

    try:
        module_cache_item = parser_cache[hashed_grammar][file_io.path]
        if p_time <= module_cache_item.change_time:
            module_cache_item.last_used = time.time()
            return module_cache_item.node
    except KeyError:
        return _load_from_file_system(
            hashed_grammar,
            file_io.path,
            p_time,
            cache_path=cache_path
        )


def _load_from_file_system(hashed_grammar, path, p_time, cache_path=None):
    cache_path = _get_hashed_path(hashed_grammar, path, cache_path=cache_path)
    try:
        try:
            if p_time > os.path.getmtime(cache_path):
                # Cache is outdated
                return None
        except OSError as e:
            if e.errno == errno.ENOENT:
                # In Python 2 instead of an IOError here we get an OSError.
                raise FileNotFoundError
            else:
                raise

        with open(cache_path, 'rb') as f:
            gc.disable()
            try:
                module_cache_item = pickle.load(f)
            finally:
                gc.enable()
    except FileNotFoundError:
        return None
    else:
        _set_cache_item(hashed_grammar, path, module_cache_item)
        LOG.debug('pickle loaded: %s', path)
        return module_cache_item.node


def _set_cache_item(hashed_grammar, path, module_cache_item):
    if sum(len(v) for v in parser_cache.values()) >= _CACHED_SIZE_TRIGGER:
        # Garbage collection of old cache files.
        # We are basically throwing everything away that hasn't been accessed
        # in 10 minutes.
        cutoff_time = time.time() - _CACHED_FILE_MINIMUM_SURVIVAL
        for key, path_to_item_map in parser_cache.items():
            parser_cache[key] = {
                path: node_item
                for path, node_item in path_to_item_map.items()
                if node_item.last_used > cutoff_time
            }

    parser_cache.setdefault(hashed_grammar, {})[path] = module_cache_item


def save_module(hashed_grammar, file_io, module, lines, pickling=True, cache_path=None):
    path = file_io.path
    try:
        p_time = None if path is None else file_io.get_last_modified()
    except OSError:
        p_time = None
        pickling = False

    item = _NodeCacheItem(module, lines, p_time)
    _set_cache_item(hashed_grammar, path, item)
    if pickling and path is not None:
        _save_to_file_system(hashed_grammar, path, item, cache_path=cache_path)


def _save_to_file_system(hashed_grammar, path, item, cache_path=None):
    with open(_get_hashed_path(hashed_grammar, path, cache_path=cache_path), 'wb') as f:
        pickle.dump(item, f, pickle.HIGHEST_PROTOCOL)


def clear_cache(cache_path=None):
    if cache_path is None:
        cache_path = _default_cache_path
    shutil.rmtree(cache_path)
    parser_cache.clear()


def _get_hashed_path(hashed_grammar, path, cache_path=None):
    directory = _get_cache_directory_path(cache_path=cache_path)

    file_hash = hashlib.sha256(path.encode("utf-8")).hexdigest()
    return os.path.join(directory, '%s-%s.pkl' % (hashed_grammar, file_hash))


def _get_cache_directory_path(cache_path=None):
    if cache_path is None:
        cache_path = _default_cache_path
    directory = os.path.join(cache_path, _VERSION_TAG)
    if not os.path.exists(directory):
        os.makedirs(directory)
    return directory
