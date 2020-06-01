import os
import sys


def _get_paths():
    # Get the path to jedi.
    _d = os.path.dirname
    _jedi_path = _d(_d(_d(_d(_d(__file__)))))
    _parso_path = sys.argv[1]
    # The paths are the directory that jedi and parso lie in.
    return {'jedi': _jedi_path, 'parso': _parso_path}


# Remove the first entry, because it's simply a directory entry that equals
# this directory.
del sys.path[0]

if sys.version_info > (3, 4):
    from importlib.machinery import PathFinder

    class _ExactImporter(object):
        def __init__(self, path_dct):
            self._path_dct = path_dct

        def find_module(self, fullname, path=None):
            if path is None and fullname in self._path_dct:
                p = self._path_dct[fullname]
                loader = PathFinder.find_module(fullname, path=[p])
                return loader
            return None

    # Try to import jedi/parso.
    sys.meta_path.insert(0, _ExactImporter(_get_paths()))
    from jedi.inference.compiled import subprocess  # NOQA
    sys.meta_path.pop(0)
else:
    import imp

    def load(name):
        paths = list(_get_paths().values())
        fp, pathname, description = imp.find_module(name, paths)
        return imp.load_module(name, fp, pathname, description)

    load('parso')
    load('jedi')
    from jedi.inference.compiled import subprocess  # NOQA

from jedi._compatibility import highest_pickle_protocol  # noqa: E402


# Retrieve the pickle protocol.
host_sys_version = [int(x) for x in sys.argv[2].split('.')]
pickle_protocol = highest_pickle_protocol([sys.version_info, host_sys_version])
# And finally start the client.
subprocess.Listener(pickle_protocol=pickle_protocol).listen()
