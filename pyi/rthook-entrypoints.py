"""PyInstaller runtime hook for setuptools entry points.

Monkey patches `pkg_resources.iter_entry_points` to return all entry
points as saved by `entrypoints.dump_entry_points` in the PyInstaller
spec file.

"""
import functools
import json
import os
import pkg_resources
import sys


class Distribution(object):
    """Fake setuptools distribution."""
    def __init__(self, key):
        self.key = key

    def requires(self, *unused_args, **unused_kwargs):
        return []

def patch(mod):
    """Monkey patch module's attributes."""
    def wrapper(f):   # pylint: disable=missing-docstring
        old = getattr(mod, f.__name__, f)
        def wrapper2(*args, **kwargs):  # pylint: disable=missing-docstring
            return f(old, *args, **kwargs)
        setattr(mod, f.__name__, wrapper2)
        return wrapper2
    return wrapper

def iter_entry_points_factory(all_entry_points):
    """Make patchable ``iter_entry_points`` that uses ``all_entry_points``."""
    def iter_entry_points(old_iter_entry_points, group, *args, **kwargs):
        """Monkey patched ``iter_entry_points``."""
        if group in all_entry_points:
            for dist_name, entry_points in all_entry_points[group].iteritems():
                dist = Distribution(dist_name)
                return [pkg_resources.EntryPoint.parse(entry_point, dist=dist)
                        for entry_point in entry_points]
        else:
            return old_iter_entry_points(group, *args, **kwargs)
    return iter_entry_points

def main():
    """Monkey-patch `pkg_resources` with correct database."""
    entry_points_path = os.path.join(sys._MEIPASS, 'entry_points.json')
    with open(entry_points_path) as fp:
        all_entry_points = json.loads(fp.read())
    patch(pkg_resources)(iter_entry_points_factory(all_entry_points))


if __name__ == '__main__':
    main()  # pragma: no cover
