"""Setuptools entry points support for PyInstaller spec files.

See rthook-entrypoints Python module for complementary runtime hook
support.

"""
import collections
import json
import logging
import os
import pkg_resources


def Entrypoint(workpath, analysis_cls, dist, group, name,
               scripts=None, pathex=None, hiddenimports=(),
               hookspath=None, excludes=None, runtime_hooks=None):
    """Analyze setuptools entry point.

    Based on PyInstaller's Recipe for "Setuptools Entry Point":
    https://github.com/pyinstaller/pyinstaller/wiki/Recipe-Setuptools-Entry-Point

    """
    def get_toplevel(dist):
        """Get toplevel packages of distribution from metadata."""
        distribution = pkg_resources.get_distribution(dist)
        if distribution.has_metadata('top_level.txt'):
            return distribution.get_metadata('top_level.txt').split()
        else:
            return []

    packages = hiddenimports or []
    for distribution in hiddenimports[:]:
        packages += get_toplevel(distribution)

    scripts = scripts or []
    pathex = pathex or []
    # get the entry point
    ep = pkg_resources.get_entry_info(dist, group, name)
    # insert path of the egg at the verify front of the search path
    pathex = [ep.dist.location] + pathex

    # script name must not be a valid module name to avoid name
    # clashes on import
    script_path = os.path.join(workpath, name + '-script.py')
    logging.info('Creating script for entry point: '
                 'distribution=%s, group=%s, name=%s.', dist, group, name)
    with open(script_path, 'w') as fp:
        fp.write('import {0}\n'.format(ep.module_name))
        fp.write('{0}.{1}()\n'.format(ep.module_name, '.'.join(ep.attrs)))
        for package in packages:
            fp.write('import {0}\n'.format(package))

    return analysis_cls(
        [script_path] + scripts,
        pathex,
        hiddenimports,
        hookspath,
        excludes,
        runtime_hooks,
    )


def dump_entry_points(tmp_entry_points_path, *distribution_names):
    """Dump entry points database.

    Compile a database by going through all entry points registered by
    distributions listed in `distribution_names`. Serialize database to
    JSON and dump to a file (located in `tmp_entry_points_path`) that
    can be later copied to the one-folder/one-file distribution and used
    by `rthook-entrypoints.iter_entry_points`.

    """
    entry_points = collections.defaultdict(collections.defaultdict)
    for name in distribution_names:
        entry_map = pkg_resources.get_distribution(name).get_entry_map()
        for group, eps in entry_map.iteritems():
            entry_points[group][name] = [str(ep) for ep in eps.itervalues()]
    with open(tmp_entry_points_path, 'w') as fp:
        fp.write(json.dumps(entry_points))
    return entry_points
