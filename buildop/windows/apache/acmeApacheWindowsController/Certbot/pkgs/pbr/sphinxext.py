# Copyright 2018 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import os.path

from six.moves import configparser
from sphinx.util import logging

import pbr.version

_project = None
logger = logging.getLogger(__name__)


def _find_setup_cfg(srcdir):
    """Find the 'setup.cfg' file, if it exists.

    This assumes we're using 'doc/source' for documentation, but also allows
    for single level 'doc' paths.
    """
    # TODO(stephenfin): Are we sure that this will always exist, e.g. for
    # an sdist or wheel? Perhaps we should check for 'PKG-INFO' or
    # 'METADATA' files, a la 'pbr.packaging._get_version_from_pkg_metadata'
    for path in [
            os.path.join(srcdir, os.pardir, 'setup.cfg'),
            os.path.join(srcdir, os.pardir, os.pardir, 'setup.cfg')]:
        if os.path.exists(path):
            return path

    return None


def _get_project_name(srcdir):
    """Return string name of project name, or None.

    This extracts metadata from 'setup.cfg'. We don't rely on
    distutils/setuptools as we don't want to actually install the package
    simply to build docs.
    """
    global _project

    if _project is None:
        parser = configparser.ConfigParser()

        path = _find_setup_cfg(srcdir)
        if not path or not parser.read(path):
            logger.info('Could not find a setup.cfg to extract project name '
                        'from')
            return None

        try:
            # for project name we use the name in setup.cfg, but if the
            # length is longer then 32 we use summary. Otherwise thAe
            # menu rendering looks brolen
            project = parser.get('metadata', 'name')
            if len(project.split()) == 1 and len(project) > 32:
                project = parser.get('metadata', 'summary')
        except configparser.Error:
            logger.info('Could not extract project metadata from setup.cfg')
            return None

        _project = project

    return _project


def _builder_inited(app):
    # TODO(stephenfin): Once Sphinx 1.8 is released, we should move the below
    # to a 'config-inited' handler

    project_name = _get_project_name(app.srcdir)
    try:
        version_info = pbr.version.VersionInfo(project_name)
    except Exception:
        version_info = None

    if version_info and not app.config.version and not app.config.release:
        app.config.version = version_info.canonical_version_string()
        app.config.release = version_info.version_string_with_vcs()


def setup(app):
    app.connect('builder-inited', _builder_inited)
    return {
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
