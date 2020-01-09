# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4 -*-
#
# This is an almost verbatim copy of what is in the snapcraft
# tree, can be completely removed once the functionality in
# snapcraft is in place. (LP: #1841861)
#
# Copyright (C) 2016-2020 Canonical Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""The python plugin can be used for python 2 or 3 based parts.

It can be used for python projects where you would want to do:

    - import python modules with a requirements.txt
    - build a python project that has a setup.py
    - install packages straight from pip

This plugin uses the common plugin keywords as well as those for "sources".
For more information check the 'plugins' topic for the former and the
'sources' topic for the latter.

Additionally, this plugin uses the following plugin-specific keywords:

    - requirements:
      (list of strings)
      List of paths to requirements files.
    - constraints:
      (list of strings)
      List of paths to constraint files.
    - process-dependency-links:
      (bool; default: false)
      Enable the processing of dependency links in pip, which allow one
      project to provide places to look for another project
    - python-packages:
      (list)
      A list of dependencies to get from PyPI
    - python-version:
      (string; default: python3)
      The python version to use. Valid options are: python2 and python3

If the plugin finds a python interpreter with a basename that matches
`python-version` in the <stage> directory on the following fixed path:
`<stage-dir>/usr/bin/<python-interpreter>` then this interpreter would
be preferred instead and no interpreter would be brought in through
`stage-packages` mechanisms.
"""

import collections
import contextlib
import os
import re
from shutil import which
from textwrap import dedent
from typing import List, Optional, Set

import requests

import snapcraft
from snapcraft.common import isurl
from snapcraft.internal import errors, mangling
from snapcraft.internal.errors import SnapcraftPluginCommandError
from snapcraft.plugins import _python


class UnsupportedPythonVersionError(snapcraft.internal.errors.SnapcraftError):

    fmt = "Unsupported python version: {python_version!r}"


class SnapcraftPluginPythonFileMissing(snapcraft.internal.errors.SnapcraftError):

    fmt = (
        "Failed to find the referred {plugin_property} file at the given "
        "path: {plugin_property_value!r}.\n"
        "Check the property and ensure the file exists."
    )

    def __init__(self, *, plugin_property, plugin_property_value):
        super().__init__(
            plugin_property=plugin_property, plugin_property_value=plugin_property_value
        )


class PythonPlugin(snapcraft.BasePlugin):
    @classmethod
    def schema(cls):
        schema = super().schema()
        schema["properties"]["requirements"] = {
            "type": "array",
            "minitems": 1,
            "uniqueItems": True,
            "items": {"type": "string"},
            "default": [],
        }
        schema["properties"]["constraints"] = {
            "type": "array",
            "minitems": 1,
            "uniqueItems": True,
            "items": {"type": "string"},
            "default": [],
        }
        schema["properties"]["python-packages"] = {
            "type": "array",
            "minitems": 1,
            "uniqueItems": True,
            "items": {"type": "string"},
            "default": [],
        }
        schema["properties"]["process-dependency-links"] = {
            "type": "boolean",
            "default": False,
        }
        schema["properties"]["python-version"] = {
            "type": "string",
            "default": "python3",
            "enum": ["python2", "python3"],
        }
        schema["anyOf"] = [{"required": ["source"]}, {"required": ["python-packages"]}]

        return schema

    @classmethod
    def get_pull_properties(cls):
        # Inform Snapcraft of the properties associated with pulling. If these
        # change in the YAML Snapcraft will consider the pull step dirty.
        return [
            "requirements",
            "constraints",
            "python-packages",
            "process-dependency-links",
            "python-version",
        ]

    @property
    def plugin_stage_packages(self):
        if self.options.python_version == "python2":
            python_base = "python"
        elif self.options.python_version == "python3":
            python_base = "python3"

        if self.project.info.get_build_base() in ("core", "core16", "core18"):
            stage_packages = [python_base]
        else:
            stage_packages = []

        if self.project.info.get_build_base() == "core18" and python_base == "python3":
            stage_packages.append("{}-distutils".format(python_base))

        return stage_packages

    # ignore mypy error: Read-only property cannot override read-write property
    @property  # type: ignore
    def stage_packages(self):
        try:
            _python.get_python_command(
                self._python_major_version,
                stage_dir=self.project.stage_dir,
                install_dir=self.installdir,
            )
        except _python.errors.MissingPythonCommandError:
            return super().stage_packages + self.plugin_stage_packages
        else:
            return super().stage_packages

    @property
    def _pip(self):
        if not self.__pip:
            self.__pip = _python.Pip(
                python_major_version=self._python_major_version,
                part_dir=self.partdir,
                install_dir=self.installdir,
                stage_dir=self.project.stage_dir,
            )
        return self.__pip

    def __init__(self, name, options, project):
        super().__init__(name, options, project)

        self._setup_base_tools(project.info.get_build_base())

        self._manifest = collections.OrderedDict()

        # Pip requires only the major version of python rather than the command
        # name like our option requires.
        match = re.match(r"python(?P<major_version>\d).*", self.options.python_version)
        if not match:
            raise UnsupportedPythonVersionError(
                python_version=self.options.python_version
            )

        self._python_major_version = match.group("major_version")
        self.__pip = None

    def _setup_base_tools(self, base):
        # NOTE: stage-packages are lazily loaded.
        if base in ("core", "core16", "core18"):
            if self.options.python_version == "python3":
                self.build_packages.extend(
                    [
                        "python3-dev",
                        "python3-pip",
                        "python3-pkg-resources",
                        "python3-setuptools",
                    ]
                )
            elif self.options.python_version == "python2":
                self.build_packages.extend(
                    [
                        "python-dev",
                        "python-pip",
                        "python-pkg-resources",
                        "python-setuptools",
                    ]
                )
        else:
            raise errors.PluginBaseError(part_name=self.name, base=base)

    def pull(self):
        super().pull()

        self._pip.setup()

        with simple_env_bzr(os.path.join(self.installdir, "bin")):
            # Download this project, using its setup.py if present. This will
            # also download any python-packages requested.
            self._download_project()

    def clean_pull(self):
        super().clean_pull()
        self._pip.clean_packages()

    def build(self):
        super().build()

        with simple_env_bzr(os.path.join(self.installdir, "bin")):
            # Install the packages that have already been downloaded
            installed_pipy_packages = self._install_project()

        requirements = self._get_list_of_packages_from_property(
            self.options.requirements
        )
        if requirements:
            self._manifest["requirements-contents"] = requirements

        constraints = self._get_list_of_packages_from_property(self.options.constraints)
        if constraints:
            self._manifest["constraints-contents"] = constraints

        self._manifest["python-packages"] = [
            "{}={}".format(name, installed_pipy_packages[name])
            for name in installed_pipy_packages
        ]

        try:
            _python.generate_sitecustomize(
                self._python_major_version,
                stage_dir=self.project.stage_dir,
                install_dir=self.installdir,
            )
        except _python.errors.MissingUserSitePackagesError as site_error:
            print("Part {!r} generated to site-packages: {!s}.".format(
                self.name, site_error))

    def _find_file(self, *, filename: str) -> Optional[str]:
        # source-subdir defaults to ''
        for basepath in [self.builddir, self.sourcedir]:
            if basepath == self.sourcedir:
                # This is overwritten in the base plugin
                # TODO add consistency
                source_subdir = self.options.source_subdir
            else:
                source_subdir = ""
            filepath = os.path.join(basepath, source_subdir, filename)
            if os.path.exists(filepath):
                return filepath

        return None

    def _get_setup_py_dir(self):
        setup_py_dir = None
        setup_py_path = self._find_file(filename="setup.py")
        if setup_py_path:
            setup_py_dir = os.path.dirname(setup_py_path)

        return setup_py_dir

    def _get_list_of_packages_from_property(self, property_list: Set[str]) -> List[str]:
        """Return a sorted list of all packages found in property."""
        package_list = list()  # type: List[str]
        for entry in property_list:
            contents = self._get_file_contents(entry)
            package_list.extend(contents.splitlines())
        return package_list

    def _get_normalized_property_set(
        self, property_name, property_list: List[str]
    ) -> Set[str]:
        """Return a normalized set from a requirements or constraints list."""
        normalized = set()  # type: Set[str]
        for entry in property_list:
            if isurl(entry):
                normalized.add(entry)
            else:
                entry_file = self._find_file(filename=entry)
                if not entry_file:
                    raise SnapcraftPluginPythonFileMissing(
                        plugin_property=property_name, plugin_property_value=entry
                    )
                normalized.add(entry_file)

        return normalized

    def _install_wheels(self, wheels):
        installed = self._pip.list()
        wheel_names = [os.path.basename(w).split("-")[0] for w in wheels]

        # we want to avoid installing what is already provided in
        # stage-packages
        need_install = [k for k in wheel_names if k not in installed]
        self._pip.install(
            need_install,
            upgrade=True,
            install_deps=False,
            process_dependency_links=self.options.process_dependency_links,
        )

    def _download_project(self):
        constraints = self._get_normalized_property_set(
            "constraints", self.options.constraints
        )
        requirements = self._get_normalized_property_set(
            "requirements", self.options.requirements
        )

        self._pip.download(
            self.options.python_packages,
            setup_py_dir=None,
            constraints=constraints,
            requirements=requirements,
            process_dependency_links=self.options.process_dependency_links,
        )

    def _install_project(self):
        setup_py_dir = self._get_setup_py_dir()
        constraints = self._get_normalized_property_set(
            "constraints", self.options.constraints
        )
        requirements = self._get_normalized_property_set(
            "requirements", self.options.requirements
        )

        # setup.py is handled in a different step as some projects may
        # need to satisfy dependencies for setup.py to be parsed.
        wheels = self._pip.wheel(
            self.options.python_packages,
            setup_py_dir=None,
            constraints=constraints,
            requirements=requirements,
            process_dependency_links=self.options.process_dependency_links,
        )

        if wheels:
            self._install_wheels(wheels)

        if setup_py_dir is not None:
            self._pip.download(
                [],
                setup_py_dir=setup_py_dir,
                constraints=constraints,
                requirements=set(),
                process_dependency_links=self.options.process_dependency_links,
            )
            wheels = self._pip.wheel(
                [],
                setup_py_dir=setup_py_dir,
                constraints=constraints,
                requirements=set(),
                process_dependency_links=self.options.process_dependency_links,
            )

            if wheels:
                self._install_wheels(wheels)

            setup_py_path = os.path.join(setup_py_dir, "setup.py")
            if os.path.exists(setup_py_path):
                self._pip.install(
                    [],
                    setup_py_dir=setup_py_dir,
                    constraints=constraints,
                    process_dependency_links=self.options.process_dependency_links,
                    upgrade=True,
                )
                # pbr and others don't work using `pip install .`
                # LP: #1670852
                # There is also a chance that this setup.py is distutils based
                # in which case we will rely on the `pip install .` ran before
                #  this.
                with contextlib.suppress(SnapcraftPluginCommandError):
                    self._setup_tools_install(setup_py_path)

        return self._pip.list()

    def _setup_tools_install(self, setup_file):
        command = [
            _python.get_python_command(
                self._python_major_version,
                stage_dir=self.project.stage_dir,
                install_dir=self.installdir,
            ),
            os.path.basename(setup_file),
            "--no-user-cfg",
            "install",
            "--single-version-externally-managed",
            "--user",
            "--record",
            "install.txt",
        ]
        self.run(command, env=self._pip.env(), cwd=os.path.dirname(setup_file))

        # Fix all shebangs to use the in-snap python. The stuff installed from
        # pip has already been fixed, but anything done in this step has not.
        mangling.rewrite_python_shebangs(self.installdir)

    def _get_file_contents(self, path):
        if isurl(path):
            return requests.get(path).text
        else:
            file_path = os.path.join(self.sourcedir, path)
            with open(file_path) as _file:
                return _file.read()

    def get_manifest(self):
        return self._manifest

    def snap_fileset(self):
        fileset = super().snap_fileset()
        fileset.append("-bin/pip")
        fileset.append("-bin/pip2")
        fileset.append("-bin/pip3")
        fileset.append("-bin/pip2.7")
        fileset.append("-bin/pip3.*")
        fileset.append("-bin/easy_install*")
        fileset.append("-bin/wheel")
        # Holds all the .pyc files. It is a major cause of inter part
        # conflict.
        fileset.append("-**/__pycache__")
        fileset.append("-**/*.pyc")
        # The RECORD files include hashes useful when uninstalling packages.
        # In the snap they will cause conflicts when more than one part uses
        # the python plugin.
        fileset.append("-lib/python*/site-packages/*/RECORD")
        return fileset


@contextlib.contextmanager
def simple_env_bzr(bin_dir):
    """Create an appropriate environment to run bzr.

       The python plugin sets up PYTHONUSERBASE and PYTHONHOME which
       conflicts with bzr when using python3 as those two environment
       variables will make bzr look for modules in the wrong location.
       """
    os.makedirs(bin_dir, exist_ok=True)
    bzr_bin = os.path.join(bin_dir, "bzr")
    real_bzr_bin = which("bzr")
    if real_bzr_bin:
        exec_line = 'exec {} "$@"'.format(real_bzr_bin)
    else:
        exec_line = "echo bzr needs to be in PATH; exit 1"
    with open(bzr_bin, "w") as f:
        f.write(
            dedent(
                """#!/bin/sh
               unset PYTHONUSERBASE
               unset PYTHONHOME
               {}
            """.format(
                    exec_line
                )
            )
        )
    os.chmod(bzr_bin, 0o777)
    try:
        yield
    finally:
        os.remove(bzr_bin)
        if not os.listdir(bin_dir):
            os.rmdir(bin_dir)
