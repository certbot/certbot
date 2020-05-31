# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (C) 2013 Association of Universities for Research in Astronomy
#                    (AURA)
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#
#     3. The name of AURA and its representatives may not be used to
#        endorse or promote products derived from this software without
#        specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY AURA ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL AURA BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

"""The code in this module is mostly copy/pasted out of the distutils2 source
code, as recommended by Tarek Ziade.  As such, it may be subject to some change
as distutils2 development continues, and will have to be kept up to date.

I didn't want to use it directly from distutils2 itself, since I do not want it
to be an installation dependency for our packages yet--it is still too unstable
(the latest version on PyPI doesn't even install).
"""

# These first two imports are not used, but are needed to get around an
# irritating Python bug that can crop up when using ./setup.py test.
# See: http://www.eby-sarna.com/pipermail/peak/2010-May/003355.html
try:
    import multiprocessing  # noqa
except ImportError:
    pass
import logging  # noqa

from collections import defaultdict
import io
import os
import re
import shlex
import sys
import traceback

import distutils.ccompiler
from distutils import errors
from distutils import log
import pkg_resources
from setuptools import dist as st_dist
from setuptools import extension

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

from pbr import extra_files
import pbr.hooks

# A simplified RE for this; just checks that the line ends with version
# predicates in ()
_VERSION_SPEC_RE = re.compile(r'\s*(.*?)\s*\((.*)\)\s*$')


# Mappings from setup() keyword arguments to setup.cfg options;
# The values are (section, option) tuples, or simply (section,) tuples if
# the option has the same name as the setup() argument
D1_D2_SETUP_ARGS = {
    "name": ("metadata",),
    "version": ("metadata",),
    "author": ("metadata",),
    "author_email": ("metadata",),
    "maintainer": ("metadata",),
    "maintainer_email": ("metadata",),
    "url": ("metadata", "home_page"),
    "project_urls": ("metadata",),
    "description": ("metadata", "summary"),
    "keywords": ("metadata",),
    "long_description": ("metadata", "description"),
    "long_description_content_type": ("metadata", "description_content_type"),
    "download_url": ("metadata",),
    "classifiers": ("metadata", "classifier"),
    "platforms": ("metadata", "platform"),  # **
    "license": ("metadata",),
    # Use setuptools install_requires, not
    # broken distutils requires
    "install_requires": ("metadata", "requires_dist"),
    "setup_requires": ("metadata", "setup_requires_dist"),
    "python_requires": ("metadata",),
    "provides": ("metadata", "provides_dist"),  # **
    "provides_extras": ("metadata",),
    "obsoletes": ("metadata", "obsoletes_dist"),  # **
    "package_dir": ("files", 'packages_root'),
    "packages": ("files",),
    "package_data": ("files",),
    "namespace_packages": ("files",),
    "data_files": ("files",),
    "scripts": ("files",),
    "py_modules": ("files", "modules"),   # **
    "cmdclass": ("global", "commands"),
    # Not supported in distutils2, but provided for
    # backwards compatibility with setuptools
    "use_2to3": ("backwards_compat", "use_2to3"),
    "zip_safe": ("backwards_compat", "zip_safe"),
    "tests_require": ("backwards_compat", "tests_require"),
    "dependency_links": ("backwards_compat",),
    "include_package_data": ("backwards_compat",),
}

# setup() arguments that can have multiple values in setup.cfg
MULTI_FIELDS = ("classifiers",
                "platforms",
                "install_requires",
                "provides",
                "obsoletes",
                "namespace_packages",
                "packages",
                "package_data",
                "data_files",
                "scripts",
                "py_modules",
                "dependency_links",
                "setup_requires",
                "tests_require",
                "keywords",
                "cmdclass",
                "provides_extras")

# setup() arguments that can have mapping values in setup.cfg
MAP_FIELDS = ("project_urls",)

# setup() arguments that contain boolean values
BOOL_FIELDS = ("use_2to3", "zip_safe", "include_package_data")

CSV_FIELDS = ()


def shlex_split(path):
    if os.name == 'nt':
        # shlex cannot handle paths that contain backslashes, treating those
        # as escape characters.
        path = path.replace("\\", "/")
        return [x.replace("/", "\\") for x in shlex.split(path)]

    return shlex.split(path)


def resolve_name(name):
    """Resolve a name like ``module.object`` to an object and return it.

    Raise ImportError if the module or name is not found.
    """

    parts = name.split('.')
    cursor = len(parts) - 1
    module_name = parts[:cursor]
    attr_name = parts[-1]

    while cursor > 0:
        try:
            ret = __import__('.'.join(module_name), fromlist=[attr_name])
            break
        except ImportError:
            if cursor == 0:
                raise
            cursor -= 1
            module_name = parts[:cursor]
            attr_name = parts[cursor]
            ret = ''

    for part in parts[cursor:]:
        try:
            ret = getattr(ret, part)
        except AttributeError:
            raise ImportError(name)

    return ret


def cfg_to_args(path='setup.cfg', script_args=()):
    """Distutils2 to distutils1 compatibility util.

    This method uses an existing setup.cfg to generate a dictionary of
    keywords that can be used by distutils.core.setup(kwargs**).

    :param path:
        The setup.cfg path.
    :param script_args:
        List of commands setup.py was called with.
    :raises DistutilsFileError:
        When the setup.cfg file is not found.
    """

    # The method source code really starts here.
    if sys.version_info >= (3, 2):
            parser = configparser.ConfigParser()
    else:
            parser = configparser.SafeConfigParser()
    if not os.path.exists(path):
        raise errors.DistutilsFileError("file '%s' does not exist" %
                                        os.path.abspath(path))
    try:
        parser.read(path, encoding='utf-8')
    except TypeError:
        # Python 2 doesn't accept the encoding kwarg
        parser.read(path)
    config = {}
    for section in parser.sections():
        config[section] = dict()
        for k, value in parser.items(section):
            config[section][k.replace('-', '_')] = value

    # Run setup_hooks, if configured
    setup_hooks = has_get_option(config, 'global', 'setup_hooks')
    package_dir = has_get_option(config, 'files', 'packages_root')

    # Add the source package directory to sys.path in case it contains
    # additional hooks, and to make sure it's on the path before any existing
    # installations of the package
    if package_dir:
        package_dir = os.path.abspath(package_dir)
        sys.path.insert(0, package_dir)

    try:
        if setup_hooks:
            setup_hooks = [
                hook for hook in split_multiline(setup_hooks)
                if hook != 'pbr.hooks.setup_hook']
            for hook in setup_hooks:
                hook_fn = resolve_name(hook)
                try:
                    hook_fn(config)
                except SystemExit:
                    log.error('setup hook %s terminated the installation')
                except Exception:
                    e = sys.exc_info()[1]
                    log.error('setup hook %s raised exception: %s\n' %
                              (hook, e))
                    log.error(traceback.format_exc())
                    sys.exit(1)

        # Run the pbr hook
        pbr.hooks.setup_hook(config)

        kwargs = setup_cfg_to_setup_kwargs(config, script_args)

        # Set default config overrides
        kwargs['include_package_data'] = True
        kwargs['zip_safe'] = False

        register_custom_compilers(config)

        ext_modules = get_extension_modules(config)
        if ext_modules:
            kwargs['ext_modules'] = ext_modules

        entry_points = get_entry_points(config)
        if entry_points:
            kwargs['entry_points'] = entry_points

        # Handle the [files]/extra_files option
        files_extra_files = has_get_option(config, 'files', 'extra_files')
        if files_extra_files:
            extra_files.set_extra_files(split_multiline(files_extra_files))

    finally:
        # Perform cleanup if any paths were added to sys.path
        if package_dir:
            sys.path.pop(0)

    return kwargs


def setup_cfg_to_setup_kwargs(config, script_args=()):
    """Convert config options to kwargs.

    Processes the setup.cfg options and converts them to arguments accepted
    by setuptools' setup() function.
    """

    kwargs = {}

    # Temporarily holds install_requires and extra_requires while we
    # parse env_markers.
    all_requirements = {}

    for arg in D1_D2_SETUP_ARGS:
        if len(D1_D2_SETUP_ARGS[arg]) == 2:
            # The distutils field name is different than distutils2's.
            section, option = D1_D2_SETUP_ARGS[arg]

        elif len(D1_D2_SETUP_ARGS[arg]) == 1:
            # The distutils field name is the same thant distutils2's.
            section = D1_D2_SETUP_ARGS[arg][0]
            option = arg

        in_cfg_value = has_get_option(config, section, option)
        if not in_cfg_value:
            # There is no such option in the setup.cfg
            if arg == "long_description":
                in_cfg_value = has_get_option(config, section,
                                              "description_file")
                if in_cfg_value:
                    in_cfg_value = split_multiline(in_cfg_value)
                    value = ''
                    for filename in in_cfg_value:
                        description_file = io.open(filename, encoding='utf-8')
                        try:
                            value += description_file.read().strip() + '\n\n'
                        finally:
                            description_file.close()
                    in_cfg_value = value
            else:
                continue

        if arg in CSV_FIELDS:
            in_cfg_value = split_csv(in_cfg_value)
        if arg in MULTI_FIELDS:
            in_cfg_value = split_multiline(in_cfg_value)
        elif arg in MAP_FIELDS:
            in_cfg_map = {}
            for i in split_multiline(in_cfg_value):
                k, v = i.split('=', 1)
                in_cfg_map[k.strip()] = v.strip()
            in_cfg_value = in_cfg_map
        elif arg in BOOL_FIELDS:
            # Provide some flexibility here...
            if in_cfg_value.lower() in ('true', 't', '1', 'yes', 'y'):
                in_cfg_value = True
            else:
                in_cfg_value = False

        if in_cfg_value:
            if arg in ('install_requires', 'tests_require'):
                # Replaces PEP345-style version specs with the sort expected by
                # setuptools
                in_cfg_value = [_VERSION_SPEC_RE.sub(r'\1\2', pred)
                                for pred in in_cfg_value]
            if arg == 'install_requires':
                # Split install_requires into package,env_marker tuples
                # These will be re-assembled later
                install_requires = []
                requirement_pattern = (
                    r'(?P<package>[^;]*);?(?P<env_marker>[^#]*?)(?:\s*#.*)?$')
                for requirement in in_cfg_value:
                    m = re.match(requirement_pattern, requirement)
                    requirement_package = m.group('package').strip()
                    env_marker = m.group('env_marker').strip()
                    install_requires.append((requirement_package, env_marker))
                all_requirements[''] = install_requires
            elif arg == 'package_dir':
                in_cfg_value = {'': in_cfg_value}
            elif arg in ('package_data', 'data_files'):
                data_files = {}
                firstline = True
                prev = None
                for line in in_cfg_value:
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key_unquoted = shlex_split(key.strip())[0]
                        key, value = (key_unquoted, value.strip())
                        if key in data_files:
                            # Multiple duplicates of the same package name;
                            # this is for backwards compatibility of the old
                            # format prior to d2to1 0.2.6.
                            prev = data_files[key]
                            prev.extend(shlex_split(value))
                        else:
                            prev = data_files[key.strip()] = shlex_split(value)
                    elif firstline:
                        raise errors.DistutilsOptionError(
                            'malformed package_data first line %r (misses '
                            '"=")' % line)
                    else:
                        prev.extend(shlex_split(line.strip()))
                    firstline = False
                if arg == 'data_files':
                    # the data_files value is a pointlessly different structure
                    # from the package_data value
                    data_files = data_files.items()
                in_cfg_value = data_files
            elif arg == 'cmdclass':
                cmdclass = {}
                dist = st_dist.Distribution()
                for cls_name in in_cfg_value:
                    cls = resolve_name(cls_name)
                    cmd = cls(dist)
                    cmdclass[cmd.get_command_name()] = cls
                in_cfg_value = cmdclass

        kwargs[arg] = in_cfg_value

    # Transform requirements with embedded environment markers to
    # setuptools' supported marker-per-requirement format.
    #
    # install_requires are treated as a special case of extras, before
    # being put back in the expected place
    #
    # fred =
    #     foo:marker
    #     bar
    # -> {'fred': ['bar'], 'fred:marker':['foo']}

    if 'extras' in config:
        requirement_pattern = (
            r'(?P<package>[^:]*):?(?P<env_marker>[^#]*?)(?:\s*#.*)?$')
        extras = config['extras']
        # Add contents of test-requirements, if any, into an extra named
        # 'test' if one does not already exist.
        if 'test' not in extras:
            from pbr import packaging
            extras['test'] = "\n".join(packaging.parse_requirements(
                packaging.TEST_REQUIREMENTS_FILES)).replace(';', ':')

        for extra in extras:
            extra_requirements = []
            requirements = split_multiline(extras[extra])
            for requirement in requirements:
                m = re.match(requirement_pattern, requirement)
                extras_value = m.group('package').strip()
                env_marker = m.group('env_marker')
                extra_requirements.append((extras_value, env_marker))
            all_requirements[extra] = extra_requirements

    # Transform the full list of requirements into:
    # - install_requires, for those that have no extra and no
    #   env_marker
    # - named extras, for those with an extra name (which may include
    #   an env_marker)
    # - and as a special case, install_requires with an env_marker are
    #   treated as named extras where the name is the empty string

    extras_require = {}
    for req_group in all_requirements:
        for requirement, env_marker in all_requirements[req_group]:
            if env_marker:
                extras_key = '%s:(%s)' % (req_group, env_marker)
                # We do not want to poison wheel creation with locally
                # evaluated markers.  sdists always re-create the egg_info
                # and as such do not need guarded, and pip will never call
                # multiple setup.py commands at once.
                if 'bdist_wheel' not in script_args:
                    try:
                        if pkg_resources.evaluate_marker('(%s)' % env_marker):
                            extras_key = req_group
                    except SyntaxError:
                        log.error(
                            "Marker evaluation failed, see the following "
                            "error.  For more information see: "
                            "http://docs.openstack.org/"
                            "pbr/latest/user/using.html#environment-markers"
                        )
                        raise
            else:
                extras_key = req_group
            extras_require.setdefault(extras_key, []).append(requirement)

    kwargs['install_requires'] = extras_require.pop('', [])
    kwargs['extras_require'] = extras_require

    return kwargs


def register_custom_compilers(config):
    """Handle custom compilers.

    This has no real equivalent in distutils, where additional compilers could
    only be added programmatically, so we have to hack it in somehow.
    """

    compilers = has_get_option(config, 'global', 'compilers')
    if compilers:
        compilers = split_multiline(compilers)
        for compiler in compilers:
            compiler = resolve_name(compiler)

            # In distutils2 compilers these class attributes exist; for
            # distutils1 we just have to make something up
            if hasattr(compiler, 'name'):
                name = compiler.name
            else:
                name = compiler.__name__
            if hasattr(compiler, 'description'):
                desc = compiler.description
            else:
                desc = 'custom compiler %s' % name

            module_name = compiler.__module__
            # Note; this *will* override built in compilers with the same name
            # TODO(embray): Maybe display a warning about this?
            cc = distutils.ccompiler.compiler_class
            cc[name] = (module_name, compiler.__name__, desc)

            # HACK!!!!  Distutils assumes all compiler modules are in the
            # distutils package
            sys.modules['distutils.' + module_name] = sys.modules[module_name]


def get_extension_modules(config):
    """Handle extension modules"""

    EXTENSION_FIELDS = ("sources",
                        "include_dirs",
                        "define_macros",
                        "undef_macros",
                        "library_dirs",
                        "libraries",
                        "runtime_library_dirs",
                        "extra_objects",
                        "extra_compile_args",
                        "extra_link_args",
                        "export_symbols",
                        "swig_opts",
                        "depends")

    ext_modules = []
    for section in config:
        if ':' in section:
            labels = section.split(':', 1)
        else:
            # Backwards compatibility for old syntax; don't use this though
            labels = section.split('=', 1)
        labels = [l.strip() for l in labels]
        if (len(labels) == 2) and (labels[0] == 'extension'):
            ext_args = {}
            for field in EXTENSION_FIELDS:
                value = has_get_option(config, section, field)
                # All extension module options besides name can have multiple
                # values
                if not value:
                    continue
                value = split_multiline(value)
                if field == 'define_macros':
                    macros = []
                    for macro in value:
                        macro = macro.split('=', 1)
                        if len(macro) == 1:
                            macro = (macro[0].strip(), None)
                        else:
                            macro = (macro[0].strip(), macro[1].strip())
                        macros.append(macro)
                    value = macros
                ext_args[field] = value
            if ext_args:
                if 'name' not in ext_args:
                    ext_args['name'] = labels[1]
                ext_modules.append(extension.Extension(ext_args.pop('name'),
                                                       **ext_args))
    return ext_modules


def get_entry_points(config):
    """Process the [entry_points] section of setup.cfg.

    Processes setup.cfg to handle setuptools entry points. This is, of course,
    not a standard feature of distutils2/packaging, but as there is not
    currently a standard alternative in packaging, we provide support for them.
    """

    if 'entry_points' not in config:
        return {}

    return dict((option, split_multiline(value))
                for option, value in config['entry_points'].items())


def has_get_option(config, section, option):
    if section in config and option in config[section]:
        return config[section][option]
    else:
        return False


def split_multiline(value):
    """Special behaviour when we have a multi line options"""

    value = [element for element in
             (line.strip() for line in value.split('\n'))
             if element and not element.startswith('#')]
    return value


def split_csv(value):
    """Special behaviour when we have a comma separated options"""

    value = [element for element in
             (chunk.strip() for chunk in value.split(','))
             if element]
    return value


# The following classes are used to hack Distribution.command_options a bit
class DefaultGetDict(defaultdict):
    """Like defaultdict, but get() also sets and returns the default value."""

    def get(self, key, default=None):
        if default is None:
            default = self.default_factory()
        return super(DefaultGetDict, self).setdefault(key, default)
