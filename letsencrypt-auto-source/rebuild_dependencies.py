#!/usr/bin/env python
"""
Gather and consolidate the up-to-date dependencies available and required to install certbot
on various Linux distributions. It generates a requirements file contained the pinned and hashed
versions, ready to be used by pip to install the certbot dependencies.

This script is typically used to update the certbot-requirements.txt file of certbot-auto.

To achieve its purpose, this script will start a certbot installation with unpinned dependencies,
then gather them, on various distributions started as Docker containers.

Usage: letsencrypt-auto-source/rebuild_dependencies new_requirements.txt

NB1: Docker must be installed on the machine running this script.
NB2: Python library 'hashin' must be installed on the machine running this script.
"""
from __future__ import print_function
import re
import shutil
import subprocess
import tempfile
import os
import sys
import argparse

# The list of docker distributions to test dependencies against with.
DISTRIBUTION_LIST = [
    'ubuntu:18.04', 'ubuntu:14.04',
    'debian:stretch', 'debian:jessie',
    'centos:7', 'centos:6',
    'opensuse/leap:15',
    'fedora:29',
]

# Theses constraints will be added while gathering dependencies on each distribution.
# It can be used because a particular version for a package is required for any reason,
# or to solve a version conflict between two distributions requirements.
AUTHORITATIVE_CONSTRAINTS = {
    # Using an older version of mock here prevents regressions of #5276.
    'mock': '1.3.0'
}


# ./certbot/letsencrypt-auto-source/rebuild_dependencies.py (2 levels from certbot root path)
CERTBOT_REPO_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(CERTBOT_REPO_PATH)

# The script will be used to gathering dependencies for a given distribution.
#   - certbot-auto is used to install relevant OS packages, and setup an initial venv
#   - then this venv is used to consistently construct an empty new venv
#   - once pipstraped, this new venv pip install certbot runtime (including apache/nginx),
#     without pinned dependencies, and in respect with input authoritative requirements
#   - `certbot plugins` is called to check we have an healthy environment
#   - finally current set of dependencies is extracted out of the docker using pip freeze
SCRIPT = """\
#!/bin/sh
set -e

cd /tmp/certbot
letsencrypt-auto-source/letsencrypt-auto --install-only -n
PYVER=`/opt/eff.org/certbot/venv/bin/python --version 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//'`

/opt/eff.org/certbot/venv/bin/python letsencrypt-auto-source/pieces/create_venv.py /tmp/venv "$PYVER" "1"

/tmp/venv/bin/python letsencrypt-auto-source/pieces/pipstrap.py
/tmp/venv/bin/pip install -e acme -e . -e certbot-apache -e certbot-nginx -c /tmp/requirements.txt
/tmp/venv/bin/certbot plugins
/tmp/venv/bin/pip freeze >> /tmp/workspace/results
"""


def _process_one_distribution(distribution, verbose):
    print('===> Gathering dependencies for {0}.'.format(distribution))
    workspace = tempfile.mkdtemp()
    script = os.path.join(workspace, 'script.sh')
    authoritative_requirements = os.path.join(workspace, 'requirements.txt')

    try:
        with open(script, 'w') as file_h:
            file_h.write(SCRIPT)
        os.chmod(script, 0o755)

        with open(authoritative_requirements, 'w') as file_h:
            file_h.write('\n'.join(['{0}=={1}'.format(package, version)
                                    for package, version in AUTHORITATIVE_CONSTRAINTS.items()]))

        command = ['docker', 'run', '--rm',
                   '-v', '{0}:/tmp/certbot'.format(CERTBOT_REPO_PATH),
                   '-v', '{0}:/tmp/workspace'.format(workspace),
                   '-v', '{0}:/tmp/requirements.txt'.format(authoritative_requirements),
                   distribution, '/tmp/workspace/script.sh']
        sub_stdout = sys.stdout if verbose else subprocess.PIPE
        sub_stderr = sys.stderr if verbose else subprocess.STDOUT
        process = subprocess.Popen(command, stdout=sub_stdout, stderr=sub_stderr, universal_newlines=True)
        stdoutdata, _ = process.communicate()

        if process.returncode:
            if stdoutdata:
                sys.stderr.write('Output was:\n{0}'.format(stdoutdata))
            raise RuntimeError('Error while gathering dependencies for {0}.'.format(distribution))

        with open(os.path.join(workspace, 'results'), 'r') as file_h:
            return file_h.read()
    finally:
        shutil.rmtree(workspace)


def _insert_results(dependencies_map, results, distribution):
    refined_results = []
    for result in results.split(os.linesep):
        match = re.match(r'(.*)==(.*)', result)
        if match:
            package = match.group(1)
            version = match.group(2)
            if not any(dep in package for dep in ['acme', 'certbot', 'pkg-resources']):
                dependencies_map.setdefault(package, []).append((version, distribution))

    return refined_results


def _process_dependency_map(dependency_map):
    print('===> Processing the dependency map.')
    requirements = []
    conflicts = []
    for package, versions in dependency_map.items():
        reduced_versions = _reduce_versions(versions)

        if len(reduced_versions) > 1:
            version_list = ['{0} ({1})'.format(version, ','.join(distributions))
                            for version, distributions in reduced_versions.items()]
            conflict = ('package {0} is declared with several versions: {1}'
                        .format(package, ', '.join(version_list)))
            conflicts.append(conflict)
            sys.stderr.write('ERROR: {0}\n'.format(conflict))
        else:
            requirements.append((package, list(reduced_versions)[0]))

    requirements.sort(key=lambda x: x[0])
    return requirements, conflicts


def _reduce_versions(versions):
    version_map = {}
    for version in versions:
        version_map.setdefault(version[0], []).append(version[1])

    return version_map


def _write_requirements(dest_file, requirements, conflicts):
    print('===> Calculating hashes for the requirement file.')
    if os.path.exists(dest_file):
        os.remove(dest_file)

    with open(dest_file, 'w') as file_h:
        file_h.write('''\
# This is the flattened list of packages certbot-auto installs.
# To generate this, do (with docker and package hashin installed):
# ```
# letsencrypt-auto-source/rebuild_dependencies.py \\
#   letsencrypt-auto-sources/pieces/dependency-requirements.txt
# ```
''')
    for req in requirements:
        subprocess.check_call(['hashin', '{0}=={1}'.format(req[0], req[1]),
                               '--requirements-file', dest_file])

    if conflicts:
        with open(dest_file, 'a') as file_h:
            file_h.write('\n## ! SOME ERRORS OCCURRED ! ##\n')
            file_h.write('\n'.join('# {0}'.format(conflict) for conflict in conflicts))
            file_h.write('\n')

    with open(dest_file, 'r') as file_h:
        print(file_h.read())


def _gather_dependencies(dest_file, verbose):
    dependencies_map = {}

    for distribution in DISTRIBUTION_LIST:
        results = _process_one_distribution(distribution, verbose)
        _insert_results(dependencies_map, results, distribution)

    requirements, conflicts = _process_dependency_map(dependencies_map)

    _write_requirements(dest_file, requirements, conflicts)

    dest_file_abs = dest_file if os.path.isabs(dest_file) else os.path.abspath(dest_file)
    print('===> Rebuilt requirement file is available on path {0}'.format(dest_file_abs))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=('Build a sanitized, pinned and hashed requirements file for certbot-auto, '
                     'validated against several OS distributions using Docker.'))
    parser.add_argument('requirements_path',
                        help='path for the generated requirements file')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='verbose will display all output during docker execution')

    namespace = parser.parse_args()

    try:
        subprocess.check_call(['hashin', '--version'])
    except subprocess.CalledProcessError:
        raise RuntimeError('Python library hashin is not installed in the current environment.')

    try:
        subprocess.check_call(['docker', '--version'])
    except subprocess.CalledProcessError:
        raise RuntimeError('Docker is not installed or accessible to current user.')

    _gather_dependencies(namespace.requirements_file, namespace.verbose)
