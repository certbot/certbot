#!/usr/bin/env python
"""
Gather and consolidate the up-to-date dependencies available and required to install certbot
on various Linux distributions. It generates a requirements file contained the pinned and hashed
versions, ready to be used by pip to install the certbot dependencies.

This script is typically used to update the certbot_requirements.txt file.

To achieve its purpose, this script will start a certbot installation with unpinned dependencies,
then gather them, on various distributions started as Docker containers.

Usage: tools/rebuild_certbot_requirements.py new_requirements.txt

NB1: Docker must be installed on the machine running this script.
NB2: Python library 'hashin' must be installed on the machine running this script.
"""
from __future__ import print_function
import re
import shutil
import subprocess
import tempfile
import os
from os.path import dirname, abspath, join
import sys
import argparse

# The list of docker distributions to test dependencies against with.
DISTRIBUTION_LIST = [
    'ubuntu:20.04', 'ubuntu:18.04', 'debian:buster',
    'centos:8', 'centos:7', 'fedora:29',
]

# These constraints will be added while gathering dependencies on each distribution.
# It can be used because a particular version for a package is required for any reason,
# or to solve a version conflict between two distributions requirements.
AUTHORITATIVE_CONSTRAINTS = {
    # Too touchy to move to a new version. And will be removed soon
    # in favor of pure python parser for Apache.
    'python-augeas': '0.5.0',
    # We avoid cryptography 3.4+ since it requires Rust to compile the wheels, and
    # this needs some work on the snap builds.
    'cryptography': '3.3.2',
}

# ./certbot/tools/rebuild_certbot_requirements.py (2 levels from certbot root path)
CERTBOT_REPO_PATH = dirname(dirname(abspath(__file__)))

# The script will be used to gather dependencies for a given distribution.
#   - bootstrap_os_packages.sh is used to install relevant OS packages, and set up an initial venv
#   - then this venv is used to consistently construct an empty new venv
#   - once pipstrap.py, this new venv pip-installs certbot runtime (including apache/nginx),
#     without pinned dependencies, and respecting input authoritative requirements
#   - `certbot plugins` is called to check we have a healthy environment
#   - finally current set of dependencies is extracted out of the docker using pip freeze
SCRIPT = r"""#!/bin/sh
set -ex

cd /tmp/certbot
tests/letstest/scripts/bootstrap_os_packages.sh

python3 -m venv /tmp/venv

/tmp/venv/bin/python tools/pipstrap.py
/tmp/venv/bin/pip install -e acme -e certbot -e certbot-apache -e certbot-nginx -c /tmp/constraints.txt
/tmp/venv/bin/certbot plugins
/tmp/venv/bin/pip freeze >> /tmp/workspace/requirements.txt
"""


def _read_from(file):
    """Read all content of the file, and return it as a string."""
    with open(file, 'r') as file_h:
        return file_h.read()


def _write_to(file, content):
    """Write given string content to the file, overwriting its initial content."""
    with open(file, 'w') as file_h:
        file_h.write(content)


def _requirements_from_one_distribution(distribution, verbose):
    """
    Calculate the Certbot dependencies expressed for the given distribution, using the official
    Docker for this distribution, and return the lines of the generated requirements file.
    """
    print('===> Gathering dependencies for {0}.'.format(distribution))
    workspace = tempfile.mkdtemp()
    script = join(workspace, 'script.sh')
    authoritative_constraints = join(workspace, 'constraints.txt')
    cid_file = join(workspace, 'cid')

    try:
        _write_to(script, SCRIPT)
        os.chmod(script, 0o755)

        _write_to(authoritative_constraints, '\n'.join(
            '{0}=={1}'.format(package, version) for package, version in AUTHORITATIVE_CONSTRAINTS.items()))

        command = ['docker', 'run', '--rm', '--cidfile', cid_file,
                   '--network=host',
                   '-v', '{0}:/tmp/certbot'.format(CERTBOT_REPO_PATH),
                   '-v', '{0}:/tmp/workspace'.format(workspace),
                   '-v', '{0}:/tmp/constraints.txt'.format(authoritative_constraints),
                   distribution, '/tmp/workspace/script.sh']
        sub_stdout = sys.stdout if verbose else subprocess.PIPE
        sub_stderr = sys.stderr if verbose else subprocess.STDOUT
        process = subprocess.Popen(command, stdout=sub_stdout, stderr=sub_stderr, universal_newlines=True)
        stdoutdata, _ = process.communicate()

        if process.returncode:
            if stdoutdata:
                sys.stderr.write('Output was:\n{0}'.format(stdoutdata))
            raise RuntimeError('Error while gathering dependencies for {0}.'.format(distribution))

        with open(join(workspace, 'requirements.txt'), 'r') as file_h:
            return file_h.readlines()
    finally:
        if os.path.isfile(cid_file):
            cid = _read_from(cid_file)
            try:
                subprocess.check_output(['docker', 'kill', cid], stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                pass
        shutil.rmtree(workspace)


def _parse_and_merge_requirements(dependencies_map, requirements_file_lines, distribution):
    """
    Extract every requirement from the given requirements file, and merge it in the dependency map.
    Merging here means that the map contain every encountered dependency, and the version used in
    each distribution.

    Example:
    # dependencies_map = {
    # }
    _parse_and_merge_requirements(['cryptography=='1.2','requests=='2.1.0'], dependencies_map, 'debian:stretch')
    # dependencies_map = {
    #   'cryptography': [('1.2', 'debian:stretch)],
    #   'requests': [('2.1.0', 'debian:stretch')]
    # }
    _parse_and_merge_requirements(['requests=='2.4.0', 'mock==1.3'], dependencies_map, 'centos:7')
    # dependencies_map = {
    #   'cryptography': [('1.2', 'debian:stretch)],
    #   'requests': [('2.1.0', 'debian:stretch'), ('2.4.0', 'centos:7')],
    #   'mock': [('2.4.0', 'centos:7')]
    # }
    """
    for line in requirements_file_lines:
        match = re.match(r'([^=]+)==([^=]+)', line.strip())
        if not line.startswith('-e') and not line.startswith('#') and match:
            package, version = match.groups()
            if package not in ['acme', 'certbot', 'certbot-apache', 'certbot-nginx', 'pkg-resources']:
                dependencies_map.setdefault(package, []).append((version, distribution))


def _consolidate_and_validate_dependencies(dependency_map):
    """
    Given the dependency map of all requirements found in all distributions for Certbot,
    construct an array containing the unit requirements for Certbot to be used by pip,
    and the version conflicts, if any, between several distributions for a package.
    Return requirements and conflicts as a tuple.
    """
    print('===> Consolidate and validate the dependency map.')
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


def _reduce_versions(version_dist_tuples):
    """
    Get an array of version/distribution tuples,
    and reduce it to a map based on the version values.

    Example: [('1.2.0', 'debian:stretch'), ('1.4.0', 'ubuntu:18.04'), ('1.2.0', 'centos:6')]
              => {'1.2.0': ['debiqn:stretch', 'centos:6'], '1.4.0': ['ubuntu:18.04']}
    """
    version_dist_map = {}
    for version, distribution in version_dist_tuples:
        version_dist_map.setdefault(version, []).append(distribution)

    return version_dist_map


def _write_requirements(dest_file, requirements, conflicts):
    """
    Given the list of requirements and conflicts, write a well-formatted requirements file,
    whose requirements are hashed signed using hashin library. Conflicts are written at the end
    of the generated file.
    """
    print('===> Calculating hashes for the requirement file.')

    _write_to(dest_file, '''\
# This is the flattened list of pinned packages to build certbot deployable artifacts.
# To generate this, do (with docker and package hashin installed):
# ```
# tools/rebuild_certbot_contraints.py \\
#   tools/certbot_requirements.txt
# ```
# If you want to update a single dependency, run commands similar to these:
# ```
# pip install hashin
# hashin -r dependency-requirements.txt cryptography==1.5.2
# ```
''')

    for req in requirements:
        if req[0] in AUTHORITATIVE_CONSTRAINTS:
            # If requirement is in AUTHORITATIVE_CONSTRAINTS, take its value instead of the
            # computed one to get any environment descriptor that would have been added.
            req = (req[0], AUTHORITATIVE_CONSTRAINTS[req[0]])
        subprocess.check_call(['hashin', '{0}=={1}'.format(req[0], req[1]),
                               '--requirements-file', dest_file])

    if conflicts:
        with open(dest_file, 'a') as file_h:
            file_h.write('\n## ! SOME ERRORS OCCURRED ! ##\n')
            file_h.write('\n'.join('# {0}'.format(conflict) for conflict in conflicts))
            file_h.write('\n')

    return _read_from(dest_file)


def _gather_dependencies(dest_file, verbose):
    """
    Main method of this script. Given a destination file path, will write the file
    containing the consolidated and hashed requirements for Certbot, validated
    against several Linux distributions.
    """
    dependencies_map = {}

    for distribution in DISTRIBUTION_LIST:
        requirements_file_lines = _requirements_from_one_distribution(distribution, verbose)
        _parse_and_merge_requirements(dependencies_map, requirements_file_lines, distribution)

    requirements, conflicts = _consolidate_and_validate_dependencies(dependencies_map)

    return _write_requirements(dest_file, requirements, conflicts)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=('Build a sanitized, pinned and hashed requirements file for certbot deployable'
                     ' artifacts, validated against several OS distributions using Docker.'))
    parser.add_argument('requirements_path',
                        help='path for the generated requirements file')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='verbose will display all output during docker execution')

    namespace = parser.parse_args()

    try:
        subprocess.check_output(['hashin', '--version'])
    except subprocess.CalledProcessError:
        raise RuntimeError('Python library hashin is not installed in the current environment.')

    try:
        subprocess.check_output(['docker', '--version'], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        raise RuntimeError('Docker is not installed or accessible to current user.')

    file_content = _gather_dependencies(namespace.requirements_path, namespace.verbose)

    print(file_content)
    print('===> Rebuilt requirement file is available on path {0}'
          .format(abspath(namespace.requirements_path)))
