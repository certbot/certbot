#!/usr/bin/env python3
"""
Gather and consolidate the up-to-date dependencies available and required to install certbot
on various Linux distributions. It generates a requirements file contained the pinned and hashed
versions, ready to be used by pip to install the certbot dependencies.

This script is typically used to update the certbot-requirements.txt file of certbot-auto.

To achieve its purpose, this script will start a certbot installation with unpinned dependencies,
then gather them, on various distributions started as Docker containers.

Usage: letsencrypt-auto-source/rebuild_dependencies new_requirements.txt

NB1: This script must be run from certbot GIT root path.
NB2: Docker must be installed on the machine running this script.
NB3: Python library 'hashin' must be installed on the machine running this script.
"""
import re
import shutil
import subprocess
import tempfile
import os
import sys

# Library hashin is not used as a module in this script, but this import is
# useful to fail fast the script if it is not installed.
import hashin

DISTRIBUTION_LIST = [
    'ubuntu:18.04', 'ubuntu:14.04',
    'debian:stretch', 'debian:jessie',
    'centos:7', 'centos:6',
    'opensuse/leap:15',
    'fedora:29',
]

CERTBOT_REPO_PATH = os.getcwd()

SCRIPT = """\
#!/bin/sh
set -e

cd /tmp/certbot
letsencrypt-auto-source/letsencrypt-auto --install-only -n
PYVER=`/opt/eff.org/certbot/venv/bin/python --version 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//'`

/opt/eff.org/certbot/venv/bin/python letsencrypt-auto-source/pieces/create_venv.py /tmp/venv "$PYVER" "1"

/tmp/venv/bin/python letsencrypt-auto-source/pieces/pipstrap.py
/tmp/venv/bin/pip install -e acme -e . -e certbot-apache -e certbot-nginx
/tmp/venv/bin/certbot --version
/tmp/venv/bin/pip freeze >> /tmp/workspace/results
"""

OUTPUT_HEADER = """\
# This is the flattened list of packages certbot-auto installs.
# To generate this, do (with docker and package hashin installed):
# ```
# letsencrypt-auto-source/rebuild_dependencies.py \
#   letsencrypt-auto-sources/pieces/dependency-requirements.txt
# ```
"""

DEPENDENCY_PATTERN = r'(.*)==(.*)'


def process_one_distribution(distribution):
    print('===> Gathering dependencies for {0}.'.format(distribution))
    workspace = tempfile.mkdtemp()
    script = os.path.join(workspace, 'script.sh')
    try:
        with open(script, 'w') as file_handler:
            file_handler.write(SCRIPT)
        os.chmod(script, 0o755)
        command = ['docker', 'run', '--rm', '-v', '{0}:/tmp/certbot'.format(CERTBOT_REPO_PATH),
                   '-v', '{0}:/tmp/workspace'.format(workspace), distribution, '/tmp/workspace/script.sh']
        subprocess.check_output(command, stderr=subprocess.STDOUT)
        with open(os.path.join(workspace, 'results'), 'r') as file_handler:
            return file_handler.read()
    except subprocess.CalledProcessError as error:
        sys.stderr.write('Error while gathering dependencies for {0}.\n'.format(distribution))
        sys.stderr.write('Output was:\n')
        sys.stderr.write(error.output)
    finally:
        shutil.rmtree(workspace)


def insert_results(dependencies_map, results, distribution):
    refined_results = []
    for result in results.split(os.linesep):
        match = re.match(DEPENDENCY_PATTERN, result)
        if match:
            package = match.group(1)
            version = match.group(2)
            if not ('acme' in package or 'certbot' in package):
                dependencies_map.setdefault(package, []).append((version, distribution))

    return refined_results


def process_dependency_map(dependency_map):
    print('===> Processing the dependency map.')
    requirements = []
    conflicts = []
    for package, versions in dependency_map.items():
        reduced_versions = reduce_versions(versions)

        if len(reduced_versions) > 1:
            version_list = ['{0} ({1})'.format(version, ','.join(distributions)) for version, distributions in reduced_versions.items()]
            conflict = 'package {0} is declared with several versions: {1}'.format(package, ', '.join(version_list))
            conflicts.append(conflict)
            sys.stderr.write('ERROR: {0}\n'.format(conflict))
        else:
            requirements.append((package, list(reduced_versions)[0]))

    requirements.sort(key=lambda x: x[0])
    return requirements, conflicts


def reduce_versions(versions):
    version_map = {}
    for version in versions:
        version_map.setdefault(version[0], []).append(version[1])

    return version_map


def write_requirements(dest_file, requirements, conflicts):
    print('===> Calculating hashes for the requirement file.')
    if os.path.exists(dest_file):
        os.remove(dest_file)

    with open(dest_file, 'w') as file_handler:
        file_handler.write(OUTPUT_HEADER)
    for req in requirements:
        subprocess.check_call(['hashin', '{0}=={1}'.format(req[0], req[1]), '--requirements-file', dest_file])

    if conflicts:
        with open(dest_file, 'a') as file_handler:
            file_handler.write('\n## ! SOME ERRORS OCCURRED WHILE REBUILDING THE REQUIREMENT FILE ! ##\n')
            file_handler.write('\n'.join('# {0}'.format(conflict) for conflict in conflicts))
            file_handler.write('\n')

    with open(dest_file, 'r') as file_handler:
        print(file_handler.read())


def main(dest_file):
    dependencies_map = {}

    for distribution in DISTRIBUTION_LIST:
        results = process_one_distribution(distribution)
        insert_results(dependencies_map, results, distribution)

    requirements, conflicts = process_dependency_map(dependencies_map)

    write_requirements(dest_file, requirements, conflicts)

    dest_file_abs = dest_file if os.path.isabs(dest_file) else os.path.abspath(dest_file)
    print('===> Rebuilt requirement file is available on path {0}'.format(dest_file_abs))



if __name__ == '__main__':
    try:
        destination_file = sys.argv[1]
    except IndexError:
        raise AttributeError('No destination requirement file provided to the command line.')
    main(destination_file)
