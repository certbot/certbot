#!/usr/bin/env python
import re
import shutil
import subprocess
import tempfile
import os
import sys
import multiprocessing

TEST = [
    'asn1crypto==0.23.0\ncertifi==2018.11.29\ncffi==1.12.2\nchardet==3.0.4\nConfigArgParse==0.14.0\nconfigobj==5.0.6\ncryptography==2.6.1\nenum34==1.1.6\nfuncsigs==1.0.2\nfuture==0.17.1\nidna==2.8\nipaddress==1.0.22\njosepy==1.1.0\nmock==2.0.0\nparsedatetime==2.4\npbr==5.1.3\npycparser==2.19\npyOpenSSL==19.0.0\npyparsing==2.3.1\npyRFC3339==1.1\npython-augeas==1.0.3\npytz==2018.9\nrequests==2.21.0\nrequests-toolbelt==0.9.1\nsix==1.12.0\nurllib3==1.24.1\nzope.component==4.5\nzope.deferredimport==4.3\nzope.deprecation==4.4.0\nzope.event==4.4\nzope.hookable==4.2.0\nzope.interface==4.6.0\nzope.proxy==4.3.1\n',
    'asn1crypto==0.24.0\ncertifi==2018.11.29\ncffi==1.12.2\nchardet==3.0.4\nConfigArgParse==0.14.0\nconfigobj==5.0.6\ncryptography==2.6.1\nenum34==1.1.6\nfuncsigs==1.0.2\nfuture==0.17.1\nidna==2.8\nipaddress==1.0.22\njosepy==1.1.0\nmock==2.0.0\nparsedatetime==2.4\npbr==5.1.3\npycparser==2.19\npyOpenSSL==19.0.0\npyparsing==2.3.1\npyRFC3339==1.1\npython-augeas==1.0.3\npytz==2018.9\nrequests==2.21.0\nrequests-toolbelt==0.9.1\nsix==1.12.0\nurllib3==1.24.1\nzope.component==4.5\nzope.deferredimport==4.3\nzope.deprecation==4.4.0\nzope.event==4.4\nzope.hookable==4.2.0\nzope.interface==4.6.0\nzope.proxy==4.3.1\n'
]

IGNORE_PACKAGES = ['acme', 'certbot', 'cerbot-apache', 'certbot-nginx', 'pkg-resources']

# This script must be run from certbot root path
CERTBOT_REPO_PATH = os.getcwd()

DISTRIBUTION_LIST = [
    'ubuntu:18.04', 'centos:7', 'fedora:29'
]

SCRIPT = """\
#!/bin/sh
set -e

cd /tmp/certbot
letsencrypt-auto-source/letsencrypt-auto --install-only -n
PYVER=`/opt/eff.org/certbot/venv/bin/python --version 2>&1 | cut -d" " -f 2 | cut -d. -f1,2 | sed 's/\.//'`

/opt/eff.org/certbot/venv/bin/python letsencrypt-auto-source/pieces/create_venv.py /tmp/venv "$PYVER" "1"

/tmp/venv/bin/python letsencrypt-auto-source/pieces/pipstrap.py
/tmp/venv/bin/pip install certbot-nginx certbot-apache
/tmp/venv/bin/certbot --version
/tmp/venv/bin/pip freeze >> /tmp/workspace/results
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
        subprocess.check_call(command)
        with open(os.path.join(workspace, 'results'), 'r') as file_handler:
            return file_handler.read(), distribution
    finally:
        shutil.rmtree(workspace)


def insert_results(dependencies_map, results, distribution):
    refined_results = []
    for result in results.split(os.linesep):
        match = re.match(DEPENDENCY_PATTERN, result)
        if match and match.group(1) not in IGNORE_PACKAGES:
            dependencies_map.setdefault(match.group(1), []).append((match.group(2), distribution))

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
            requirements.append((package, reduced_versions.keys()[0]))

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
    open(dest_file, 'w').close()
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
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
    promises = [pool.apply_async(process_one_distribution, [distribution])
                for distribution in DISTRIBUTION_LIST]

    for promise in promises:
        data, distribution = promise.get()
        insert_results(dependencies_map, data, distribution)

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
