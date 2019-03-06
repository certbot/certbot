#!/usr/bin/env python

import logging
import re
import shutil
import subprocess
import tempfile
import os

TEST = [
    'asn1crypto==0.23.0\ncertifi==2018.11.29\ncffi==1.12.2\nchardet==3.0.4\nConfigArgParse==0.14.0\nconfigobj==5.0.6\ncryptography==2.6.1\nenum34==1.1.6\nfuncsigs==1.0.2\nfuture==0.17.1\nidna==2.8\nipaddress==1.0.22\njosepy==1.1.0\nmock==2.0.0\nparsedatetime==2.4\npbr==5.1.3\npycparser==2.19\npyOpenSSL==19.0.0\npyparsing==2.3.1\npyRFC3339==1.1\npython-augeas==1.0.3\npytz==2018.9\nrequests==2.21.0\nrequests-toolbelt==0.9.1\nsix==1.12.0\nurllib3==1.24.1\nzope.component==4.5\nzope.deferredimport==4.3\nzope.deprecation==4.4.0\nzope.event==4.4\nzope.hookable==4.2.0\nzope.interface==4.6.0\nzope.proxy==4.3.1\n',
    'asn1crypto==0.24.0\ncertifi==2018.11.29\ncffi==1.12.2\nchardet==3.0.4\nConfigArgParse==0.14.0\nconfigobj==5.0.6\ncryptography==2.6.1\nenum34==1.1.6\nfuncsigs==1.0.2\nfuture==0.17.1\nidna==2.8\nipaddress==1.0.22\njosepy==1.1.0\nmock==2.0.0\nparsedatetime==2.4\npbr==5.1.3\npycparser==2.19\npyOpenSSL==19.0.0\npyparsing==2.3.1\npyRFC3339==1.1\npython-augeas==1.0.3\npytz==2018.9\nrequests==2.21.0\nrequests-toolbelt==0.9.1\nsix==1.12.0\nurllib3==1.24.1\nzope.component==4.5\nzope.deferredimport==4.3\nzope.deprecation==4.4.0\nzope.event==4.4\nzope.hookable==4.2.0\nzope.interface==4.6.0\nzope.proxy==4.3.1\n'
]

IGNORE_PACKAGES = ['acme', 'certbot', 'cerbot-apache', 'certbot-nginx', 'pkg-resources']

# This script must be run from certbot root path
CERTBOT_REPO_PATH = os.getcwd()

DISTRIBUTION_LIST = [
    'ubuntu:cosmic', 'centos:7'
]

SCRIPT = """\
#!/bin/sh

cd /tmp/certbot
letsencrypt-auto-source/letsencrypt-auto --os-packages-only -n

python2 letsencrypt-auto-source/pieces/create_venv.py /tmp/venv "27" "1"
/tmp/venv/bin/python letsencrypt-auto-source/pieces/pipstrap.py
/tmp/venv/bin/pip install certbot-nginx certbot-apache
/tmp/venv/bin/certbot --version
/tmp/venv/bin/pip freeze >> /tmp/workspace/results_2

#python3 letsencrypt-auto-source/pieces/create_venv.py /tmp/venv "37" "1"
#/tmp/venv3/bin/python letsencrypt-auto-source/pieces/pipstrap.py
#/tmp/venv3/bin/pip install certbot-nginx certbot-apache
#/tmp/venv3/bin/pip freeze >> /tmp/workspace/results_3
touch /tmp/workspace/results_3
"""

DEPENDENCY_PATTERN = r'(.*)==(.*)'


def process_one_distribution(distribution):
    workspace = tempfile.mkdtemp()
    script = os.path.join(workspace, 'script.sh')
    try:
        with open(script, 'w') as file_handler:
            file_handler.write(SCRIPT)
        with open(script, 'r') as file_handler:
            print(file_handler.read())
        os.chmod(script, 0o755)
        command = ['docker', 'run', '--rm', '-v', '{0}:/tmp/certbot'.format(CERTBOT_REPO_PATH),
                   '-v', '{0}:/tmp/workspace'.format(workspace), distribution, '/tmp/workspace/script.sh']
        subprocess.check_call(command)
        with open(os.path.join(workspace, 'results_2'), 'r') as file_handler_2:
            with open(os.path.join(workspace, 'results_3'), 'r') as file_handler_3:
                return file_handler_2.read(), file_handler_3.read()
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
    requirements = []
    conflicts = []
    for package, versions in dependency_map.items():
        reduced_versions = reduce_versions(versions)

        if len(reduced_versions) > 1:
            version_list = ['{0} ({1})'.format(version, ','.join(distributions)) for version, distributions in reduced_versions.items()]
            conflict = 'package {0} is declared with several versions: {1}'.format(package, ', '.join(version_list))
            conflicts.append(conflict)
        else:
            requirements.append((package, reduced_versions.keys()[0]))

    requirements.sort(key=lambda x: x[0])
    return requirements, conflicts


def reduce_versions(versions):
    version_map = {}
    for version in versions:
        version_map.setdefault(version[0], []).append(version[1])

    return version_map


def print_requirements(requirements, conflicts):
    temp_requirement = tempfile.mkstemp()[1]
    try:
        for req in requirements:
            subprocess.check_call(['hashin', '{0}=={1}'.format(req[0], req[1]), '--requirements-file', temp_requirement])

        if conflicts:
            with open(temp_requirement, 'a') as file_handler:
                file_handler.write('\n## ! SOME ERRORS OCCURRED ! ##\n')
                file_handler.write('\n'.join('# {0}'.format(conflict) for conflict in conflicts))

        with open(temp_requirement, 'r') as file_handler:
            print(file_handler.read())
    finally:
        os.remove(temp_requirement)


def main():
    dependencies_map = {}
    for index, distribution in enumerate(DISTRIBUTION_LIST):
        #results = process_one_distribution(distribution)
        results = (TEST[index], '')
        insert_results(dependencies_map, results[0], distribution)

    requirements, conflicts = process_dependency_map(dependencies_map)

    print_requirements(requirements, conflicts)


if __name__ == '__main__':
    main()
