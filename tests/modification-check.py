#!/usr/bin/env python

from __future__ import print_function

import os
import subprocess
import sys
import tempfile
import shutil
try:
    from urllib.request import urlretrieve
except ImportError:
    from urllib import urlretrieve

def find_repo_path(script_path):
    return os.path.dirname(os.path.realpath(script_path))

# We do not use filecmp.cmp to not be sensitive to CRLF/LF during comparison
def compare_files(path_1, path_2):
    l1 = l2 = True
    with open(path_1, 'r') as f1, open(path_2, 'r') as f2:
        while l1 and l2:
            l1 = f1.readline()
            l2 = f2.readline()
            if l1 != l2:
                return False

    return True

def validate_scripts_content(repo_path, temp_cwd):
    errors = False

    if not compare_files(
        os.path.join(repo_path, 'certbot-auto'),
        os.path.join(repo_path, 'letsencrypt-auto')):
        print('Root certbot-auto and letsencrypt-auto differ.')
        errors = True
    else:
        shutil.copyfile(
            os.path.join(repo_path, 'certbot-auto'), 
            os.path.join(temp_cwd, 'local-auto'))
        shutil.copy(os.path.normpath(os.path.join(
            repo_path, 
            'letsencrypt-auto-source/pieces/fetch.py')), temp_cwd)
        
        # Compare file against current version in the target branch
        branch = os.environ.get('TRAVIS_BRANCH', 'master')
        url = (
            'https://raw.githubusercontent.com/certbot/certbot/{0}/certbot-auto'
            .format(branch))
        urlretrieve(url, os.path.join(temp_cwd, 'certbot-auto'))

        if compare_files(
            os.path.join(temp_cwd, 'certbot-auto'),
            os.path.join(temp_cwd, 'local-auto')):
            print('Root *-auto were unchanged')
        else:
            # Compare file against the latest released version
            latest_version = subprocess.check_output(
                [sys.executable, 'fetch.py', '--latest-version'], cwd=temp_cwd)
            subprocess.call(
                [sys.executable, 'fetch.py', '--le-auto-script', 
                'v{0}'.format(latest_version.decode().strip())], cwd=temp_cwd)
            if compare_files(
                os.path.join(temp_cwd, 'letsencrypt-auto'),
                os.path.join(temp_cwd, 'local-auto')):
                print('Root *-auto were updated to the latest version.')
            else:
                print('Root *-auto have unexpected changes.')
                errors = True

    return errors

def main(args):
    repo_path = find_repo_path(args[0])
    errors = False

    try:
        temp_cwd = tempfile.mkdtemp()

        errors = validate_scripts_content(repo_path, temp_cwd)

        shutil.copyfile(
            os.path.normpath(os.path.join(repo_path, 'letsencrypt-auto-source/letsencrypt-auto')),
            os.path.join(temp_cwd, 'original-lea')
        )
        subprocess.call([sys.executable, os.path.normpath(os.path.join(
            repo_path, 'letsencrypt-auto-source/build.py'))])
        shutil.copyfile(
            os.path.normpath(os.path.join(repo_path, 'letsencrypt-auto-source/letsencrypt-auto')),
            os.path.join(temp_cwd, 'build-lea')
        )
        shutil.copyfile(
            os.path.join(temp_cwd, 'original-lea'),
            os.path.normpath(os.path.join(repo_path, 'letsencrypt-auto-source/letsencrypt-auto'))
        )

        if not compare_files(
            os.path.join(temp_cwd, 'original-lea'),
            os.path.join(temp_cwd, 'build-lea')):
            print('Script letsencrypt-auto-source/letsencrypt-auto doesn\'t match output of build.py.')
            errors = True
        else:
            print('Script letsencrypt-auto-source/letsencrypt-auto matches output of build.py.')
    finally:
        shutil.rmtree(temp_cwd)

    return errors

if __name__ == '__main__':
    errors = main(sys.argv[0])
    if errors:
        sys.exit(1)
