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

def find_repo_path():
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

# We do not use filecmp.cmp to take advantage of universal newlines 
# handling in open() for Python 3.x and be insensitive to CRLF/LF when run on Windows.
# As a consequence, this function will not work correctly if executed by Python 2.x on Windows.
# But it will work correctly on Linux for any version, because every file tested will be LF.
def compare_files(path_1, path_2):
    l1 = l2 = True
    with open(path_1, 'r') as f1, open(path_2, 'r') as f2:
        line = 1
        while l1 and l2:
            line += 1
            l1 = f1.readline()
            l2 = f2.readline()
            if l1 != l2:
                print('---')
                print((
                    'While comparing {0} (1) and {1} (2), a difference was found at line {2}:'
                    .format(os.path.basename(path_1), os.path.basename(path_2), line)))
                print('(1): {0}'.format(repr(l1)))
                print('(2): {0}'.format(repr(l2)))
                print('---')
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
            subprocess.check_call(
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

def main():
    repo_path = find_repo_path()
    temp_cwd = tempfile.mkdtemp()
    errors = False

    try:
        errors = validate_scripts_content(repo_path, temp_cwd)

        shutil.copyfile(
            os.path.normpath(os.path.join(repo_path, 'letsencrypt-auto-source/letsencrypt-auto')),
            os.path.join(temp_cwd, 'original-lea')
        )
        subprocess.check_call([sys.executable, os.path.normpath(os.path.join(
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
            print('Script letsencrypt-auto-source/letsencrypt-auto '
                  'doesn\'t match output of build.py.')
            errors = True
        else:
            print('Script letsencrypt-auto-source/letsencrypt-auto matches output of build.py.')
    finally:
        shutil.rmtree(temp_cwd)

    return errors

if __name__ == '__main__':
    if main():
        sys.exit(1)
