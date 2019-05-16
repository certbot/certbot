#!/usr/bin/env python
from distutils.version import StrictVersion
import os
import re
import subprocess


IGNORE_DISTRIBUTIONS = ['certbot-postfix', 'certbot-compatibility-tests', 'certbot-ci']

CHANGELOG_HEADER = '''\
Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number was:'''

CHANGELOG_FOOTER = '''\
More details about these changes can be found on our GitHub repo.'''

CERTBOT_DISTRIBUTION_RELATIVE_PATHS = ['setup.py', 'setup.cfg', 'certbot', 'docs',
                                       'pytest.ini', 'local-oldest-requirements.txt']


def _find_certbot_root_path():
    output = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'])
    return output.strip()


def _find_last_release_merge_commit():
    subprocess.check_output(['git', 'pull', '--tags'])
    output = subprocess.check_output(['git', 'tag'], universal_newlines=True)
    release_tags = [tag for tag in output.split('\n') if tag and re.match(r'^v\d+\.\d+\.0$', tag)]
    release_tags = sorted(release_tags, key=lambda x: StrictVersion(x[1:]))  # version on 0.31.0, not v0.31.0
    release_tag = release_tags[-1]

    output = subprocess.check_output(['git', 'rev-list', '{0}..HEAD'.format(release_tag), '--ancestry-path'], universal_newlines=True)
    ancestor_commits = output.strip().split('\n')

    output = subprocess.check_output(['git', 'rev-list', '{0}..HEAD'.format(release_tag), '--first-parent'], universal_newlines=True)
    parent_commits = output.strip().split('\n')

    matching_commits = [ancestor for ancestor, parent in zip(ancestor_commits, parent_commits)
                        if ancestor == parent]
    return matching_commits[-1]


def _find_modified_files(certbot_root_path, base_commit):
    output = subprocess.check_output(['git', 'log', '--name-only', '--pretty=oneline',
                                      '--full-index', '{0}..HEAD'.format(base_commit)])
    return {os.path.join(certbot_root_path, item)
            for item in output.split('\n')
            if item and not re.match(r'^[0-9a-f]{40}', item)}


def _find_distributions_path(root_path):
    return {os.path.join(root_path, name) for name in os.listdir(root_path)
            if (os.path.isdir(os.path.join(root_path, name))
                and 'setup.py' in os.listdir(os.path.join(root_path, name))
                and name not in IGNORE_DISTRIBUTIONS)}


def _detect_certbot_distribution_modifications(root_path, modified_files):
    target_paths = {os.path.join(root_path, path)
                    for path in CERTBOT_DISTRIBUTION_RELATIVE_PATHS}
    return {path for path in modified_files if any(path.startswith(target_path)
                                                   for target_path in target_paths)}


def _find_modified_distributions(root_path, distributions_paths, modified_files):
    modified_distributions = {distribution_path for distribution_path in distributions_paths
                              if any([path.startswith(distribution_path) for path in modified_files])}
    if _detect_certbot_distribution_modifications(root_path, modified_distributions):
        modified_distributions.add('certbot')
    return modified_distributions


def _prepare_changelog_entry(root_path, modified_distributions):
    entries = sorted([os.path.relpath(dist, root_path) for dist in modified_distributions])
    return '{0}\n\n{1}\n\n{2}'.format(CHANGELOG_HEADER, '\n'.join('* {0}'.format(entry) for entry in entries), CHANGELOG_FOOTER)


def _insert_changelog_entry(changelog_path, changelog_entry):
    with open(changelog_path) as file_h:
        data = file_h.read()

    data = re.sub(r'(## \d+\.\d+\.\d+ - \d{4}-\d{2}-\d{2})',
                  '{0}\n\n'.format(changelog_entry) + r'\1', data, count=1)

    with open(changelog_path, 'w') as file_h:
        file_h.write(data)


def main():
    last_release_merge_commit = _find_last_release_merge_commit()
    root_path = _find_certbot_root_path()
    modified_files = _find_modified_files(root_path, last_release_merge_commit)
    distributions_paths = _find_distributions_path(root_path)

    modified_distributions = _find_modified_distributions(root_path, distributions_paths, modified_files)

    changelog_entry = _prepare_changelog_entry(root_path, modified_distributions)
    changelog_path = os.path.join(root_path, 'CHANGELOG.md')
    _insert_changelog_entry(changelog_path, changelog_entry)

    print('--> Changelog at {0} as been updated with following changed distribution list for the next version:')
    print('============')
    print(changelog_entry)
    print('============')


if __name__ == '__main__':
    main()
