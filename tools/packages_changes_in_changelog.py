#!/usr/bin/env python
"""
This script calculates, from git HEAD, all modifications done in the certbot package since a
given release version, then generate a list of changes that is included in CHANGELOG.md.
It uses intensively the locally installed git executable capabilities to do so.

The trickiest part of this script is to find the actual commit that needs to be set as the
base comparison. It is not the commit that holds the version tag. Indeed after a release
several unrelated changes to an effective modification of the codebase logic are done: this
concerns in particular all versions values in __init__.py that are updated from 0.XX.dev0 to
0.XZ once the candidate release branch is merged back to master.

Also, the particular situation of point release branches needs to be taken into account, since
theses releases are not extracted from master, but from the current 0.XX.x branch, on top of
the previous point release.

The correct commit base is the commit that integrates the commit tagged with the given base
release. Indeed, this commit contains all unrelated changes to codebase logic and defines the
new integration window for the next release: from it the diff contains the effective modifications
for the next release.

Then the two main use cases for this script are (we take 0.34.1 as the current release version):
1) For a normal release: after extracting candidate-0.35.0 from master, call
   `tools/packages_changes_in_changelog.py 0.34.0`
   (here base comparison is last normal version, so 0.34.0)
2) For a point release: after checkout of current release branch 0.34.x, call
   `tools/packages_changes_in_changelog.py 0.34.1`
   (here base comparison is last point version, so 0.34.1)

WARNING: You need to execute the script BEFORE executing the release script since it will update
         all versions in __init__.py files. Otherwise the CHANGELOG.md will contain all the
         distributions since they have all been modified by the release script.
"""
import argparse
import os
import re
import subprocess


# Define distributions to be ignored in the changelog, most like because they are not released.
IGNORE_DISTRIBUTIONS = ['certbot-postfix', 'certbot-compatibility-tests', 'certbot-ci']

# For the certbot distribution, gives the relative paths to search for, ignoring all others.
# These paths can be files or directories.
CERTBOT_DISTRIBUTION_RELATIVE_PATHS = ['setup.py', 'setup.cfg', 'certbot', 'docs',
                                       'pytest.ini', 'local-oldest-requirements.txt']

CHANGELOG_HEADER_TPL = '''\
Despite us having broken lockstep, we are continuing to release new versions of
all Certbot components during releases for the time being, however, the only
package with changes other than its version number since {0} was:'''

CHANGELOG_FOOTER = '''\
More details about these changes can be found on our GitHub repo.'''


def _find_certbot_root_path():
    output = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'])
    return output.strip()


def _find_last_release_merge_commit(base_version):
    # Here is the GIT Black Magic: using appropriate rev-list between HEAD and version tag,
    # in the parent and the children point of view, we find the first commit that integrates
    # the commit tag into the branch of current HEAD.
    # In case of a normal release, it will be the merge commit of candidate-0.XX.Y onto master.
    # In case of a point release, it will be the merge commit of candidate-0.XX.Y onto 0.XX.x.
    subprocess.check_output(['git', 'pull', '--tags'])

    output = subprocess.check_output(['git', 'rev-list', 'v{0}..HEAD'
                                     .format(base_version), '--ancestry-path'],
                                     universal_newlines=True)
    children_commits = output.strip().split('\n')

    output = subprocess.check_output(['git', 'rev-list', 'v{0}..HEAD'
                                     .format(base_version), '--first-parent'],
                                     universal_newlines=True)
    parent_commits = output.strip().split('\n')

    matching_commits = [child for child, parent in zip(children_commits, parent_commits)
                        if child == parent]
    return matching_commits[-1]


def _find_modified_files(certbot_root_path, base_commit):
    # The appropriate GIT command gives use the list of all path impacted with the relevant
    # commit(s) that modify these paths. One regex later, we have all the paths in a list.
    output = subprocess.check_output(['git', 'log', '--name-only', '--pretty=oneline',
                                      '--full-index', '{0}..HEAD'.format(base_commit)])
    return {os.path.join(certbot_root_path, item)
            for item in output.split('\n')
            if item and not re.match(r'^[0-9a-f]{40}', item)}


def _find_distributions_path(root_path):
    # We consider all distributions folder as containing a setup.py. Case of certbot package
    # itself is handled by _detect_certbot_distribution_modifications.
    return {os.path.join(root_path, name) for name in os.listdir(root_path)
            if (os.path.isdir(os.path.join(root_path, name))
                and 'setup.py' in os.listdir(os.path.join(root_path, name))
                and name not in IGNORE_DISTRIBUTIONS)}


def _detect_certbot_distribution_modifications(root_path, modified_files):
    # Special case of certbot package itself, since it is on the GIT root path,
    # not on its dedicated sub-folder. One day I will fix that.
    target_paths = {os.path.join(root_path, path)
                    for path in CERTBOT_DISTRIBUTION_RELATIVE_PATHS}
    return {path for path in modified_files if any(path.startswith(target_path + os.sep)
                                                   or path == target_path
                                                   for target_path in target_paths)}


def _find_modified_distributions(root_path, distributions_paths, modified_files):
    # Method to detect which are the packages impacted by modification, by searching
    # when the distribution path is the base of a modified path.
    modified_distributions = {distribution_path for distribution_path in distributions_paths
                              if any([path.startswith(distribution_path + os.sep)
                                      or path == distribution_path
                                      for path in modified_files])}
    if _detect_certbot_distribution_modifications(root_path, modified_distributions):
        modified_distributions.add('certbot')
    return modified_distributions


def _prepare_changelog_entry(root_path, modified_distributions, base_version):
    # Changelog entry is parameterized using the base release that has been used to make
    # the comparison, and so show clearly what is the base comparison of the change list.
    entries = sorted([os.path.relpath(dist, root_path) for dist in modified_distributions])
    return '{0}\n\n{1}\n\n{2}'.format(CHANGELOG_HEADER_TPL.format(base_version),
                                      '\n'.join('* {0}'.format(entry) for entry in entries),
                                      CHANGELOG_FOOTER)


def _insert_changelog_entry(changelog_path, changelog_entry):
    # We put the changelog entry just before the last release version entry.
    # It is something like `0.34.0 - 2019-04-15`, while current master entry
    # is something like `0.35.0 - master`.
    with open(changelog_path) as file_h:
        data = file_h.read()

    data = re.sub(r'(## \d+\.\d+\.\d+ - \d{4}-\d{2}-\d{2})',
                  '{0}\n\n'.format(changelog_entry) + r'\1', data, count=1)

    with open(changelog_path, 'w') as file_h:
        file_h.write(data)


def main(base_version):
    """
    Main function of this module, executing the logic described at the module documentation.
    :param base_version: the release version to use as a base comparison for the package changes
    :return: the changelog entry inserted in CHANGELOG.md
    """
    last_release_merge_commit = _find_last_release_merge_commit(base_version)
    root_path = _find_certbot_root_path()
    modified_files = _find_modified_files(root_path, last_release_merge_commit)
    distributions_paths = _find_distributions_path(root_path)

    modified_distributions = _find_modified_distributions(root_path, distributions_paths, modified_files)

    changelog_entry = _prepare_changelog_entry(root_path, modified_distributions, base_version)
    changelog_path = os.path.join(root_path, 'CHANGELOG.md')
    _insert_changelog_entry(changelog_path, changelog_entry)

    return changelog_entry


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Calculate the packages modified since a given Certbot release '
                    'compared to git HEAD, and write the change list in CHANGELOG.md.')
    parser.add_argument('base_version',
                        help='Specify the base version on which the package modifications '
                             'will be compared against (eg. 0.34.0).')
    args = parser.parse_args()
    output = main(args.base_version)

    print('--> Changelog at {0} as been updated with following changed distribution list for the next version:')
    print('============')
    print(output)
    print('============')
