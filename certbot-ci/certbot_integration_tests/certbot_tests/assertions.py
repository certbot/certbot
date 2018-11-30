import os
import grp


__all__ = ['assert_hook_execution', 'assert_save_renew_hook', 'assert_certs_count_for_lineage',
           'assert_equals_group_permissions', 'assert_not_world_readable']


def assert_hook_execution(probe_path, probe_content):
    with open(probe_path, 'r') as file:
        lines = file.readlines()

    # Comparing pattern to each line avoids to match "pre" for a line with "pre-override"
    assert [line for line in lines if line == '{0}{1}'.format(probe_content, os.linesep)]


def assert_save_renew_hook(config_dir, lineage):
    assert os.path.isfile(os.path.join(config_dir, 'renewal/{0}.conf'.format(lineage)))


def assert_certs_count_for_lineage(config_dir, lineage, count):
    archive_dir = os.path.join(config_dir, 'archive')
    lineage_dir = os.path.join(archive_dir, lineage)
    certs = [file for file in os.listdir(lineage_dir) if file.startswith('cert')]
    assert len(certs) == count


def assert_equals_group_permissions(file1, file2):
    mode_file1 = os.stat(file1).st_mode & 0o777
    mode_file2 = os.stat(file2).st_mode & 0o777

    # Check the group permissions
    assert mode_file1 & 0o700 == mode_file2 & 0o700

    group_owner_file1 = grp.getgrgid(os.stat(file1).st_gid)[0]
    group_owner_file2 = grp.getgrgid(os.stat(file2).st_gid)[0]

    # Check the group owner
    assert group_owner_file1 == group_owner_file2


def assert_not_world_readable(file):
    mode_file_all = os.stat(file).st_mode & 0o007

    assert mode_file_all == 0
