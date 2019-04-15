"""This module contains advanced assertions for the certbot integration tests."""
import os
import grp


def assert_hook_execution(probe_path, probe_content):
    """
    Assert that a certbot hook has been executed
    :param probe_path: path to the file that received the hook output
    :param probe_content: content expected when the hook is executed
    """
    with open(probe_path, 'r') as file:
        lines = file.readlines()

    assert '{0}{1}'.format(probe_content, os.linesep) in lines


def assert_saved_renew_hook(config_dir, lineage):
    """
    Assert that the renew hook configuration of a lineage has been saved.
    :param config_dir: location of the certbot configuration
    :param lineage: lineage domain name
    """
    with open(os.path.join(config_dir, 'renewal', '{0}.conf'.format(lineage))) as file_h:
        assert 'renew_hook' in file_h.read()


def assert_cert_count_for_lineage(config_dir, lineage, count):
    """
    Assert the number of certificates generated for a lineage.
    :param config_dir: location of the certbot configuration
    :param lineage: lineage domain name
    :param count: number of expected certificates
    """
    archive_dir = os.path.join(config_dir, 'archive')
    lineage_dir = os.path.join(archive_dir, lineage)
    certs = [file for file in os.listdir(lineage_dir) if file.startswith('cert')]
    assert len(certs) == count


def assert_equals_permissions(file1, file2, mask):
    """
    Assert that permissions on two files are identical in respect to a given umask.
    :param file1: first file path to compare
    :param file2: second file path to compare
    :param mask: 3-octal representation of a POSIX umask under which the two files mode
                 should match (eg. 0o074 will test RWX on group and R on world)
    """
    mode_file1 = os.stat(file1).st_mode & mask
    mode_file2 = os.stat(file2).st_mode & mask

    assert mode_file1 == mode_file2


def assert_equals_group_owner(file1, file2):
    """
    Assert that two files have the same group owner.
    :param file1: first file path to compare
    :param file2: second file path to compare
    :return:
    """
    group_owner_file1 = grp.getgrgid(os.stat(file1).st_gid)[0]
    group_owner_file2 = grp.getgrgid(os.stat(file2).st_gid)[0]

    assert group_owner_file1 == group_owner_file2


def assert_world_permissions(file, mode):
    """
    Assert that a file has the expected world permission.
    :param file: file path to check
    :param mode: world permissions mode expected
    """
    mode_file_all = os.stat(file).st_mode & 0o007

    assert mode_file_all == mode
