import os


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
