import os


def assert_hook_execution(probe_path, probe_content):
    with open(probe_path, 'r') as file:
        data = file.read()

    print(data)
    assert probe_content in data


def assert_save_renew_hook(config_dir, lineage):
    assert os.path.isfile(os.path.join(config_dir, 'renewal/{0}.conf'.format(lineage)))


def assert_certs_count_for_lineage(config_dir, lineage, count):
    archive_dir = os.path.join(config_dir, 'archive')
    lineage_dir = os.path.join(archive_dir, lineage)
    certs = [file for file in os.listdir(lineage_dir) if file.startswith('cert')]
    assert len(certs) == count
