import os


def assert_hook_execution(probe_path, probe_content):
    with open(probe_path, 'r') as file:
        data = file.read()

    assert probe_content in data


def assert_save_renew_hook(config_dir, lineage):
    assert os.path.isfile(os.path.join(config_dir, 'renewal/{0}.conf'.format(lineage)))
