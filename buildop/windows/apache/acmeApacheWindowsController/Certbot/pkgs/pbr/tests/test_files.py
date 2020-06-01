# Copyright (c) 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import print_function

import os

import fixtures

from pbr.hooks import files
from pbr.tests import base


class FilesConfigTest(base.BaseTestCase):

    def setUp(self):
        super(FilesConfigTest, self).setUp()

        pkg_fixture = fixtures.PythonPackage(
            "fake_package", [
                ("fake_module.py", b""),
                ("other_fake_module.py", b""),
            ])
        self.useFixture(pkg_fixture)
        pkg_etc = os.path.join(pkg_fixture.base, 'etc')
        pkg_ansible = os.path.join(pkg_fixture.base, 'ansible',
                                   'kolla-ansible', 'test')
        dir_spcs = os.path.join(pkg_fixture.base, 'dir with space')
        dir_subdir_spc = os.path.join(pkg_fixture.base, 'multi space',
                                      'more spaces')
        pkg_sub = os.path.join(pkg_etc, 'sub')
        subpackage = os.path.join(
            pkg_fixture.base, 'fake_package', 'subpackage')
        os.makedirs(pkg_sub)
        os.makedirs(subpackage)
        os.makedirs(pkg_ansible)
        os.makedirs(dir_spcs)
        os.makedirs(dir_subdir_spc)
        with open(os.path.join(pkg_etc, "foo"), 'w') as foo_file:
            foo_file.write("Foo Data")
        with open(os.path.join(pkg_sub, "bar"), 'w') as foo_file:
            foo_file.write("Bar Data")
        with open(os.path.join(pkg_ansible, "baz"), 'w') as baz_file:
            baz_file.write("Baz Data")
        with open(os.path.join(subpackage, "__init__.py"), 'w') as foo_file:
            foo_file.write("# empty")
        with open(os.path.join(dir_spcs, "file with spc"), 'w') as spc_file:
            spc_file.write("# empty")
        with open(os.path.join(dir_subdir_spc, "file with spc"), 'w') as file_:
            file_.write("# empty")

        self.useFixture(base.DiveDir(pkg_fixture.base))

    def test_implicit_auto_package(self):
        config = dict(
            files=dict(
            )
        )
        files.FilesConfig(config, 'fake_package').run()
        self.assertIn('subpackage', config['files']['packages'])

    def test_auto_package(self):
        config = dict(
            files=dict(
                packages='fake_package',
            )
        )
        files.FilesConfig(config, 'fake_package').run()
        self.assertIn('subpackage', config['files']['packages'])

    def test_data_files_globbing(self):
        config = dict(
            files=dict(
                data_files="\n  etc/pbr = etc/*"
            )
        )
        files.FilesConfig(config, 'fake_package').run()
        self.assertIn(
            "\n'etc/pbr/' = \n 'etc/foo'\n'etc/pbr/sub' = \n 'etc/sub/bar'",
            config['files']['data_files'])

    def test_data_files_with_spaces(self):
        config = dict(
            files=dict(
                data_files="\n  'i like spaces' = 'dir with space'/*"
            )
        )
        files.FilesConfig(config, 'fake_package').run()
        self.assertIn(
            "\n'i like spaces/' = \n 'dir with space/file with spc'",
            config['files']['data_files'])

    def test_data_files_with_spaces_subdirectories(self):
        # test that we can handle whitespace in subdirectories
        data_files = "\n 'one space/two space' = 'multi space/more spaces'/*"
        expected = (
            "\n'one space/two space/' = "
            "\n 'multi space/more spaces/file with spc'")
        config = dict(
            files=dict(
                data_files=data_files
            )
        )
        files.FilesConfig(config, 'fake_package').run()
        self.assertIn(expected, config['files']['data_files'])

    def test_data_files_with_spaces_quoted_components(self):
        # test that we can quote individual path components
        data_files = (
            "\n'one space'/'two space' = 'multi space'/'more spaces'/*"
        )
        expected = ("\n'one space/two space/' = "
                    "\n 'multi space/more spaces/file with spc'")
        config = dict(
            files=dict(
                data_files=data_files
            )
        )
        files.FilesConfig(config, 'fake_package').run()
        self.assertIn(expected, config['files']['data_files'])

    def test_data_files_globbing_source_prefix_in_directory_name(self):
        # We want to test that the string, "docs", is not replaced in a
        # subdirectory name, "sub-docs"
        config = dict(
            files=dict(
                data_files="\n  share/ansible = ansible/*"
            )
        )
        files.FilesConfig(config, 'fake_package').run()
        self.assertIn(
            "\n'share/ansible/' = "
            "\n'share/ansible/kolla-ansible' = "
            "\n'share/ansible/kolla-ansible/test' = "
            "\n 'ansible/kolla-ansible/test/baz'",
            config['files']['data_files'])
