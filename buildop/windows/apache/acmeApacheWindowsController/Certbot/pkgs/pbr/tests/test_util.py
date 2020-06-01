# -*- coding: utf-8 -*-
# Copyright (c) 2015 Hewlett-Packard Development Company, L.P. (HP)
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

import io
import tempfile
import textwrap

import six
from six.moves import configparser
import sys

from pbr.tests import base
from pbr import util


def config_from_ini(ini):
    config = {}
    if sys.version_info >= (3, 2):
        parser = configparser.ConfigParser()
    else:
        parser = configparser.SafeConfigParser()
    ini = textwrap.dedent(six.u(ini))
    parser.readfp(io.StringIO(ini))
    for section in parser.sections():
        config[section] = dict(parser.items(section))
    return config


class TestExtrasRequireParsingScenarios(base.BaseTestCase):

    scenarios = [
        ('simple_extras', {
            'config_text': """
                [extras]
                first =
                    foo
                    bar==1.0
                second =
                    baz>=3.2
                    foo
                """,
            'expected_extra_requires': {
                'first': ['foo', 'bar==1.0'],
                'second': ['baz>=3.2', 'foo'],
                'test': ['requests-mock'],
                "test:(python_version=='2.6')": ['ordereddict'],
            }
        }),
        ('with_markers', {
            'config_text': """
                [extras]
                test =
                    foo:python_version=='2.6'
                    bar
                    baz<1.6 :python_version=='2.6'
                    zaz :python_version>'1.0'
                """,
            'expected_extra_requires': {
                "test:(python_version=='2.6')": ['foo', 'baz<1.6'],
                "test": ['bar', 'zaz']}}),
        ('no_extras', {
            'config_text': """
            [metadata]
            long_description = foo
            """,
            'expected_extra_requires':
            {}
        })]

    def test_extras_parsing(self):
        config = config_from_ini(self.config_text)
        kwargs = util.setup_cfg_to_setup_kwargs(config)

        self.assertEqual(self.expected_extra_requires,
                         kwargs['extras_require'])


class TestInvalidMarkers(base.BaseTestCase):

    def test_invalid_marker_raises_error(self):
        config = {'extras': {'test': "foo :bad_marker>'1.0'"}}
        self.assertRaises(SyntaxError, util.setup_cfg_to_setup_kwargs, config)


class TestMapFieldsParsingScenarios(base.BaseTestCase):

    scenarios = [
        ('simple_project_urls', {
            'config_text': """
                [metadata]
                project_urls =
                    Bug Tracker = https://bugs.launchpad.net/pbr/
                    Documentation = https://docs.openstack.org/pbr/
                    Source Code = https://git.openstack.org/cgit/openstack-dev/pbr/
                """,  # noqa: E501
            'expected_project_urls': {
                'Bug Tracker': 'https://bugs.launchpad.net/pbr/',
                'Documentation': 'https://docs.openstack.org/pbr/',
                'Source Code': 'https://git.openstack.org/cgit/openstack-dev/pbr/',  # noqa: E501
            },
        }),
        ('query_parameters', {
            'config_text': """
                [metadata]
                project_urls =
                    Bug Tracker = https://bugs.launchpad.net/pbr/?query=true
                    Documentation = https://docs.openstack.org/pbr/?foo=bar
                    Source Code = https://git.openstack.org/cgit/openstack-dev/pbr/commit/?id=hash
                """,  # noqa: E501
            'expected_project_urls': {
                'Bug Tracker': 'https://bugs.launchpad.net/pbr/?query=true',
                'Documentation': 'https://docs.openstack.org/pbr/?foo=bar',
                'Source Code': 'https://git.openstack.org/cgit/openstack-dev/pbr/commit/?id=hash',  # noqa: E501
            },
        }),
    ]

    def test_project_url_parsing(self):
        config = config_from_ini(self.config_text)
        kwargs = util.setup_cfg_to_setup_kwargs(config)

        self.assertEqual(self.expected_project_urls, kwargs['project_urls'])


class TestKeywordsParsingScenarios(base.BaseTestCase):

    scenarios = [
        ('keywords_list', {
            'config_text': """
                [metadata]
                keywords =
                    one
                    two
                    three
                """,  # noqa: E501
            'expected_keywords': ['one', 'two', 'three'],
            },
        ),
        ('inline_keywords', {
            'config_text': """
                [metadata]
                keywords = one, two, three
                """,  # noqa: E501
            'expected_keywords': ['one, two, three'],
        }),
    ]

    def test_keywords_parsing(self):
        config = config_from_ini(self.config_text)
        kwargs = util.setup_cfg_to_setup_kwargs(config)

        self.assertEqual(self.expected_keywords, kwargs['keywords'])


class TestProvidesExtras(base.BaseTestCase):
    def test_provides_extras(self):
        ini = """
        [metadata]
        provides_extras = foo
                          bar
        """
        config = config_from_ini(ini)
        kwargs = util.setup_cfg_to_setup_kwargs(config)
        self.assertEqual(['foo', 'bar'], kwargs['provides_extras'])


class TestDataFilesParsing(base.BaseTestCase):

    scenarios = [
        ('data_files', {
            'config_text': """
            [files]
            data_files =
                'i like spaces/' =
                    'dir with space/file with spc 2'
                    'dir with space/file with spc 1'
            """,
            'data_files': [
                ('i like spaces/', ['dir with space/file with spc 2',
                                    'dir with space/file with spc 1'])
            ]
        })]

    def test_handling_of_whitespace_in_data_files(self):
        config = config_from_ini(self.config_text)
        kwargs = util.setup_cfg_to_setup_kwargs(config)

        self.assertEqual(self.data_files,
                         list(kwargs['data_files']))


class TestUTF8DescriptionFile(base.BaseTestCase):
    def test_utf8_description_file(self):
        _, path = tempfile.mkstemp()
        ini_template = """
        [metadata]
        description_file = %s
        """
        # Two \n's because pbr strips the file content and adds \n\n
        # This way we can use it directly as the assert comparison
        unicode_description = u'UTF8 description: é"…-ʃŋ\'\n\n'
        ini = ini_template % path
        with io.open(path, 'w', encoding='utf8') as f:
            f.write(unicode_description)
        config = config_from_ini(ini)
        kwargs = util.setup_cfg_to_setup_kwargs(config)
        self.assertEqual(unicode_description, kwargs['long_description'])
