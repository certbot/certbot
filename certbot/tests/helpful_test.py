"""Tests for certbot.helpful_parser"""
import sys
import unittest
from unittest import mock

import pytest

from certbot import errors
from certbot._internal import constants
from certbot._internal.cli import _DomainsAction
from certbot._internal.cli import HelpfulArgumentParser


class TestScanningFlags(unittest.TestCase):
    '''Test the prescan_for_flag method of HelpfulArgumentParser'''
    def test_prescan_no_help_flag(self):
        arg_parser = HelpfulArgumentParser(['run'], {})
        detected_flag = arg_parser.prescan_for_flag('--help',
                                                        ['all', 'certonly'])
        self.assertIs(detected_flag, False)
        detected_flag = arg_parser.prescan_for_flag('-h',
                                                        ['all, certonly'])
        self.assertIs(detected_flag, False)

    def test_prescan_unvalid_topic(self):
        arg_parser = HelpfulArgumentParser(['--help', 'all'], {})
        detected_flag = arg_parser.prescan_for_flag('--help',
                                                    ['potato'])
        self.assertIs(detected_flag, True)
        detected_flag = arg_parser.prescan_for_flag('-h',
                                                    arg_parser.help_topics)
        self.assertIs(detected_flag, False)

    def test_prescan_valid_topic(self):
        arg_parser = HelpfulArgumentParser(['-h', 'all'], {})
        detected_flag = arg_parser.prescan_for_flag('-h',
                                                    arg_parser.help_topics)
        self.assertEqual(detected_flag, 'all')
        detected_flag = arg_parser.prescan_for_flag('--help',
                                                    arg_parser.help_topics)
        self.assertIs(detected_flag, False)

class TestDetermineVerbs(unittest.TestCase):
    '''Tests for determine_verb methods of HelpfulArgumentParser'''
    def test_determine_verb_wrong_verb(self):
        arg_parser = HelpfulArgumentParser(['potato'], {})
        self.assertEqual(arg_parser.verb, "run")
        self.assertEqual(arg_parser.args, ["potato"])

    def test_determine_verb_help(self):
        arg_parser = HelpfulArgumentParser(['--help', 'everything'], {})
        self.assertEqual(arg_parser.verb, "help")
        self.assertEqual(arg_parser.args, ["--help", "everything"])
        arg_parser = HelpfulArgumentParser(['-d', 'some_domain', '--help',
                                               'all'], {})
        self.assertEqual(arg_parser.verb, "help")
        self.assertEqual(arg_parser.args, ['-d', 'some_domain', '--help',
                                               'all'])

    def test_determine_verb(self):
        arg_parser = HelpfulArgumentParser(['certonly'], {})
        self.assertEqual(arg_parser.verb, 'certonly')
        self.assertEqual(arg_parser.args, [])

        arg_parser = HelpfulArgumentParser(['auth'], {})
        self.assertEqual(arg_parser.verb, 'certonly')
        self.assertEqual(arg_parser.args, [])

        arg_parser = HelpfulArgumentParser(['everything'], {})
        self.assertEqual(arg_parser.verb, 'run')
        self.assertEqual(arg_parser.args, [])


class TestAdd(unittest.TestCase):
    '''Tests for add method in HelpfulArgumentParser'''
    def test_add_trivial_argument(self):
        arg_parser = HelpfulArgumentParser(['run'], {})
        arg_parser.add(None, "--hello-world")
        parsed_args = arg_parser.parser.parse_args(['--hello-world',
                                                    'Hello World!'])
        self.assertIs(parsed_args.hello_world, 'Hello World!')
        self.assertFalse(hasattr(parsed_args, 'potato'))

    def test_add_expected_argument(self):
        arg_parser = HelpfulArgumentParser(['--help', 'run'], {})
        arg_parser.add(
                [None, "run", "certonly", "register"],
                "--eab-kid", dest="eab_kid", action="store",
                metavar="EAB_KID",
                help="Key Identifier for External Account Binding")
        parsed_args = arg_parser.parser.parse_args(["--eab-kid", None])
        self.assertIsNone(parsed_args.eab_kid)
        self.assertTrue(hasattr(parsed_args, 'eab_kid'))


class TestAddGroup(unittest.TestCase):
    '''Test add_group method of HelpfulArgumentParser'''
    def test_add_group_no_input(self):
        arg_parser = HelpfulArgumentParser(['run'], {})
        self.assertRaises(TypeError, arg_parser.add_group)

    def test_add_group_topic_not_visible(self):
        # The user request help on run. A topic that given somewhere in the
        # args won't be added to the groups in the parser.
        arg_parser = HelpfulArgumentParser(['--help', 'run'], {})
        arg_parser.add_group("auth",
                                         description="description of auth")
        self.assertEqual(arg_parser.groups, {})

    def test_add_group_topic_requested_help(self):
        arg_parser = HelpfulArgumentParser(['--help', 'run'], {})
        arg_parser.add_group("run",
                                         description="description of run")
        self.assertTrue(arg_parser.groups["run"])
        arg_parser.add_group("certonly", description="description of certonly")
        with self.assertRaises(KeyError):
            self.assertIs(arg_parser.groups["certonly"], False)


class TestParseArgsErrors(unittest.TestCase):
    '''Tests for errors that should be met for some cases in parse_args method
    in HelpfulArgumentParser'''
    def test_parse_args_renew_force_interactive(self):
        arg_parser = HelpfulArgumentParser(['renew', '--force-interactive'],
                                           {})
        arg_parser.add(
            None, constants.FORCE_INTERACTIVE_FLAG, action="store_true")

        with self.assertRaises(errors.Error):
            arg_parser.parse_args()

    def test_parse_args_non_interactive_and_force_interactive(self):
        arg_parser = HelpfulArgumentParser(['--force-interactive',
                                            '--non-interactive'], {})
        arg_parser.add(
            None, constants.FORCE_INTERACTIVE_FLAG, action="store_true")
        arg_parser.add(
            None, "--non-interactive", dest="noninteractive_mode",
            action="store_true"
        )

        with self.assertRaises(errors.Error):
            arg_parser.parse_args()

    def test_parse_args_subset_names_wildcard_domain(self):
        arg_parser = HelpfulArgumentParser(['--domain',
                                           '*.example.com,potato.example.com',
                                           '--allow-subset-of-names'], {})
        # The following arguments are added because they have to be defined
        # in order for arg_parser to run completely. They are not used for the
        # test.
        arg_parser.add(
            None, constants.FORCE_INTERACTIVE_FLAG, action="store_true")
        arg_parser.add(
            None, "--non-interactive", dest="noninteractive_mode",
            action="store_true")
        arg_parser.add(
            None, "--staging"
        )
        arg_parser.add(None, "--dry-run")
        arg_parser.add(None, "--csr")
        arg_parser.add(None, "--must-staple")
        arg_parser.add(None, "--validate-hooks")

        arg_parser.add(None, "-d", "--domain", dest="domains",
                       metavar="DOMAIN", action=_DomainsAction)
        arg_parser.add(None, "--allow-subset-of-names")
        # with self.assertRaises(errors.Error):
        #    arg_parser.parse_args()

    def test_parse_args_hosts_and_auto_hosts(self):
        arg_parser = HelpfulArgumentParser(['--hsts', '--auto-hsts'], {})

        arg_parser.add(
            None, "--hsts", action="store_true", dest="hsts")
        arg_parser.add(
            None, "--auto-hsts", action="store_true", dest="auto_hsts")
        # The following arguments are added because they have to be defined
        # in order for arg_parser to run completely. They are not used for the
        # test.
        arg_parser.add(
            None, constants.FORCE_INTERACTIVE_FLAG, action="store_true")
        arg_parser.add(
            None, "--non-interactive", dest="noninteractive_mode",
            action="store_true")
        arg_parser.add(None, "--staging")
        arg_parser.add(None, "--dry-run")
        arg_parser.add(None, "--csr")
        arg_parser.add(None, "--must-staple")
        arg_parser.add(None, "--validate-hooks")
        arg_parser.add(None, "--allow-subset-of-names")
        with self.assertRaises(errors.Error):
            arg_parser.parse_args()


class TestAddDeprecatedArgument(unittest.TestCase):
    """Tests for add_deprecated_argument method of HelpfulArgumentParser"""

    @mock.patch.object(HelpfulArgumentParser, "modify_kwargs_for_default_detection")
    def test_no_default_detection_modifications(self, mock_modify):
        arg_parser = HelpfulArgumentParser(["run"], {}, detect_defaults=True)
        arg_parser.add_deprecated_argument("--foo", 0)
        arg_parser.parse_args()
        mock_modify.assert_not_called()


if __name__ == '__main__':
    sys.exit(pytest.main([__file__]))  # pragma: no cover
