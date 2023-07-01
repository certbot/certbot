"""Tests for certbot.helpful_parser"""
import sys

import pytest

from certbot._internal.cli import HelpfulArgumentParser


class TestScanningFlags:
    '''Test the prescan_for_flag method of HelpfulArgumentParser'''
    def test_prescan_no_help_flag(self):
        arg_parser = HelpfulArgumentParser(['run'], {})
        detected_flag = arg_parser.prescan_for_flag('--help',
                                                        ['all', 'certonly'])
        assert detected_flag is False
        detected_flag = arg_parser.prescan_for_flag('-h',
                                                        ['all, certonly'])
        assert detected_flag is False

    def test_prescan_unvalid_topic(self):
        arg_parser = HelpfulArgumentParser(['--help', 'all'], {})
        detected_flag = arg_parser.prescan_for_flag('--help',
                                                    ['potato'])
        assert detected_flag is True
        detected_flag = arg_parser.prescan_for_flag('-h',
                                                    arg_parser.help_topics)
        assert detected_flag is False

    def test_prescan_valid_topic(self):
        arg_parser = HelpfulArgumentParser(['-h', 'all'], {})
        detected_flag = arg_parser.prescan_for_flag('-h',
                                                    arg_parser.help_topics)
        assert detected_flag == 'all'
        detected_flag = arg_parser.prescan_for_flag('--help',
                                                    arg_parser.help_topics)
        assert detected_flag is False

class TestDetermineVerbs:
    '''Tests for determine_verb methods of HelpfulArgumentParser'''
    def test_determine_verb_wrong_verb(self):
        arg_parser = HelpfulArgumentParser(['potato'], {})
        assert arg_parser.verb == "run"
        assert arg_parser.args == ["potato"]

    def test_determine_verb_help(self):
        arg_parser = HelpfulArgumentParser(['--help', 'everything'], {})
        assert arg_parser.verb == "help"
        assert arg_parser.args == ["--help", "everything"]
        arg_parser = HelpfulArgumentParser(['-d', 'some_domain', '--help',
                                               'all'], {})
        assert arg_parser.verb == "help"
        assert arg_parser.args == ['-d', 'some_domain', '--help',
                                               'all']

    def test_determine_verb(self):
        arg_parser = HelpfulArgumentParser(['certonly'], {})
        assert arg_parser.verb == 'certonly'
        assert arg_parser.args == []

        arg_parser = HelpfulArgumentParser(['auth'], {})
        assert arg_parser.verb == 'certonly'
        assert arg_parser.args == []

        arg_parser = HelpfulArgumentParser(['everything'], {})
        assert arg_parser.verb == 'run'
        assert arg_parser.args == []


class TestAdd:
    '''Tests for add method in HelpfulArgumentParser'''
    def test_add_trivial_argument(self):
        arg_parser = HelpfulArgumentParser(['run'], {})
        arg_parser.add(None, "--hello-world")
        parsed_args = arg_parser.parser.parse_args(['--hello-world',
                                                    'Hello World!'])
        assert parsed_args.hello_world == 'Hello World!'
        assert not hasattr(parsed_args, 'potato')

    def test_add_expected_argument(self):
        arg_parser = HelpfulArgumentParser(['--help', 'run'], {})
        arg_parser.add(
                [None, "run", "certonly", "register"],
                "--eab-kid", dest="eab_kid", action="store",
                metavar="EAB_KID",
                help="Key Identifier for External Account Binding")
        parsed_args = arg_parser.parser.parse_args(["--eab-kid", None])
        assert parsed_args.eab_kid is None
        assert hasattr(parsed_args, 'eab_kid')


class TestAddGroup:
    '''Test add_group method of HelpfulArgumentParser'''
    def test_add_group_no_input(self):
        arg_parser = HelpfulArgumentParser(['run'], {})
        with pytest.raises(TypeError):
            arg_parser.add_group()

    def test_add_group_topic_not_visible(self):
        # The user request help on run. A topic that given somewhere in the
        # args won't be added to the groups in the parser.
        arg_parser = HelpfulArgumentParser(['--help', 'run'], {})
        arg_parser.add_group("auth",
                                         description="description of auth")
        assert arg_parser.groups == {}

    def test_add_group_topic_requested_help(self):
        arg_parser = HelpfulArgumentParser(['--help', 'run'], {})
        arg_parser.add_group("run",
                                         description="description of run")
        assert arg_parser.groups["run"]
        arg_parser.add_group("certonly", description="description of certonly")
        with pytest.raises(KeyError):
            assert arg_parser.groups["certonly"] is False


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
