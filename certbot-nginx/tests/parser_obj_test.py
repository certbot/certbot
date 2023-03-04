""" Tests for functions and classes in parser_obj.py """

import sys
import unittest
from unittest import mock

import pytest

from certbot_nginx._internal.parser_obj import COMMENT_BLOCK
from certbot_nginx._internal.parser_obj import parse_raw


class CommentHelpersTest(unittest.TestCase):
    def test_is_comment(self):
        from certbot_nginx._internal.parser_obj import _is_comment
        assert _is_comment(parse_raw(['#']))
        assert _is_comment(parse_raw(['#', ' literally anything else']))
        assert not _is_comment(parse_raw(['not', 'even', 'a', 'comment']))

    def test_is_certbot_comment(self):
        from certbot_nginx._internal.parser_obj import _is_certbot_comment
        assert _is_certbot_comment(
            parse_raw(COMMENT_BLOCK))
        assert not _is_certbot_comment(
            parse_raw(['#', ' not a certbot comment']))
        assert not _is_certbot_comment(
            parse_raw(['#', ' managed by Certbot', ' also not a certbot comment']))
        assert not _is_certbot_comment(
            parse_raw(['not', 'even', 'a', 'comment']))

    def test_certbot_comment(self):
        from certbot_nginx._internal.parser_obj import _certbot_comment
        from certbot_nginx._internal.parser_obj import _is_certbot_comment
        comment = _certbot_comment(None)
        assert _is_certbot_comment(comment)
        assert comment.dump() == COMMENT_BLOCK
        assert comment.dump(True) == ['    '] + COMMENT_BLOCK
        assert _certbot_comment(None, 2).dump(True) == ['  '] + COMMENT_BLOCK


class ParsingHooksTest(unittest.TestCase):
    def test_is_sentence(self):
        from certbot_nginx._internal.parser_obj import Sentence
        assert not Sentence.should_parse([])
        assert Sentence.should_parse([''])
        assert Sentence.should_parse(['word'])
        assert Sentence.should_parse(['two', 'words'])
        assert not Sentence.should_parse([[]])
        assert not Sentence.should_parse(['word', []])

    def test_is_block(self):
        from certbot_nginx._internal.parser_obj import Block
        assert not Block.should_parse([])
        assert not Block.should_parse([''])
        assert not Block.should_parse(['two', 'words'])
        assert not Block.should_parse([[[]], []])
        assert not Block.should_parse([['block_name'], ['hi', []], []])
        assert not Block.should_parse([['block_name'], 'lol'])
        assert Block.should_parse([['block_name'], ['hi', []]])
        assert Block.should_parse([['hello'], []])
        assert Block.should_parse([['block_name'], [['many'], ['statements'], 'here']])
        assert Block.should_parse([['if', ' ', '(whatever)'], ['hi']])

    def test_parse_raw(self):
        fake_parser1 = mock.Mock()
        fake_parser1.should_parse = lambda x: True
        fake_parser2 = mock.Mock()
        fake_parser2.should_parse = lambda x: False
        # First encountered "match" should parse.
        parse_raw([])
        fake_parser1.called_once()
        fake_parser2.not_called()
        fake_parser1.reset_mock()
        # "match" that returns False shouldn't parse.
        parse_raw([])
        fake_parser1.not_called()
        fake_parser2.called_once()

    @mock.patch("certbot_nginx._internal.parser_obj.Parsable.parsing_hooks")
    def test_parse_raw_no_match(self, parsing_hooks):
        from certbot import errors
        fake_parser1 = mock.Mock()
        fake_parser1.should_parse = lambda x: False
        parsing_hooks.return_value = (fake_parser1,)
        with pytest.raises(errors.MisconfigurationError):
            parse_raw([])
        parsing_hooks.return_value = ()
        with pytest.raises(errors.MisconfigurationError):
            parse_raw([])

    def test_parse_raw_passes_add_spaces(self):
        fake_parser1 = mock.Mock()
        fake_parser1.should_parse = lambda x: True
        parse_raw([])
        fake_parser1.parse.called_with([None])
        parse_raw([], add_spaces=True)
        fake_parser1.parse.called_with([None, True])


class SentenceTest(unittest.TestCase):
    def setUp(self):
        from certbot_nginx._internal.parser_obj import Sentence
        self.sentence = Sentence(None)

    def test_parse_bad_sentence_raises_error(self):
        from certbot import errors
        with pytest.raises(errors.MisconfigurationError):
            self.sentence.parse('lol')
        with pytest.raises(errors.MisconfigurationError):
            self.sentence.parse([[]])
        with pytest.raises(errors.MisconfigurationError):
            self.sentence.parse([5])

    def test_parse_sentence_words_hides_spaces(self):
        og_sentence = ['\r\n', 'hello', ' ', ' ', '\t\n  ', 'lol', ' ', 'spaces']
        self.sentence.parse(og_sentence)
        assert self.sentence.words == ['hello', 'lol', 'spaces']
        assert self.sentence.dump() == ['hello', 'lol', 'spaces']
        assert self.sentence.dump(True) == og_sentence

    def test_parse_sentence_with_add_spaces(self):
        self.sentence.parse(['hi', 'there'], add_spaces=True)
        assert self.sentence.dump(True) == ['hi', ' ', 'there']
        self.sentence.parse(['one', ' ', 'space', 'none'], add_spaces=True)
        assert self.sentence.dump(True) == ['one', ' ', 'space', ' ', 'none']

    def test_iterate(self):
        expected = [['1', '2', '3']]
        self.sentence.parse(['1', ' ', '2', ' ', '3'])
        for i, sentence in enumerate(self.sentence.iterate()):
            assert sentence.dump() == expected[i]

    def test_set_tabs(self):
        self.sentence.parse(['tabs', 'pls'], add_spaces=True)
        self.sentence.set_tabs()
        assert self.sentence.dump(True)[0] == '\n    '
        self.sentence.parse(['tabs', 'pls'], add_spaces=True)

    def test_get_tabs(self):
        self.sentence.parse(['no', 'tabs'])
        assert self.sentence.get_tabs() == ''
        self.sentence.parse(['\n \n  ', 'tabs'])
        assert self.sentence.get_tabs() == '  '
        self.sentence.parse(['\n\t  ', 'tabs'])
        assert self.sentence.get_tabs() == '\t  '
        self.sentence.parse(['\n\t \n', 'tabs'])
        assert self.sentence.get_tabs() == ''


class BlockTest(unittest.TestCase):
    def setUp(self):
        from certbot_nginx._internal.parser_obj import Block
        self.bloc = Block(None)
        self.name = ['server', 'name']
        self.contents = [['thing', '1'], ['thing', '2'], ['another', 'one']]
        self.bloc.parse([self.name, self.contents])

    def test_iterate(self):
        # Iterates itself normally
        assert self.bloc == next(self.bloc.iterate())
        # Iterates contents while expanded
        expected = [self.bloc.dump()] + self.contents
        for i, elem in enumerate(self.bloc.iterate(expanded=True)):
            assert expected[i] == elem.dump()

    def test_iterate_match(self):
        # can match on contents while expanded
        from certbot_nginx._internal.parser_obj import Block
        from certbot_nginx._internal.parser_obj import Sentence
        expected = [['thing', '1'], ['thing', '2']]
        for i, elem in enumerate(self.bloc.iterate(expanded=True,
            match=lambda x: isinstance(x, Sentence) and 'thing' in x.words)):
            assert expected[i] == elem.dump()
        # can match on self
        assert self.bloc == next(self.bloc.iterate(
            expanded=True,
            match=lambda x: isinstance(x, Block) and 'server' in x.names))

    def test_parse_with_added_spaces(self):
        import copy
        self.bloc.parse([copy.copy(self.name), self.contents], add_spaces=True)
        assert self.bloc.dump() == [self.name, self.contents]
        assert self.bloc.dump(True) == [
            ['server', ' ', 'name', ' '],
            [['thing', ' ', '1'],
             ['thing', ' ', '2'],
             ['another', ' ', 'one']]]

    def test_bad_parse_raises_error(self):
        from certbot import errors
        with pytest.raises(errors.MisconfigurationError):
            self.bloc.parse([[[]], [[]]])
        with pytest.raises(errors.MisconfigurationError):
            self.bloc.parse(['lol'])
        with pytest.raises(errors.MisconfigurationError):
            self.bloc.parse(['fake', 'news'])

    def test_set_tabs(self):
        self.bloc.set_tabs()
        assert self.bloc.names.dump(True)[0] == '\n    '
        for elem in self.bloc.contents.dump(True)[:-1]:
            assert elem[0] == '\n        '
        assert self.bloc.contents.dump(True)[-1][0] == '\n'

    def test_get_tabs(self):
        self.bloc.parse([[' \n  \t', 'lol'], []])
        assert self.bloc.get_tabs() == '  \t'

class StatementsTest(unittest.TestCase):
    def setUp(self):
        from certbot_nginx._internal.parser_obj import Statements
        self.statements = Statements(None)
        self.raw = [
            ['sentence', 'one'],
            ['sentence', 'two'],
            ['and', 'another']
        ]
        self.raw_spaced = [
            ['\n  ', 'sentence', ' ', 'one'],
            ['\n  ', 'sentence', ' ', 'two'],
            ['\n  ', 'and', ' ', 'another'],
            '\n\n'
        ]

    def test_set_tabs(self):
        self.statements.parse(self.raw)
        self.statements.set_tabs()
        for statement in self.statements.iterate():
            assert statement.dump(True)[0] == '\n    '

    def test_set_tabs_with_parent(self):
        # Trailing whitespace should inherit from parent tabbing.
        self.statements.parse(self.raw)
        self.statements.parent = mock.Mock()
        self.statements.parent.get_tabs.return_value = '\t\t'
        self.statements.set_tabs()
        for statement in self.statements.iterate():
            assert statement.dump(True)[0] == '\n    '
        assert self.statements.dump(True)[-1] == '\n\t\t'

    def test_get_tabs(self):
        self.raw[0].insert(0, '\n \n  \t')
        self.statements.parse(self.raw)
        assert self.statements.get_tabs() == '  \t'
        self.statements.parse([])
        assert self.statements.get_tabs() == ''

    def test_parse_with_added_spaces(self):
        self.statements.parse(self.raw, add_spaces=True)
        assert self.statements.dump(True)[0] == ['sentence', ' ', 'one']

    def test_parse_bad_list_raises_error(self):
        from certbot import errors
        with pytest.raises(errors.MisconfigurationError):
            self.statements.parse('lol not a list')

    def test_parse_hides_trailing_whitespace(self):
        self.statements.parse(self.raw + ['\n\n  '])
        assert isinstance(self.statements.dump()[-1], list)
        assert self.statements.dump(True)[-1].isspace() is True
        assert self.statements.dump(True)[-1] == '\n\n  '

    def test_iterate(self):
        self.statements.parse(self.raw)
        expected = [['sentence', 'one'], ['sentence', 'two']]
        for i, elem in enumerate(self.statements.iterate(match=lambda x: 'sentence' in x)):
            assert expected[i] == elem.dump()


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
