""" Tests for functions and classes in parser_obj.py """

import unittest
import mock

from certbot_nginx.parser_obj import parse_raw
from certbot_nginx.parser_obj import COMMENT_BLOCK

class CommentHelpersTest(unittest.TestCase):
    def test_is_comment(self):
        from certbot_nginx.parser_obj import _is_comment
        self.assertTrue(_is_comment(parse_raw(['#'])))
        self.assertTrue(_is_comment(parse_raw(['#', ' literally anything else'])))
        self.assertFalse(_is_comment(parse_raw(['not', 'even', 'a', 'comment'])))

    def test_is_certbot_comment(self):
        from certbot_nginx.parser_obj import _is_certbot_comment
        self.assertTrue(_is_certbot_comment(
            parse_raw(COMMENT_BLOCK)))
        self.assertFalse(_is_certbot_comment(
            parse_raw(['#', ' not a certbot comment'])))
        self.assertFalse(_is_certbot_comment(
            parse_raw(['#', ' managed by Certbot', ' also not a certbot comment'])))
        self.assertFalse(_is_certbot_comment(
            parse_raw(['not', 'even', 'a', 'comment'])))

    def test_certbot_comment(self):
        from certbot_nginx.parser_obj import _certbot_comment, _is_certbot_comment
        comment = _certbot_comment(None)
        self.assertTrue(_is_certbot_comment(comment))
        self.assertEqual(comment.dump(), COMMENT_BLOCK)
        self.assertEqual(comment.dump(True), ['    '] + COMMENT_BLOCK)
        self.assertEqual(_certbot_comment(None, 2).dump(True),
            ['  '] + COMMENT_BLOCK)

class ParsingHooksTest(unittest.TestCase):
    def test_is_sentence(self):
        from certbot_nginx.parser_obj import Sentence
        self.assertFalse(Sentence.should_parse([]))
        self.assertTrue(Sentence.should_parse(['']))
        self.assertTrue(Sentence.should_parse(['word']))
        self.assertTrue(Sentence.should_parse(['two', 'words']))
        self.assertFalse(Sentence.should_parse([[]]))
        self.assertFalse(Sentence.should_parse(['word', []]))

    def test_is_block(self):
        from certbot_nginx.parser_obj import Block
        self.assertFalse(Block.should_parse([]))
        self.assertFalse(Block.should_parse(['']))
        self.assertFalse(Block.should_parse(['two', 'words']))
        self.assertFalse(Block.should_parse([[[]], []]))
        self.assertFalse(Block.should_parse([['block_name'], ['hi', []], []]))
        self.assertFalse(Block.should_parse([['block_name'], 'lol']))
        self.assertTrue(Block.should_parse([['block_name'], ['hi', []]]))
        self.assertTrue(Block.should_parse([['hello'], []]))
        self.assertTrue(Block.should_parse([['block_name'], [['many'], ['statements'], 'here']]))
        self.assertTrue(Block.should_parse([['if', ' ', '(whatever)'], ['hi']]))

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

    @mock.patch("certbot_nginx.parser_obj.Parsable.parsing_hooks")
    def test_parse_raw_no_match(self, parsing_hooks):
        from certbot import errors
        fake_parser1 = mock.Mock()
        fake_parser1.should_parse = lambda x: False
        parsing_hooks.return_value = (fake_parser1,)
        self.assertRaises(errors.MisconfigurationError, parse_raw, [])
        parsing_hooks.return_value = tuple()
        self.assertRaises(errors.MisconfigurationError, parse_raw, [])

    def test_parse_raw_passes_add_spaces(self):
        fake_parser1 = mock.Mock()
        fake_parser1.should_parse = lambda x: True
        parse_raw([])
        fake_parser1.parse.called_with([None])
        parse_raw([], add_spaces=True)
        fake_parser1.parse.called_with([None, True])

class SentenceTest(unittest.TestCase):
    def setUp(self):
        from certbot_nginx.parser_obj import Sentence
        self.sentence = Sentence(None)

    def test_parse_bad_sentence_raises_error(self):
        from certbot import errors
        self.assertRaises(errors.MisconfigurationError, self.sentence.parse, 'lol')
        self.assertRaises(errors.MisconfigurationError, self.sentence.parse, [[]])
        self.assertRaises(errors.MisconfigurationError, self.sentence.parse, [5])

    def test_parse_sentence_words_hides_spaces(self):
        og_sentence = ['\r\n', 'hello', ' ', ' ', '\t\n  ', 'lol', ' ', 'spaces']
        self.sentence.parse(og_sentence)
        self.assertEqual(self.sentence.words, ['hello', 'lol', 'spaces'])
        self.assertEqual(self.sentence.dump(), ['hello', 'lol', 'spaces'])
        self.assertEqual(self.sentence.dump(True), og_sentence)

    def test_parse_sentence_with_add_spaces(self):
        self.sentence.parse(['hi', 'there'], add_spaces=True)
        self.assertEqual(self.sentence.dump(True), ['hi', ' ', 'there'])
        self.sentence.parse(['one', ' ', 'space', 'none'], add_spaces=True)
        self.assertEqual(self.sentence.dump(True), ['one', ' ', 'space', ' ', 'none'])

    def test_iterate(self):
        expected = [['1', '2', '3']]
        self.sentence.parse(['1', ' ', '2', ' ', '3'])
        for i, sentence in enumerate(self.sentence.iterate()):
            self.assertEqual(sentence.dump(), expected[i])

    def test_set_tabs(self):
        self.sentence.parse(['tabs', 'pls'], add_spaces=True)
        self.sentence.set_tabs()
        self.assertEqual(self.sentence.dump(True)[0], '\n    ')
        self.sentence.parse(['tabs', 'pls'], add_spaces=True)

    def test_get_tabs(self):
        self.sentence.parse(['no', 'tabs'])
        self.assertEqual(self.sentence.get_tabs(), '')
        self.sentence.parse(['\n \n  ', 'tabs'])
        self.assertEqual(self.sentence.get_tabs(), '  ')
        self.sentence.parse(['\n\t  ', 'tabs'])
        self.assertEqual(self.sentence.get_tabs(), '\t  ')
        self.sentence.parse(['\n\t \n', 'tabs'])
        self.assertEqual(self.sentence.get_tabs(), '')

class BlockTest(unittest.TestCase):
    def setUp(self):
        from certbot_nginx.parser_obj import Block
        self.bloc = Block(None)
        self.name = ['server', 'name']
        self.contents = [['thing', '1'], ['thing', '2'], ['another', 'one']]
        self.bloc.parse([self.name, self.contents])

    def test_iterate(self):
        # Iterates itself normally
        self.assertEqual(self.bloc, next(self.bloc.iterate()))
        # Iterates contents while expanded
        expected = [self.bloc.dump()] + self.contents
        for i, elem in enumerate(self.bloc.iterate(expanded=True)):
            self.assertEqual(expected[i], elem.dump())

    def test_iterate_match(self):
        # can match on contents while expanded
        from certbot_nginx.parser_obj import Block, Sentence
        expected = [['thing', '1'], ['thing', '2']]
        for i, elem in enumerate(self.bloc.iterate(expanded=True,
            match=lambda x: isinstance(x, Sentence) and 'thing' in x.words)):
            self.assertEqual(expected[i], elem.dump())
        # can match on self
        self.assertEqual(self.bloc, next(self.bloc.iterate(
            expanded=True,
            match=lambda x: isinstance(x, Block) and 'server' in x.names)))

    def test_parse_with_added_spaces(self):
        import copy
        self.bloc.parse([copy.copy(self.name), self.contents], add_spaces=True)
        self.assertEqual(self.bloc.dump(), [self.name, self.contents])
        self.assertEqual(self.bloc.dump(True), [
            ['server', ' ', 'name', ' '],
            [['thing', ' ', '1'],
             ['thing', ' ', '2'],
             ['another', ' ', 'one']]])

    def test_bad_parse_raises_error(self):
        from certbot import errors
        self.assertRaises(errors.MisconfigurationError, self.bloc.parse, [[[]], [[]]])
        self.assertRaises(errors.MisconfigurationError, self.bloc.parse, ['lol'])
        self.assertRaises(errors.MisconfigurationError, self.bloc.parse, ['fake', 'news'])

    def test_set_tabs(self):
        self.bloc.set_tabs()
        self.assertEqual(self.bloc.names.dump(True)[0], '\n    ')
        for elem in self.bloc.contents.dump(True)[:-1]:
            self.assertEqual(elem[0], '\n        ')
        self.assertEqual(self.bloc.contents.dump(True)[-1][0], '\n')

    def test_get_tabs(self):
        self.bloc.parse([[' \n  \t', 'lol'], []])
        self.assertEqual(self.bloc.get_tabs(), '  \t')

class StatementsTest(unittest.TestCase):
    def setUp(self):
        from certbot_nginx.parser_obj import Statements
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
            self.assertEqual(statement.dump(True)[0], '\n    ')

    def test_set_tabs_with_parent(self):
        # Trailing whitespace should inherit from parent tabbing.
        self.statements.parse(self.raw)
        self.statements.parent = mock.Mock()
        self.statements.parent.get_tabs.return_value = '\t\t'
        self.statements.set_tabs()
        for statement in self.statements.iterate():
            self.assertEqual(statement.dump(True)[0], '\n    ')
        self.assertEqual(self.statements.dump(True)[-1], '\n\t\t')

    def test_get_tabs(self):
        self.raw[0].insert(0, '\n \n  \t')
        self.statements.parse(self.raw)
        self.assertEqual(self.statements.get_tabs(), '  \t')
        self.statements.parse([])
        self.assertEqual(self.statements.get_tabs(), '')

    def test_parse_with_added_spaces(self):
        self.statements.parse(self.raw, add_spaces=True)
        self.assertEqual(self.statements.dump(True)[0], ['sentence', ' ', 'one'])

    def test_parse_bad_list_raises_error(self):
        from certbot import errors
        self.assertRaises(errors.MisconfigurationError, self.statements.parse, 'lol not a list')

    def test_parse_hides_trailing_whitespace(self):
        self.statements.parse(self.raw + ['\n\n  '])
        self.assertTrue(isinstance(self.statements.dump()[-1], list))
        self.assertTrue(self.statements.dump(True)[-1].isspace())
        self.assertEqual(self.statements.dump(True)[-1], '\n\n  ')

    def test_iterate(self):
        self.statements.parse(self.raw)
        expected = [['sentence', 'one'], ['sentence', 'two']]
        for i, elem in enumerate(self.statements.iterate(match=lambda x: 'sentence' in x)):
            self.assertEqual(expected[i], elem.dump())

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
