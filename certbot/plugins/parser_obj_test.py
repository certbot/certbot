""" Tests for functions and classes in parser_obj.py """

import unittest
import mock

from certbot.plugins.parser_obj import parse_raw
from certbot.plugins.parser_obj import COMMENT_BLOCK

class CommentHelpersTest(unittest.TestCase):
    def test_is_comment(self):
        from certbot.plugins.parser_obj import is_comment
        self.assertTrue(is_comment(parse_raw(['#'])))
        self.assertTrue(is_comment(parse_raw(['#', ' literally anything else'])))
        self.assertFalse(is_comment(parse_raw(['not', 'even', 'a', 'comment'])))

    def test_is_certbot_comment(self):
        from certbot.plugins.parser_obj import is_certbot_comment
        self.assertTrue(is_certbot_comment(
            parse_raw(COMMENT_BLOCK)))
        self.assertFalse(is_certbot_comment(
            parse_raw(['#', ' not a certbot comment'])))
        self.assertFalse(is_certbot_comment(
            parse_raw(['#', ' managed by Certbot', ' also not a certbot comment'])))
        self.assertFalse(is_certbot_comment(
            parse_raw(['not', 'even', 'a', 'comment'])))

    def test_certbot_comment(self):
        from certbot.plugins.parser_obj import certbot_comment, is_certbot_comment
        comment = certbot_comment(None)
        self.assertTrue(is_certbot_comment(comment))
        self.assertEqual(comment.dump(), COMMENT_BLOCK)
        self.assertEqual(comment.dump(True), ['    '] + COMMENT_BLOCK)
        self.assertEqual(certbot_comment(None, 2).dump(True),
            ['  '] + COMMENT_BLOCK)

class ParsingHooksTest(unittest.TestCase):
    def test_is_sentence(self):
        from certbot.plugins.parser_obj import is_sentence
        self.assertTrue(is_sentence([]))
        self.assertTrue(is_sentence(['']))
        self.assertTrue(is_sentence(['word']))
        self.assertTrue(is_sentence(['two', 'words']))
        self.assertFalse(is_sentence([[]]))
        self.assertFalse(is_sentence(['word', []]))

    def test_is_block(self):
        from certbot.plugins.parser_obj import is_bloc
        self.assertFalse(is_bloc([]))
        self.assertFalse(is_bloc(['']))
        self.assertFalse(is_bloc(['two', 'words']))
        self.assertFalse(is_bloc([[[]], []]))
        self.assertFalse(is_bloc([['block_name'], ['hi', []], []]))
        self.assertFalse(is_bloc([['block_name'], 'lol']))
        self.assertTrue(is_bloc([['block_name'], ['hi', []]]))
        self.assertTrue(is_bloc([[], []]))
        self.assertTrue(is_bloc([['block_name'], [['many'], ['statements'], 'here']]))

    def test_parse_raw(self):
        from certbot.plugins.parser_obj import ParseContext
        mock_true = lambda x: True
        mock_false = lambda x: False
        fake_parser1 = mock.Mock()
        fake_parser2 = mock.Mock()
        # First encountered "match" should parse.
        fake_context = ParseContext("", "", None, None,
            ((mock_true, fake_parser1), (mock_true, fake_parser2)))
        parse_raw([], fake_context)
        fake_parser1.called_once()
        fake_parser2.not_called()
        fake_parser1.reset_mock()
        # "match" that returns False shouldn't parse.
        fake_context = ParseContext("", "", None, None,
            ((mock_false, fake_parser1), (mock_true, fake_parser2)))
        parse_raw([], fake_context)
        fake_parser1.not_called()
        fake_parser2.called_once()

    def test_parse_raw_no_match(self):
        from certbot.plugins.parser_obj import ParseContext
        from certbot import errors
        mock_false = lambda x: False
        fake_parser1 = mock.Mock()
        fake_context = ParseContext("", "", None, None,
            ((mock_false, fake_parser1),))
        self.assertRaises(errors.MisconfigurationError, parse_raw, [], fake_context)
        fake_context = ParseContext("", "", None, None, tuple())
        self.assertRaises(errors.MisconfigurationError, parse_raw, [], fake_context)

    def test_parse_raw_passes_add_spaces(self):
        from certbot.plugins.parser_obj import ParseContext
        fake_parser1 = mock.Mock()
        fake_context = ParseContext("", "", None, None,
            ((lambda x: True, fake_parser1),))
        parse_raw([], fake_context)
        fake_parser1.parse.called_with([None])
        parse_raw([], fake_context, add_spaces=True)
        fake_parser1.parse.called_with([None, True])

    def test_parse_raw_uses_default_hooks(self):
        from certbot.plugins.parser_obj import ParseContext
        from certbot.plugins.parser_obj import DEFAULT_PARSING_HOOKS
        default_context = ParseContext("", "")
        self.assertEqual(default_context.parsing_hooks, DEFAULT_PARSING_HOOKS)

class SentenceTest(unittest.TestCase):
    def setUp(self):
        from certbot.plugins.parser_obj import Sentence
        self.sentence = Sentence(None)

    def test_parse_bad_sentence_raises_error(self):
        from certbot import errors
        self.assertRaises(errors.MisconfigurationError, self.sentence.parse, 'lol')
        self.assertRaises(errors.MisconfigurationError, self.sentence.parse, [[]])
        self.assertRaises(errors.MisconfigurationError, self.sentence.parse, [5])

    def test_parse_sentence_words_hides_spaces(self):
        og_sentence = ['\r\n', 'hello', ' ', ' ', '\t\n  ', 'lol', ' ', 'spaces']
        self.sentence.parse(og_sentence)
        self.assertEquals(self.sentence.words, ['hello', 'lol', 'spaces'])
        self.assertEquals(self.sentence.dump(), ['hello', 'lol', 'spaces'])
        self.assertEquals(self.sentence.dump(True), og_sentence)

    def test_parse_sentence_with_add_spaces(self):
        self.sentence.parse(['hi', 'there'], add_spaces=True)
        self.assertEquals(self.sentence.dump(True), ['hi', ' ', 'there'])
        self.sentence.parse(['one', ' ', 'space', 'none'], add_spaces=True)
        self.assertEquals(self.sentence.dump(True), ['one', ' ', 'space', ' ', 'none'])

    def test_iterate(self):
        expected = [['1', '2', '3']]
        self.sentence.parse(['1', ' ', '2', ' ', '3'])
        for i, sentence in enumerate(self.sentence.iterate()):
            self.assertEquals(sentence.dump(), expected[i])

    def test_set_tabs(self):
        self.sentence.parse(['tabs', 'pls'], add_spaces=True)
        self.sentence.set_tabs()
        self.assertEquals(self.sentence.dump(True)[0], '\n    ')
        self.sentence.parse(['tabs', 'pls'], add_spaces=True)
        self.sentence.set_tabs('  \t', newline='\r\n')
        self.assertEquals(self.sentence.dump(True)[0], '\r\n  \t')

    def test_get_tabs(self):
        self.sentence.parse(['no', 'tabs'])
        self.assertEquals(self.sentence.get_tabs(), '')
        self.sentence.parse(['\n \n  ', 'tabs'])
        self.assertEquals(self.sentence.get_tabs(), '  ')
        self.sentence.parse(['  \n\t  ', 'tabs'])
        self.assertEquals(self.sentence.get_tabs(), '\t  ')
        self.sentence.parse(['\n\t \n', 'tabs'])
        self.assertEquals(self.sentence.get_tabs(), '')

class BlocTest(unittest.TestCase):
    def setUp(self):
        from certbot.plugins.parser_obj import Bloc
        self.bloc = Bloc(None)
        self.name = ['server', 'name']
        self.contents = [['thing', '1'], ['thing', '2'], ['another', 'one']]
        self.bloc.parse([self.name, self.contents])

    def test_iterate(self):
        # Iterates itself normally
        self.assertEquals(self.bloc, next(self.bloc.iterate()))
        # Iterates contents while expanded
        expected = [self.bloc.dump()] + self.contents
        for i, elem in enumerate(self.bloc.iterate(expanded=True)):
            self.assertEquals(expected[i], elem.dump())

    def test_iterate_match(self):
        # can match on contents while expanded
        from certbot.plugins.parser_obj import Bloc, Sentence
        expected = [['thing', '1'], ['thing', '2']]
        for i, elem in enumerate(self.bloc.iterate(expanded=True,
            match=lambda x: isinstance(x, Sentence) and 'thing' in x.words)):
            self.assertEquals(expected[i], elem.dump())
        # can match on self
        self.assertEquals(self.bloc, next(self.bloc.iterate(
            expanded=True,
            match=lambda x: isinstance(x, Bloc) and 'server' in x._data[0])))

    def test_parse_with_added_spaces(self):
        import copy
        self.bloc.parse([copy.copy(self.name), self.contents], add_spaces=True)
        self.assertEquals(self.bloc.dump(), [self.name, self.contents])
        self.assertEquals(self.bloc.dump(True), [
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
        self.assertEquals(self.bloc.names.dump(True)[0], '\n    ')
        for elem in self.bloc.contents.dump(True)[:-1]:
            self.assertEquals(elem[0], '\n        ')
        self.assertEquals(self.bloc.contents.dump(True)[-1][0], '\n')

    def test_get_tabs(self):
        self.bloc.parse([[' \n  \t', 'lol'], []])
        self.assertEquals(self.bloc.get_tabs(), '  \t')

class StatementsTest(unittest.TestCase):
    def setUp(self):
        from certbot.plugins.parser_obj import Statements
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
            self.assertEquals(statement.dump(True)[0], '\n    ')

    def test_set_tabs_with_parent(self):
        # Trailing whitespace should inherit from parent tabbing.
        self.statements.parse(self.raw)
        self.statements.context = mock.Mock()
        self.statements.context.parent.get_tabs.return_value = '\t\t'
        self.statements.set_tabs()
        for statement in self.statements.iterate():
            self.assertEquals(statement.dump(True)[0], '\n    ')
        self.assertEquals(self.statements.dump(True)[-1], '\n\t\t')

    def test_get_tabs(self):
        self.raw[0].insert(0, '\n \n  \t')
        self.statements.parse(self.raw)
        self.assertEquals(self.statements.get_tabs(), '  \t')
        self.statements.parse([])
        self.assertEquals(self.statements.get_tabs(), '')

    def test_parse_with_added_spaces(self):
        self.statements.parse(self.raw, add_spaces=True)
        self.assertEquals(self.statements.dump(True)[0], ['sentence', ' ', 'one'])

    def test_parse_bad_list_raises_error(self):
        from certbot import errors
        self.assertRaises(errors.MisconfigurationError, self.statements.parse, 'lol not a list')

    def test_parse_hides_trailing_whitespace(self):
        self.statements.parse(self.raw + ['\n\n  '])
        self.assertTrue(isinstance(self.statements.dump()[-1], list))
        self.assertTrue(self.statements.dump(True)[-1].isspace())
        self.assertEquals(self.statements.dump(True)[-1], '\n\n  ')

    def test_iterate(self):
        self.statements.parse(self.raw)
        expected = [['sentence', 'one'], ['sentence', 'two']]
        for i, elem in enumerate(self.statements.iterate(match=lambda x: 'sentence' in x)):
            self.assertEquals(expected[i], elem.dump())

    def test_get_type(self):
        import copy
        from certbot.plugins.parser_obj import Sentence, Bloc
        expected = copy.deepcopy(self.raw)
        server_bloc = [['server', 'bloc'], []]
        self.raw.insert(1, server_bloc)
        self.statements.parse(self.raw)
        for i, elem in enumerate(self.statements.get_type(Sentence)):
            self.assertEquals(expected[i], elem.dump())
        expected = expected[0:2]
        for i, elem in enumerate(self.statements.get_type(Sentence,
                match_func=lambda x: 'sentence' in x.words)):
            self.assertEquals(expected[i], elem.dump())
        expected = [server_bloc]
        for i, elem in enumerate(self.statements.get_type(Bloc)):
            self.assertEquals(expected[i], elem.dump())

    def test_add_sentence(self):
        self.statements.parse(self.raw_spaced)
        self.statements.add_statement(['added', 'statement'])
        self.assertEquals(self.statements.dump(True)[-3], ['\n  ', 'added', ' ', 'statement'])
        self.assertEquals(self.statements.dump(True)[-2], ['    ', '#', ' managed by Certbot'])

    def test_add_sentence_at_top(self):
        self.statements.parse(self.raw_spaced)
        self.statements.add_statement(['added', 'statement'], True)
        self.assertEquals(self.statements.dump(True)[0], ['\n  ', 'added', ' ', 'statement'])
        self.assertEquals(self.statements.dump(True)[1], ['    ', '#', ' managed by Certbot'])

    def test_add_comment(self):
        self.statements.parse(self.raw_spaced)
        self.statements.add_statement(['#', 'comment'], False)
        self.statements.add_statement(['#', 'comment'], True)
        self.assertEquals(self.statements.dump(True)[-2], ['\n  ', '#', ' ', 'comment'])
        self.assertEquals(self.statements.dump(True)[0], ['\n  ', '#', ' ', 'comment'])

    def test_add_bloc(self):
        self.statements.parse(self.raw_spaced)
        self.statements.add_statement([
            ['server', 'name'],
            [['statement', 'one'], ['statement', 'two']]])
        dump = self.statements.dump(True)
        expected_block = [['\n  ', 'server', ' ', 'name', ' '], [
            ['\n      ', 'statement', ' ', 'one'],
            ['\n      ', 'statement', ' ', 'two'],
            '\n  ']]
        self.assertEquals(expected_block, dump[-3])
        self.assertEquals(['    ', '#', ' managed by Certbot'], dump[-2])

    def test_remove_statement(self):
        from certbot.plugins.parser_obj import Sentence
        self.statements.parse(self.raw_spaced)
        self.statements.remove_statements(match_func=lambda statement:
            isinstance(statement, Sentence) and 'sentence' in statement.words)
        self.assertEqual(self.statements.dump(), [['and', 'another']])

    def test_remove_statement_removes_comment(self):
        from certbot.plugins.parser_obj import Sentence
        self.statements.parse(self.raw_spaced)
        self.statements.add_statement(['fake', 'news', 'sentence'])
        self.statements.add_statement(['fake', 'news', 'sentence'], True)
        self.statements.remove_statements(match_func=lambda statement:
            isinstance(statement, Sentence) and 'sentence' in statement.words)
        self.assertEqual(self.statements.dump(), [['and', 'another']])

    def test_replace_statement(self):
        from certbot.plugins.parser_obj import Sentence
        self.statements.parse(self.raw_spaced)
        self.statements.replace_statement(['new', 'sentence'], match_func=lambda statement:
            isinstance(statement, Sentence) and 'two' in statement.words)
        self.assertEqual(self.statements.dump()[1], ['new', 'sentence'])
        self.assertEqual(self.statements.dump()[2], ['#', ' managed by Certbot'])

    def test_replace_statement_twice(self):
        from certbot.plugins.parser_obj import Sentence
        self.statements.parse(self.raw_spaced)
        self.statements.replace_statement(['new', 'sentence'], match_func=lambda statement:
            isinstance(statement, Sentence) and 'two' in statement.words)
        self.statements.replace_statement(['renew', 'sentence'], match_func=lambda statement:
            isinstance(statement, Sentence) and 'new' in statement.words)
        self.assertEqual(self.statements.dump()[1], ['renew', 'sentence'])
        self.assertEqual(self.statements.dump()[2], ['#', ' managed by Certbot'])
        self.assertEqual(self.statements.dump()[3], ['and', 'another'])

    def test_replace_statement_adds_backup(self):
        self.statements.replace_statement(['new', 'sentence'], match_func=lambda statement: False)
        self.assertEqual(self.statements.dump()[-2], ['new', 'sentence'])
        self.assertEqual(self.statements.dump()[-1], ['#', ' managed by Certbot'])
        self.statements.replace_statement(['new', 'sentence'],
            match_func=lambda statement: False, insert_at_top=True)
        self.assertEqual(self.statements.dump()[0], ['new', 'sentence'])
        self.assertEqual(self.statements.dump()[1], ['#', ' managed by Certbot'])

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
