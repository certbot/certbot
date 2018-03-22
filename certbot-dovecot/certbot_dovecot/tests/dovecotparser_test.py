"""Tests for certbot_dns_cloudxns.dns_cloudxns."""

import os
import unittest

import mock

from certbot_dovecot import dovecotparser
from certbot_dovecot.dovecotparser import DovecotParser


class DovecotParserTest(unittest.TestCase):
    def setUp(self):
        self.parser_instance = DovecotParser()

    def test_key_value(self):
        string = "x = 1 a b c,d ,e, f\n"
        parsed = self.parser_instance.parse_string(string).asList()

        result = [list(string[0:-1])]
        self.assertEqual(parsed, result)

    def test_variable_expansion(self):
        string = "key1 = $key2 value\n"
        parsed = self.parser_instance.parse_string(string).asList()

        result = [['key1', ' ', '=', ' ', '$key2', ' ', 'value']]
        self.assertEqual(parsed, result)

    def test_quoted_values(self):
        string = "key1 = 'value1' \"value2\"\n"
        parsed = self.parser_instance.parse_string(string).asList()

        result = [['key1', ' ', '=', ' ', '\'value1\'', ' ', '"value2"']]
        self.assertEqual(parsed, result)

    def test_empty_block(self):
        string = "block {\n}\n"
        parsed = self.parser_instance.parse_string(string).asList()

        result = [
                   [
                     ['block', ' ', '{'],
                     [],
                     ['}']
                   ]
                 ]
        self.assertEqual(parsed, result)

    def test_block_with_key_value(self):
        string = (
            "block {\n"
            "x = a\n"
            "}\n"
        )

        parsed = self.parser_instance.parse_string(string).asList()

        result = [
                   [
                     ['block', ' ', '{'],
                     [['x', ' ', '=', ' ', 'a']],
                     ['}']
                   ]
                 ]

        self.assertEqual(parsed, result)

    def test_block_with_two_words_title(self):
      string = (
        "namespace block {\n"
        "x = 1\n"
        "}\n"
      )

      parsed = self.parser_instance.parse_string(string).asList()

      result = [
                 [
                   ['namespace', ' ', 'block', ' ', '{'],
                   [['x', ' ', '=', ' ', '1']],
                   ['}']
                 ]
               ]

      self.assertEqual(parsed, result)

    def test_nested_blocks(self):
        string = (
            "block {\n"
            "block {\n"
            "x = y\n"
            "}\n"
            "\n"
            "}\n"
        )

        parsed = self.parser_instance.parse_string(string).asList()

        result = [[
                    ['block', ' ', '{'],
                    [
                      [
                        ['block', ' ', '{'],
                        [['x', ' ', '=', ' ', 'y']],
                        ['}']
                      ],
                    ],
                    ['\n', '}']
                  ]]

        self.assertEqual(parsed, result)

    def test_includes(self):
        string = "!include test1\n!include_try test2\n"
        parsed = self.parser_instance.parse_string(string).asList()

        result = [
            ['!include', ' ', 'test1'],
            ['!include_try', ' ', 'test2']
        ]

        self.assertEqual(parsed, result)

    def test_nested_items(self):
        string = (
            "x = y\n"
            "!include test\n"
            "block1 {\n"
              "a = b\n"
              "block2 {\n"
                "c = d\n"
              "}\n"
              "!include_try test2\n"
            "}\n"
        )

        parsed = self.parser_instance.parse_string(string).asList()

        result = [
          ['x', ' ', '=', ' ', 'y'],
          ['!include', ' ', 'test'],
          [
            ['block1', ' ', '{'],
            [
              ['a', ' ', '=', ' ', 'b'],
              [
                ['block2', ' ', '{'],
                [['c', ' ', '=', ' ', 'd']],
                ['}']
              ],
              ['!include_try', ' ', 'test2']
            ],
            ['}']
          ]
        ]

        self.assertEqual(parsed, result)

    def test_spacing(self):
        string = (
            "   block    {    \n"
            "\n\n  \n\n   x =     y    \n"
            "c=d\n\n"
            "\n   a     =      b       \n"
            "  }   "
        )

        parsed = self.parser_instance.parse_string(string).asList()

        result = [[
          ['   ', 'block', '    ', '{', '    '],
          [
            ['\n\n  \n\n   ', 'x', ' ', '=', '     ', 'y', '    '],
            ['c', '=', 'd'],
            ['\n\n   ', 'a', '     ', '=', '      ', 'b', '       ']
          ],
          ['  ', '}', '   ']
        ]]

        self.assertEqual(parsed, result)

    def test_comment(self):
      string = (
        "   # this is a comment"
      )

      parsed = self.parser_instance.parse_string(string).asList()

      result = [[
        '   ', '#', ' this is a comment'
      ]]

      self.assertEqual(parsed, result)

    def test_comment_after_item(self):
      string = (
        "x = y # this is a comment\n"
        "!include this_is_an_include # this is another comment\n"
        "!include_try include2 # this is a third comment\n"
        "block1 { # a third comment\n"
          "# comment 4\n"
        "} # comment 5\n"
      )

      parsed = self.parser_instance.parse_string(string).asList()

      result = [
        ['x', ' ', '=', ' ', 'y', ' ', '#', ' this is a comment'],
        [
          '!include', ' ', 'this_is_an_include', ' ',
          '#', ' this is another comment'
        ],
        ['!include_try', ' ', 'include2', ' ', '#', ' this is a third comment'],
        [
          ['block1', ' ', '{', ' ', '#', ' a third comment'],
          [
            ['#', ' comment 4']
          ],
          ['}', ' ', '#', ' comment 5']
        ]
      ]

      self.assertEqual(parsed, result)

    def test_parse_file(self):
        m = mock.mock_open(read_data='x = y\n')

        with mock.patch("certbot_dovecot.dovecotparser.open", m, create=True):
            parsed = self.parser_instance.parse_file('test').asList()

            result = [['x', ' ', '=', ' ', 'y']]
            self.assertEqual(parsed, result)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
