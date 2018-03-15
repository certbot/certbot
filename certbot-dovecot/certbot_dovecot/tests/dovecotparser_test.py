"""Tests for certbot_dns_cloudxns.dns_cloudxns."""

import os
import unittest

import mock

from certbot_dovecot import dovecotparser
from certbot_dovecot.dovecotparser import DovecotParser
from certbot_dovecot.dovecotparser import RawDovecotDumper


class DovecotParserTest(unittest.TestCase):
    def setUp(self):
        self.parser_instance = DovecotParser()

    def test_key_value(self):
        string = "x = 1 a b c,d ,e, f\n"
        parsed = self.parser_instance.parse_string(string).asList()

        result = [list(string[0:-1])]

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
        string = "!include test1 test2\n!include_try test3 test4\n"
        parsed = self.parser_instance.parse_string(string).asList()

        result = [
            ['!include', ' ', 'test1', ' ', 'test2'],
            ['!include_try', ' ', 'test3', ' ', 'test4']
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
            "\n   a     =      b       \n"
            "  }   "
        )

        parsed = self.parser_instance.parse_string(string).asList()

        result = [[
          ['   ', 'block', '    ', '{', '    '],
          [
            ['\n\n  \n\n   ', 'x', ' ', '=', '     ', 'y', '    '],
            ['\n   ', 'a', '     ', '=', '      ', 'b', '       ']
          ],
          ['  ', '}', '   ']
        ]]

        self.assertEqual(parsed, result)

    def test_parse_file(self):
        m = mock.mock_open(read_data='x = y\n')

        with mock.patch("certbot_dovecot.dovecotparser.open", m, create=True):
            parsed = self.parser_instance.parse_file('test').asList()

            result = [['x', ' ', '=', ' ', 'y']]

            self.assertEqual(parsed, result)

class RawDovecotDumperTest(unittest.TestCase):
    def test_key_value(self):
        tree = [[
          'x', ' ',
          '=', ' ',
          '1', ' ',
          'a', ' ',
          'b', ' ',
          'c', ',',
          'd', ' ', ',',
          'e', ',', ' ',
          'f'
        ]]

        result = "x = 1 a b c,d ,e, f\n"

        parsed = str(RawDovecotDumper(tree))

        self.assertEqual(parsed, result)

    def test_empty_block(self):
        tree = [
                 [
                   ['block', ' '],
                   []
                 ]
               ]

        result = "block {\n}\n"

        parsed = str(RawDovecotDumper(tree))

        self.assertEqual(parsed, result);

    def test_block_with_key_value(self):
        tree = [
                 [
                   ['block', ' '],
                   [['x', ' ', '=', ' ', 'a']],
                 ]
               ]

        result = (
            "block {\n"
            "x = a\n"
            "}\n"
        )

        parsed = str(RawDovecotDumper(tree))

        self.assertEqual(parsed, result);

    def test_nested_blocks(self):
        tree = [[
                  ['block', ' '],
                  [
                    [
                      ['block', ' '],
                      [['x', ' ', '=', ' ', 'y']],
                    ],
                    '\n'
                  ]
                ]]

        result = (
            "block {\n"
            "block {\n"
            "x = y\n"
            "}\n"
            "\n"
            "}\n"
        )

        parsed = str(RawDovecotDumper(tree))

        self.assertEqual(parsed, result)

    def test_includes(self):
        tree = [
            ['!include', ' ', 'test1', ' ', 'test2'],
            ['!include_try', ' ', 'test3', ' ', 'test4']
        ]

        result = "!include test1 test2\n!include_try test3 test4\n"

        parsed = str(RawDovecotDumper(tree))

        self.assertEqual(parsed, result)

    def test_nested_items(self):
        tree = [
          ['x', ' ', '=', ' ', 'y'],
          ['!include', ' ', 'test'],
          [
            ['block1', ' '],
            [
              ['a', ' ', '=', ' ', 'b'],
              [
                ['block2', ' '],
                [['c', ' ', '=', ' ', 'd']],
              ],
              ['!include_try', ' ', 'test2']
            ]
          ]
        ]

        result = (
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

        parsed = str(RawDovecotDumper(tree))

        self.assertEqual(parsed, result)

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
