"""Test for certbot_nginx.nginxparser."""
import copy
import operator
import os
import unittest

from pyparsing import ParseException

from certbot_nginx.nginxparser import (
    RawNginxParser, loads, load, dumps, dump, UnspacedList)
from certbot_nginx.tests import util


FIRST = operator.itemgetter(0)


class TestRawNginxParser(unittest.TestCase):
    """Test the raw low-level Nginx config parser."""

    def test_assignments(self):
        parsed = RawNginxParser.assignment.parseString('root /test;').asList()
        self.assertEqual(parsed, ['root', ' ', '/test'])
        parsed = RawNginxParser.assignment.parseString('root /test;foo bar;').asList()
        self.assertEqual(parsed, ['root', ' ', '/test'], ['foo', ' ', 'bar'])

    def test_blocks(self):
        parsed = RawNginxParser.block.parseString('foo {}').asList()
        self.assertEqual(parsed, [[['foo', ' '], []]])
        parsed = RawNginxParser.block.parseString('location /foo{}').asList()
        self.assertEqual(parsed, [[['location', ' ', '/foo'], []]])
        parsed = RawNginxParser.block.parseString('foo { bar foo ; }').asList()
        self.assertEqual(parsed, [[['foo', ' '], [[' ', 'bar', ' ', 'foo '], ' ']]])

    def test_nested_blocks(self):
        parsed = RawNginxParser.block.parseString('foo { bar {} }').asList()
        block, content = FIRST(parsed)
        self.assertEqual(FIRST(content), [[' ', 'bar', ' '], []])
        self.assertEqual(FIRST(block), 'foo')

    def test_dump_as_string(self):
        dumped = dumps(UnspacedList([
            ['user', ' ', 'www-data'],
            [['\n', 'server', ' '], [
                ['\n    ', 'listen', ' ', '80'],
                ['\n    ', 'server_name', ' ', 'foo.com'],
                ['\n    ', 'root', ' ', '/home/ubuntu/sites/foo/'],
                [['\n\n    ', 'location', ' ', '/status', ' '], [
                    ['\n        ', 'check_status', ''],
                    [['\n\n        ', 'types', ' '],
                    [['\n            ', 'image/jpeg', ' ', 'jpg']]],
                ]]
            ]]]))

        self.assertEqual(dumped.split('\n'),
                         'user www-data;\n'
                         'server {\n'
                         '    listen 80;\n'
                         '    server_name foo.com;\n'
                         '    root /home/ubuntu/sites/foo/;\n'
                         '\n'
                         '    location /status {\n'
                         '        check_status;\n'
                         '\n'
                         '        types {\n'
                         '            image/jpeg jpg;}}}'.split('\n'))

    def test_parse_from_file(self):
        with open(util.get_data_filename('foo.conf')) as handle:
            parsed = util.filter_comments(load(handle))
        self.assertEqual(
            parsed,
            [['user', 'www-data'],
             [['http'],
              [[['server'], [
                  ['listen', '*:80 default_server ssl'],
                  ['server_name', '*.www.foo.com *.www.example.com'],
                  ['root', '/home/ubuntu/sites/foo/'],
                  [['location', '/status'], [
                      [['types'], [['image/jpeg', 'jpg']]],
                  ]],
                  [['location', '~', r'case_sensitive\.php$'], [
                      ['index', 'index.php'],
                      ['root', '/var/root'],
                  ]],
                  [['location', '~*', r'case_insensitive\.php$'], []],
                  [['location', '=', r'exact_match\.php$'], []],
                  [['location', '^~', r'ignore_regex\.php$'], []]
              ]]]]]
        )

    def test_parse_from_file2(self):
        with open(util.get_data_filename('edge_cases.conf')) as handle:
            parsed = util.filter_comments(load(handle))
        self.assertEqual(
            parsed,
            [[['server'], [['server_name', 'simple']]],
             [['server'],
              [['server_name', 'with.if'],
               [['location', '~', '^/services/.+$'],
                [[['if', '($request_filename ~* \\.(ttf|woff)$)'],
                  [['add_header', 'Access-Control-Allow-Origin "*"']]]]]]],
             [['server'],
              [['server_name', 'with.complicated.headers'],
               [['location', '~*', '\\.(?:gif|jpe?g|png)$'],
                [['add_header', 'Pragma public'],
                 ['add_header',
                  'Cache-Control  \'public, must-revalidate, proxy-revalidate\''
                  ' "test,;{}" foo'],
                 ['blah', '"hello;world"'],
                 ['try_files', '$uri @rewrites']]]]]])

    def test_abort_on_parse_failure(self):
        with open(util.get_data_filename('broken.conf')) as handle:
            self.assertRaises(ParseException, load, handle)

    def test_dump_as_file(self):
        with open(util.get_data_filename('nginx.conf')) as handle:
            parsed = load(handle)
        parsed[-1][-1].append(UnspacedList([['server'],
                               [['listen', ' ', '443 ssl'],
                                ['server_name', ' ', 'localhost'],
                                ['ssl_certificate', ' ', 'cert.pem'],
                                ['ssl_certificate_key', ' ', 'cert.key'],
                                ['ssl_session_cache', ' ', 'shared:SSL:1m'],
                                ['ssl_session_timeout', ' ', '5m'],
                                ['ssl_ciphers', ' ', 'HIGH:!aNULL:!MD5'],
                                [['location', ' ', '/'],
                                 [['root', ' ', 'html'],
                                  ['index', ' ', 'index.html index.htm']]]]]))

        with open(util.get_data_filename('nginx.new.conf'), 'w') as handle:
            dump(parsed, handle)
        with open(util.get_data_filename('nginx.new.conf')) as handle:
            parsed_new = load(handle)
        try:
            self.maxDiff = None
            self.assertEqual(parsed[0], parsed_new[0])
            self.assertEqual(parsed[1:], parsed_new[1:])
        finally:
            os.unlink(util.get_data_filename('nginx.new.conf'))

    def test_comments(self):
        with open(util.get_data_filename('minimalistic_comments.conf')) as handle:
            parsed = load(handle)

        with open(util.get_data_filename('minimalistic_comments.new.conf'), 'w') as handle:
            dump(parsed, handle)

        with open(util.get_data_filename('minimalistic_comments.new.conf')) as handle:
            parsed_new = load(handle)

        try:
            self.assertEqual(parsed, parsed_new)

            self.assertEqual(parsed_new, [
                ['#', " Use bar.conf when it's a full moon!"],
                ['include', 'foo.conf'],
                ['#', ' Kilroy was here'],
                ['check_status'],
                [['server'],
                 [['#', ''],
                  ['#', " Don't forget to open up your firewall!"],
                  ['#', ''],
                  ['listen', '1234'],
                  ['#', ' listen 80;']]],
            ])
        finally:
            os.unlink(util.get_data_filename('minimalistic_comments.new.conf'))

    def test_issue_518(self):
        parsed = loads('if ($http_accept ~* "webp") { set $webp "true"; }')

        self.assertEqual(parsed, [
            [['if', '($http_accept ~* "webp")'],
             [['set', '$webp "true"']]]
        ])

class TestUnspacedList(unittest.TestCase):
    """Test the UnspacedList data structure"""
    def setUp(self):
        self.a = ["\n    ", "things", " ", "quirk"]
        self.b = ["y", " "]
        self.l = self.a[:]
        self.l2 = self.b[:]
        self.ul = UnspacedList(self.l)
        self.ul2 = UnspacedList(self.l2)

    def test_construction(self):
        self.assertEqual(self.ul, ["things", "quirk"])
        self.assertEqual(self.ul2, ["y"])

    def test_append(self):
        ul3 = copy.deepcopy(self.ul)
        ul3.append("wise")
        self.assertEqual(ul3, ["things", "quirk", "wise"])
        self.assertEqual(ul3.spaced, self.a + ["wise"])

    def test_add(self):
        ul3 = self.ul + self.ul2
        self.assertEqual(ul3, ["things", "quirk", "y"])
        self.assertEqual(ul3.spaced, self.a + self.b)
        self.assertEqual(self.ul.spaced, self.a)
        ul3 = self.ul + self.l2
        self.assertEqual(ul3, ["things", "quirk", "y"])
        self.assertEqual(ul3.spaced, self.a + self.b)

    def test_extend(self):
        ul3 = copy.deepcopy(self.ul)
        ul3.extend(self.ul2)
        self.assertEqual(ul3, ["things", "quirk", "y"])
        self.assertEqual(ul3.spaced, self.a + self.b)
        self.assertEqual(self.ul.spaced, self.a)

    def test_set(self):
        ul3 = copy.deepcopy(self.ul)
        ul3[0] = "zither"
        l = ["\n ", "zather", "zest"]
        ul3[1] = UnspacedList(l)
        self.assertEqual(ul3, ["zither", ["zather", "zest"]])
        self.assertEqual(ul3.spaced, [self.a[0], "zither", " ", l])

    def test_get(self):
        self.assertRaises(IndexError, self.ul2.__getitem__, 2)
        self.assertRaises(IndexError, self.ul2.__getitem__, -3)

    def test_insert(self):
        x = UnspacedList(
                [['\n    ', 'listen', '       ', '69.50.225.155:9000'],
                ['\n    ', 'listen', '       ', '127.0.0.1'],
                ['\n    ', 'server_name', ' ', '.example.com'],
                ['\n    ', 'server_name', ' ', 'example.*'], '\n',
                ['listen', ' ', '5001 ssl']])
        x.insert(5, "FROGZ")
        self.assertEqual(x,
            [['listen', '69.50.225.155:9000'], ['listen', '127.0.0.1'],
            ['server_name', '.example.com'], ['server_name', 'example.*'],
            ['listen', '5001 ssl'], 'FROGZ'])
        self.assertEqual(x.spaced,
            [['\n    ', 'listen', '       ', '69.50.225.155:9000'],
            ['\n    ', 'listen', '       ', '127.0.0.1'],
            ['\n    ', 'server_name', ' ', '.example.com'],
            ['\n    ', 'server_name', ' ', 'example.*'], '\n',
            ['listen', ' ', '5001 ssl'],
            'FROGZ'])

    def test_rawlists(self):
        ul3 = copy.deepcopy(self.ul)
        ul3.insert(0, "some")
        ul3.append("why")
        ul3.extend(["did", "whether"])
        del ul3[2]
        self.assertEqual(ul3, ["some", "things", "why", "did", "whether"])

    def test_is_dirty(self):
        self.assertEqual(False, self.ul2.is_dirty())
        ul3 = UnspacedList([])
        ul3.append(self.ul)
        self.assertEqual(False, self.ul.is_dirty())
        self.assertEqual(True, ul3.is_dirty())
        ul4 = UnspacedList([[1], [2, 3, 4]])
        self.assertEqual(False, ul4.is_dirty())
        ul4[1][2] = 5
        self.assertEqual(True, ul4.is_dirty())


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
