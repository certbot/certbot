"""Test for letsencrypt_nginx.nginxparser."""
import operator
import unittest

from letsencrypt_nginx.nginxparser import (
    RawNginxParser, load, dumps, dump)
from letsencrypt_nginx.tests import util


FIRST = operator.itemgetter(0)


class TestRawNginxParser(unittest.TestCase):
    """Test the raw low-level Nginx config parser."""

    def test_assignments(self):
        parsed = RawNginxParser.assignment.parseString('root /test;').asList()
        self.assertEqual(parsed, ['root', '/test'])
        parsed = RawNginxParser.assignment.parseString('root /test;'
                                                       'foo bar;').asList()
        self.assertEqual(parsed, ['root', '/test'], ['foo', 'bar'])

    def test_blocks(self):
        parsed = RawNginxParser.block.parseString('foo {}').asList()
        self.assertEqual(parsed, [[['foo'], []]])
        parsed = RawNginxParser.block.parseString('location /foo{}').asList()
        self.assertEqual(parsed, [[['location', '/foo'], []]])
        parsed = RawNginxParser.block.parseString('foo { bar foo; }').asList()
        self.assertEqual(parsed, [[['foo'], [['bar', 'foo']]]])

    def test_nested_blocks(self):
        parsed = RawNginxParser.block.parseString('foo { bar {} }').asList()
        block, content = FIRST(parsed)
        self.assertEqual(FIRST(content), [['bar'], []])
        self.assertEqual(FIRST(block), 'foo')

    def test_dump_as_string(self):
        dumped = dumps([
            ['user', 'www-data'],
            [['server'], [
                ['listen', '80'],
                ['server_name', 'foo.com'],
                ['root', '/home/ubuntu/sites/foo/'],
                [['location', '/status'], [
                    ['check_status'],
                    [['types'], [['image/jpeg', 'jpg']]],
                ]]
            ]]])

        self.assertEqual(dumped,
                         'user www-data;\n'
                         'server {\n'
                         '    listen 80;\n'
                         '    server_name foo.com;\n'
                         '    root /home/ubuntu/sites/foo/;\n \n'
                         '    location /status {\n'
                         '        check_status;\n \n'
                         '        types {\n'
                         '            image/jpeg jpg;\n'
                         '        }\n'
                         '    }\n'
                         '}')

    def test_parse_from_file(self):
        parsed = load(open(util.get_data_filename('foo.conf')))
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
        parsed = load(open(util.get_data_filename('edge_cases.conf')))
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

    def test_dump_as_file(self):
        parsed = load(open(util.get_data_filename('nginx.conf')))
        parsed[-1][-1].append([['server'],
                               [['listen', '443 ssl'],
                                ['server_name', 'localhost'],
                                ['ssl_certificate', 'cert.pem'],
                                ['ssl_certificate_key', 'cert.key'],
                                ['ssl_session_cache', 'shared:SSL:1m'],
                                ['ssl_session_timeout', '5m'],
                                ['ssl_ciphers', 'HIGH:!aNULL:!MD5'],
                                [['location', '/'],
                                 [['root', 'html'],
                                  ['index', 'index.html index.htm']]]]])
        _file = open(util.get_data_filename('nginx.new.conf'), 'w')
        dump(parsed, _file)
        _file.close()
        parsed_new = load(open(util.get_data_filename('nginx.new.conf')))
        self.assertEquals(parsed, parsed_new)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
