import operator
import unittest

from letsencrypt.client.plugins.nginx.nginxparser import (RawNginxParser,
                                                          load, dumps, dump)
from letsencrypt.client.plugins.nginx.tests import util


first = operator.itemgetter(0)


class TestRawNginxParser(unittest.TestCase):

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
        block, content = first(parsed)
        self.assertEqual(first(content), [['bar'], []])

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
                         'user www-data;\n' +
                         'server {\n' +
                         '    listen 80;\n' +
                         '    server_name foo.com;\n' +
                         '    root /home/ubuntu/sites/foo/;\n \n' +
                         '    location /status {\n' +
                         '        check_status;\n \n' +
                         '        types {\n' +
                         '            image/jpeg jpg;\n' +
                         '        }\n' +
                         '    }\n' +
                         '}')

    def test_parse_from_file(self):
        parsed = load(open(util.get_data_filename('foo.conf')))
        self.assertEqual(
            parsed,
            [['user', 'www-data'],
             [['server'], [
                 ['listen', '*:80 default_server ssl'],
                 ['server_name', '*.www.foo.com *.www.example.com'],
                 ['root', '/home/ubuntu/sites/foo/'],
                 [['location', '/status'], [
                     ['check_status'],
                     [['types'], [['image/jpeg', 'jpg']]],
                 ]],
                 [['location', '~', 'case_sensitive\.php$'], [
                     ['hoge', 'hoge']
                 ]],
                 [['location', '~*', 'case_insensitive\.php$'], []],
                 [['location', '=', 'exact_match\.php$'], []],
                 [['location', '^~', 'ignore_regex\.php$'], []],
             ]]]
        )

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
        f = open(util.get_data_filename('nginx.new.conf'), 'w')
        dump(parsed, f)
        f.close()
        parsed_new = load(open(util.get_data_filename('nginx.new.conf')))
        self.assertEquals(parsed, parsed_new)


if __name__ == '__main__':
    unittest.main()
