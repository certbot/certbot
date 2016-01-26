"""Test for letsencrypt_nginx.nginxparser."""
import operator
import unittest

from letsencrypt_nginx.nginxparser import (
    RawNginxParser, ParseException, loads, load, dumps, dump)
from letsencrypt_nginx.tests import util


FIRST = operator.itemgetter(0)


class TestRawNginxParser(unittest.TestCase):
    """Test the raw low-level Nginx config parser."""

    def test_simple_comment_parsing(self):
        parsed = RawNginxParser("""
# hello world

""").parse()

        self.assertEqual(parsed, [
            [],
            ['#', ' hello world'],
            []
        ])

    def test_assignments(self):
        parsed = RawNginxParser("""
user www-data;
worker_processes 4;

pid /run/nginx.pid; # hello world

error_log  logs/error.log  notice; # not really

log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                  '$status $body_bytes_sent "$http_referer" '
                  '"$http_user_agent" "$http_x_forwarded_for"';
""").parse()

        self.assertEqual(parsed, [
            [],
            ['user', 'www-data'],
            ['worker_processes', '4'],
            [],
            ['pid', '/run/nginx.pid', '# hello world'],
            [],
            ['error_log', 'logs/error.log  notice', '# not really'],
            [],
            ['log_format', 'main  \'$remote_addr - $remote_user [$time_local] "$request" \'\n                  \'$status $body_bytes_sent "$http_referer" \'\n                  \'"$http_user_agent" "$http_x_forwarded_for"\'']

         ])

    def test_blocks(self):
        parsed = RawNginxParser('foo {}').parse()
        self.assertEqual(parsed, [[['foo'], []]])

        parsed = RawNginxParser('location /foo{}').parse()
        self.assertEqual(parsed, [[['location', '/foo'], []]])

        parsed = RawNginxParser('foo { bar foo; }').parse()
        self.assertEqual(parsed, [[['foo'], [['bar', 'foo']]]])

    def test_assignments2(self):
        parsed = RawNginxParser('root /test;').as_list()
        self.assertEqual(parsed, [['root', '/test']])

        parsed = RawNginxParser('root /test;'
                                 'foo bar;').as_list()
        self.assertEqual(parsed, [['root', '/test'], ['foo', 'bar']])

    def test_nested_blocks(self):
        parsed = RawNginxParser('foo { bar {} }').as_list()
        block, content = parsed[0]
        self.assertEqual(content[0], [['bar'], []])
        self.assertEqual(block[0], 'foo')

    def test_dump_as_string(self):
        dumped = dumps([
            ['user', 'www-data'],
            [['server'], [
                ['listen', '80'],
                ['server_name', 'foo.com'],
                ['root', '/home/ubuntu/sites/foo/'],
                [['location', '/status'], [
                    ['check_status', None],
                    [['types'], [['image/jpeg', 'jpg']]],
                ]]
            ]]])

        self.assertEqual(dumped,
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
                         '            image/jpeg jpg;\n'
                         '        }\n'
                         '    }\n'
                         '}\n')

    def test_parse_from_file(self):
        with open(util.get_data_filename('foo.conf')) as handle:
            parsed = load(handle)
        self.assertEqual(
            parsed,
            [['#', ' a test nginx conf'],
             ['user', 'www-data'],
             [],
             [['http'],
              [[['server'], [
                  ['listen', '*:80 default_server ssl'],
                  ['server_name', '*.www.foo.com *.www.example.com'],
                  ['root', '/home/ubuntu/sites/foo/'],
                  [],
                  [['location', '/status'], [
                      [['types'], [['image/jpeg', 'jpg']]],
                  ]],
                  [],
                  [['location', '~', r'case_sensitive\.php$'], [
                      ['index', 'index.php'],
                      ['root', '/var/root'],
                  ]],
                  [['location', '~*', r'case_insensitive\.php$'], []],
                  [['location', '=', r'exact_match\.php$'], []],
                  [['location', '^~', r'ignore_regex\.php$'], []],
                  []
              ]]]]]
        )


    def test_parse_from_file2(self):
        with open(util.get_data_filename('edge_cases.conf')) as handle:
            parsed = load(handle)
        self.assertEqual(
            parsed,
            [['#', ' This is not a valid nginx config file but it tests edge cases in valid nginx syntax'],
             [],
             [['server'], [['server_name', 'simple']]],
             [],
             [['server'],
              [['server_name', 'with.if'],
               [['location', '~', '^/services/.+$'],
                [[['if', '($request_filename ~* \\.(ttf|woff)$)'],
                  [['add_header', 'Access-Control-Allow-Origin "*"']]]]]]],
             [],
             [['server'],
              [['server_name', 'with.complicated.headers'],
               [],
               [['location', '~*', '\\.(?:gif|jpe?g|png)$'],
                [[],
                 ['add_header', 'Pragma public'],
                 ['add_header',
                  'Cache-Control  \'public, must-revalidate, proxy-revalidate\''
                  ' "test,;{}" foo'],
                 ['blah', '"hello;world"'],
                 [],
                 ['try_files', '$uri @rewrites']]]]]])

    def test_abort_on_parse_failure(self):
        with open(util.get_data_filename('broken.conf')) as handle:
            self.assertRaises(ParseException, load, handle)

    def test_comments(self):
        with open(util.get_data_filename('minimalistic_comments.conf')) as handle:
            parsed = load(handle)
        self.assertEqual(parsed, [
            ['#', " Use bar.conf when it's a full moon!"],
            ['include', 'foo.conf', '# Kilroy was here'],
            ['check_status', None],
            [],
            [['server'],
             [['#', ''],
              ['#', " Don't forget to open up your firewall!"],
              ['#', ''],
              ['listen', '1234'],
              ['#', ' listen 80;']]],
        ])

    def test_issue_518(self):
        parsed = loads('if ($http_accept ~* "webp") { set $webp "true"; }')

        self.assertEqual(parsed, [
            [['if', '($http_accept ~* "webp")'],
             [['set', '$webp "true"']]]
        ])


    def test_dump_as_file(self):
        with open(util.get_data_filename('nginx.conf')) as handle:
            parsed = util.filter_comments(load(handle))
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

        with open(util.get_data_filename('nginx.new.conf'), 'w') as handle:
            dump(parsed, handle)
        with open(util.get_data_filename('nginx.new.conf')) as handle:
            parsed_new = util.filter_comments(load(handle))
        self.assertEquals(parsed, parsed_new)

if __name__ == '__main__':
    unittest.main()  # pragma: no cover
