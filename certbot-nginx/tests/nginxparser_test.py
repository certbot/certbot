"""Test for certbot_nginx._internal.nginxparser."""
import copy
import operator
import tempfile
import unittest

from pyparsing import ParseException

from certbot_nginx._internal.nginxparser import dump
from certbot_nginx._internal.nginxparser import dumps
from certbot_nginx._internal.nginxparser import load
from certbot_nginx._internal.nginxparser import loads
from certbot_nginx._internal.nginxparser import RawNginxParser
from certbot_nginx._internal.nginxparser import UnspacedList
import test_util as util

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
        self.assertEqual(parsed, [['foo', ' '], []])
        parsed = RawNginxParser.block.parseString('location /foo{}').asList()
        self.assertEqual(parsed, [['location', ' ', '/foo'], []])
        parsed = RawNginxParser.block.parseString('foo { bar foo ; }').asList()
        self.assertEqual(parsed, [['foo', ' '], [[' ', 'bar', ' ', 'foo', ' '], ' ']])

    def test_nested_blocks(self):
        parsed = RawNginxParser.block.parseString('foo { bar {} }').asList()
        block, content = parsed
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
                  ['listen', '*:80', 'default_server', 'ssl'],
                  ['server_name', '*.www.foo.com', '*.www.example.com'],
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
                [[['if', '($request_filename', '~*', '\\.(ttf|woff)$)'],
                  [['add_header', 'Access-Control-Allow-Origin', '"*"']]]]]]],
             [['server'],
              [['server_name', 'with.complicated.headers'],
               [['location', '~*', '\\.(?:gif|jpe?g|png)$'],
                [['add_header', 'Pragma', 'public'],
                 ['add_header',
                  'Cache-Control', '\'public, must-revalidate, proxy-revalidate\'',
                  '"test,;{}"', 'foo'],
                 ['blah', '"hello;world"'],
                 ['try_files', '$uri', '@rewrites']]]]]])

    def test_parse_from_file3(self):
        with open(util.get_data_filename('multiline_quotes.conf')) as handle:
            parsed = util.filter_comments(load(handle))
        self.assertEqual(
            parsed,
            [[['http'],
                [[['server'],
                    [['listen', '*:443'],
                    [['location', '/'],
                        [['body_filter_by_lua',
                          '\'ngx.ctx.buffered = (ngx.ctx.buffered or "")'
                          ' .. string.sub(ngx.arg[1], 1, 1000)\n'
                          '                            '
                          'if ngx.arg[2] then\n'
                          '                              '
                          'ngx.var.resp_body = ngx.ctx.buffered\n'
                          '                            end\'']]]]]]]])

    def test_abort_on_parse_failure(self):
        with open(util.get_data_filename('broken.conf')) as handle:
            self.assertRaises(ParseException, load, handle)

    def test_dump_as_file(self):
        with open(util.get_data_filename('nginx.conf')) as handle:
            parsed = load(handle)
        parsed[-1][-1].append(UnspacedList([['server'],
                               [['listen', ' ', '443', ' ', 'ssl'],
                                ['server_name', ' ', 'localhost'],
                                ['ssl_certificate', ' ', 'cert.pem'],
                                ['ssl_certificate_key', ' ', 'cert.key'],
                                ['ssl_session_cache', ' ', 'shared:SSL:1m'],
                                ['ssl_session_timeout', ' ', '5m'],
                                ['ssl_ciphers', ' ', 'HIGH:!aNULL:!MD5'],
                                [['location', ' ', '/'],
                                 [['root', ' ', 'html'],
                                  ['index', ' ', 'index.html', ' ', 'index.htm']]]]]))

        with tempfile.TemporaryFile(mode='w+t') as f:
            dump(parsed, f)
            f.seek(0)
            parsed_new = load(f)
        self.assertEqual(parsed, parsed_new)

    def test_comments(self):
        with open(util.get_data_filename('minimalistic_comments.conf')) as handle:
            parsed = load(handle)

        with tempfile.TemporaryFile(mode='w+t') as f:
            dump(parsed, f)
            f.seek(0)
            parsed_new = load(f)

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

    def test_issue_518(self):
        parsed = loads('if ($http_accept ~* "webp") { set $webp "true"; }')

        self.assertEqual(parsed, [
            [['if', '($http_accept', '~*', '"webp")'],
             [['set', '$webp', '"true"']]]
        ])

    def test_comment_in_block(self):
        parsed = loads("""http {
          # server{
          }""")

        self.assertEqual(parsed, [
            [['http'],
             [['#', ' server{']]]
        ])

    def test_access_log(self):
        # see issue #3798
        parsed = loads('access_log syslog:server=unix:/dev/log,facility=auth,'
            'tag=nginx_post,severity=info custom;')

        self.assertEqual(parsed, [
            ['access_log',
             'syslog:server=unix:/dev/log,facility=auth,tag=nginx_post,severity=info',
             'custom']
        ])

    def test_add_header(self):
        # see issue #3798
        parsed = loads('add_header Cache-Control no-cache,no-store,must-revalidate,max-age=0;')

        self.assertEqual(parsed, [
            ['add_header', 'Cache-Control', 'no-cache,no-store,must-revalidate,max-age=0']
        ])

    def test_map_then_assignment_in_block(self):
        # see issue #3798
        test_str = """http {
            map $http_upgrade $connection_upgrade {
              default upgrade;
              ''      close;
              "~Opera Mini" 1;
              *.example.com 1;
            }
            one;
        }"""
        parsed = loads(test_str)
        self.assertEqual(parsed, [
            [['http'], [
                [['map', '$http_upgrade', '$connection_upgrade'], [
                    ['default', 'upgrade'],
                    ["''", 'close'],
                    ['"~Opera Mini"', '1'],
                    ['*.example.com', '1']
                ]],
                ['one']
            ]]
        ])

    def test_variable_name(self):
        parsed = loads('try_files /typo3temp/tx_ncstaticfilecache/'
            '$host${request_uri}index.html @nocache;')

        self.assertEqual(parsed, [
            ['try_files',
             '/typo3temp/tx_ncstaticfilecache/$host${request_uri}index.html',
             '@nocache']
        ])

    def test_weird_blocks(self):
        test = r"""
            if ($http_user_agent ~ MSIE) {
                rewrite ^(.*)$ /msie/$1 break;
            }

            if ($http_cookie ~* "id=([^;]+)(?:;|$)") {
               set $id $1;
            }

            if ($request_method = POST) {
               return 405;
            }

            if ($request_method) {
               return 403;
            }

            if ($args ~ post=140){
              rewrite ^ http://example.com/;
            }

            location ~ ^/users/(.+\.(?:gif|jpe?g|png))$ {
              alias /data/w3/images/$1;
            }

            proxy_set_header X-Origin-URI ${scheme}://${http_host}/$request_uri;
        """
        parsed = loads(test)
        self.assertEqual(parsed, [[['if', '($http_user_agent', '~', 'MSIE)'],
            [['rewrite', '^(.*)$', '/msie/$1', 'break']]],
            [['if', '($http_cookie', '~*', '"id=([^;]+)(?:;|$)")'], [['set', '$id', '$1']]],
            [['if', '($request_method', '=', 'POST)'], [['return', '405']]],
            [['if', '($request_method)'],
            [['return', '403']]], [['if', '($args', '~', 'post=140)'],
            [['rewrite', '^', 'http://example.com/']]],
            [['location', '~', '^/users/(.+\\.(?:gif|jpe?g|png))$'],
            [['alias', '/data/w3/images/$1']]],
            ['proxy_set_header', 'X-Origin-URI', '${scheme}://${http_host}/$request_uri']]
        )

    def test_edge_cases(self):
        # quotes
        parsed = loads(r'"hello\""; # blah "heh heh"')
        self.assertEqual(parsed, [['"hello\\""'], ['#', ' blah "heh heh"']])

        # if with comment
        parsed = loads("""if ($http_cookie ~* "id=([^;]+)(?:;|$)") { # blah )
            }""")
        self.assertEqual(parsed, [[['if', '($http_cookie', '~*', '"id=([^;]+)(?:;|$)")'],
            [['#', ' blah )']]]])

        # end paren
        test = """
            one"test";
            ("two");
            "test")red;
            "test")"blue";
            "test")"three;
            (one"test")one;
            one";
            one"test;
            one"test"one;
        """
        parsed = loads(test)
        self.assertEqual(parsed, [
            ['one"test"'],
            ['("two")'],
            ['"test")red'],
            ['"test")"blue"'],
            ['"test")"three'],
            ['(one"test")one'],
            ['one"'],
            ['one"test'],
            ['one"test"one']
        ])
        self.assertRaises(ParseException, loads, r'"test"one;') # fails
        self.assertRaises(ParseException, loads, r'"test;') # fails

        # newlines
        test = """
            server_name foo.example.com bar.example.com \
                        baz.example.com qux.example.com;
            server_name foo.example.com bar.example.com
                        baz.example.com qux.example.com;
        """
        parsed = loads(test)
        self.assertEqual(parsed, [
            ['server_name', 'foo.example.com', 'bar.example.com',
                'baz.example.com', 'qux.example.com'],
            ['server_name', 'foo.example.com', 'bar.example.com',
                'baz.example.com', 'qux.example.com']
        ])

        # variable weirdness
        parsed = loads("directive $var ${var} $ ${};")
        self.assertEqual(parsed, [['directive', '$var', '${var}', '$', '${}']])
        self.assertRaises(ParseException, loads, "server {server_name test.com};")
        self.assertEqual(loads("blag${dfgdfg};"), [['blag${dfgdfg}']])
        self.assertRaises(ParseException, loads, "blag${dfgdf{g};")


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
                ['listen', ' ', '5001', ' ', 'ssl']])
        x.insert(5, "FROGZ")
        self.assertEqual(x,
            [['listen', '69.50.225.155:9000'], ['listen', '127.0.0.1'],
            ['server_name', '.example.com'], ['server_name', 'example.*'],
            ['listen', '5001', 'ssl'], 'FROGZ'])
        self.assertEqual(x.spaced,
            [['\n    ', 'listen', '       ', '69.50.225.155:9000'],
            ['\n    ', 'listen', '       ', '127.0.0.1'],
            ['\n    ', 'server_name', ' ', '.example.com'],
            ['\n    ', 'server_name', ' ', 'example.*'], '\n',
            ['listen', ' ', '5001', ' ', 'ssl'],
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
