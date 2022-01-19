"""Tests for certbot_nginx._internal.parser."""
import glob
import re
import shutil
import unittest
from typing import List

from certbot import errors
from certbot.compat import os
from certbot_nginx._internal import nginxparser
from certbot_nginx._internal import obj
from certbot_nginx._internal import parser
import test_util as util


class NginxParserTest(util.NginxTest):
    """Nginx Parser Test."""

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_root_normalized(self):
        path = os.path.join(self.temp_dir, "etc_nginx/////"
                            "ubuntu_nginx/../../etc_nginx")
        nparser = parser.NginxParser(path)
        self.assertEqual(nparser.root, self.config_path)

    def test_root_absolute(self):
        curr_dir = os.getcwd()
        try:
            # On Windows current directory may be on a different drive than self.tempdir.
            # However a relative path between two different drives is invalid. So we move to
            # self.tempdir to ensure that we stay on the same drive.
            os.chdir(self.temp_dir)
            nparser = parser.NginxParser(os.path.relpath(self.config_path))
            self.assertEqual(nparser.root, self.config_path)
        finally:
            os.chdir(curr_dir)

    def test_root_no_trailing_slash(self):
        nparser = parser.NginxParser(self.config_path + os.path.sep)
        self.assertEqual(nparser.root, self.config_path)

    def test_load(self):
        """Test recursive conf file parsing.

        """
        nparser = parser.NginxParser(self.config_path)
        nparser.load()
        self.assertEqual({nparser.abs_path(x) for x in
                          ['foo.conf', 'nginx.conf', 'server.conf', 'mime.types',
                           'sites-enabled/default',
                           'sites-enabled/both.com',
                           'sites-enabled/example.com',
                           'sites-enabled/headers.com',
                           'sites-enabled/migration.com',
                           'sites-enabled/sslon.com',
                           'sites-enabled/globalssl.com',
                           'sites-enabled/ipv6.com',
                           'sites-enabled/ipv6ssl.com',
                           'sites-enabled/example.net']},
                         set(nparser.parsed.keys()))
        self.assertEqual([['server_name', 'somename', 'alias', 'another.alias']],
                         nparser.parsed[nparser.abs_path('server.conf')])
        self.assertEqual([[['server'], [['listen', '69.50.225.155:9000'],
                                        ['listen', '127.0.0.1'],
                                        ['server_name', '.example.com'],
                                        ['server_name', 'example.*']]]],
                         nparser.parsed[nparser.abs_path(
                             'sites-enabled/example.com')])

    def test_abs_path(self):
        nparser = parser.NginxParser(self.config_path)
        if os.name != 'nt':
            self.assertEqual('/etc/nginx/*', nparser.abs_path('/etc/nginx/*'))
            self.assertEqual(os.path.join(self.config_path, 'foo/bar'),
                             nparser.abs_path('foo/bar'))
        else:
            self.assertEqual('C:\\etc\\nginx\\*', nparser.abs_path('C:\\etc\\nginx\\*'))
            self.assertEqual(os.path.join(self.config_path, 'foo\\bar'),
                             nparser.abs_path('foo\\bar'))


    def test_filedump(self):
        nparser = parser.NginxParser(self.config_path)
        nparser.filedump('test', lazy=False)
        # pylint: disable=protected-access
        parsed = nparser._parse_files(nparser.abs_path(
            'sites-enabled/example.com.test'))
        self.assertEqual(4, len(glob.glob(nparser.abs_path('*.test'))))
        self.assertEqual(10, len(
            glob.glob(nparser.abs_path('sites-enabled/*.test'))))
        self.assertEqual([[['server'], [['listen', '69.50.225.155:9000'],
                                        ['listen', '127.0.0.1'],
                                        ['server_name', '.example.com'],
                                        ['server_name', 'example.*']]]],
                         parsed[0])

    def test__do_for_subarray(self):
        # pylint: disable=protected-access
        mylists = [([[2], [3], [2]], [[0], [2]]),
                   ([[2], [3], [4]], [[0]]),
                   ([[4], [3], [2]], [[2]]),
                   ([], []),
                   (2, []),
                   ([[[2], [3], [2]], [[2], [3], [2]]],
                        [[0, 0], [0, 2], [1, 0], [1, 2]]),
                   ([[[0], [3], [2]], [[2], [3], [2]]], [[0, 2], [1, 0], [1, 2]]),
                   ([[[0], [3], [4]], [[2], [3], [2]]], [[1, 0], [1, 2]]),
                   ([[[0], [3], [4]], [[5], [3], [2]]], [[1, 2]]),
                   ([[[0], [3], [4]], [[5], [3], [0]]], [])]

        for mylist, result in mylists:
            paths: List[List[int]] = []
            parser._do_for_subarray(mylist,
                                    lambda x: isinstance(x, list) and
                                    len(x) >= 1 and
                                    x[0] == 2,
                                    lambda x, y, pts=paths: pts.append(y))
            self.assertEqual(paths, result)

    def test_get_vhosts_global_ssl(self):
        nparser = parser.NginxParser(self.config_path)
        vhosts = nparser.get_vhosts()

        vhost = obj.VirtualHost(nparser.abs_path('sites-enabled/globalssl.com'),
                                [obj.Addr('4.8.2.6', '57', True, False,
                                          False, False)],
                                True, True, {'globalssl.com'}, [], [0])

        globalssl_com = [x for x in vhosts if 'globalssl.com' in x.filep][0]
        self.assertEqual(vhost, globalssl_com)

    def test_get_vhosts(self):
        nparser = parser.NginxParser(self.config_path)
        vhosts = nparser.get_vhosts()

        vhost1 = obj.VirtualHost(nparser.abs_path('nginx.conf'),
                                 [obj.Addr('', '8080', False, False,
                                           False, False)],
                                 False, True,
                                 {'localhost',
                                      r'~^(www\.)?(example|bar)\.'},
                                 [], [10, 1, 9])
        vhost2 = obj.VirtualHost(nparser.abs_path('nginx.conf'),
                                 [obj.Addr('somename', '8080', False, False,
                                           False, False),
                                  obj.Addr('', '8000', False, False,
                                           False, False)],
                                 False, True,
                                 {'somename', 'another.alias', 'alias'},
                                 [], [10, 1, 12])
        vhost3 = obj.VirtualHost(nparser.abs_path('sites-enabled/example.com'),
                                 [obj.Addr('69.50.225.155', '9000',
                                           False, False, False, False),
                                  obj.Addr('127.0.0.1', '', False, False,
                                           False, False)],
                                 False, True,
                                 {'.example.com', 'example.*'}, [], [0])
        vhost4 = obj.VirtualHost(nparser.abs_path('sites-enabled/default'),
                                 [obj.Addr('myhost', '', False, True,
                                           False, False),
                                  obj.Addr('otherhost', '', False, True,
                                           False, False)],
                                 False, True, {'www.example.org'},
                                 [], [0])
        vhost5 = obj.VirtualHost(nparser.abs_path('foo.conf'),
                                 [obj.Addr('*', '80', True, True,
                                           False, False)],
                                 True, True, {'*.www.foo.com',
                                                  '*.www.example.com'},
                                 [], [2, 1, 0])

        self.assertEqual(19, len(vhosts))
        example_com = [x for x in vhosts if 'example.com' in x.filep][0]
        self.assertEqual(vhost3, example_com)
        default = [x for x in vhosts if 'default' in x.filep][0]
        self.assertEqual(vhost4, default)
        fooconf = [x for x in vhosts if 'foo.conf' in x.filep][0]
        self.assertEqual(vhost5, fooconf)
        localhost = [x for x in vhosts if 'localhost' in x.names][0]
        self.assertEqual(vhost1, localhost)
        somename = [x for x in vhosts if 'somename' in x.names][0]
        self.assertEqual(vhost2, somename)

    def test_has_ssl_on_directive(self):
        nparser = parser.NginxParser(self.config_path)
        mock_vhost = obj.VirtualHost(None, None, None, None, None,
              [['listen', 'myhost default_server'],
               ['server_name', 'www.example.org'],
               [['location', '/'], [['root', 'html'], ['index', 'index.html index.htm']]]
               ], None)
        self.assertFalse(nparser.has_ssl_on_directive(mock_vhost))
        mock_vhost.raw = [['listen', '*:80', 'default_server', 'ssl'],
                          ['server_name', '*.www.foo.com', '*.www.example.com'],
                          ['root', '/home/ubuntu/sites/foo/']]
        self.assertFalse(nparser.has_ssl_on_directive(mock_vhost))
        mock_vhost.raw = [['listen', '80 ssl'],
                          ['server_name', '*.www.foo.com', '*.www.example.com']]
        self.assertFalse(nparser.has_ssl_on_directive(mock_vhost))
        mock_vhost.raw = [['listen', '80'],
                          ['ssl', 'on'],
                          ['server_name', '*.www.foo.com', '*.www.example.com']]
        self.assertIs(nparser.has_ssl_on_directive(mock_vhost), True)

    def test_remove_server_directives(self):
        nparser = parser.NginxParser(self.config_path)
        mock_vhost = obj.VirtualHost(nparser.abs_path('nginx.conf'),
                                     None, None, None,
                                     {'localhost',
                                           r'~^(www\.)?(example|bar)\.'},
                                     None, [10, 1, 9])
        example_com = nparser.abs_path('sites-enabled/example.com')
        names = {'.example.com', 'example.*'}
        mock_vhost.filep = example_com
        mock_vhost.names = names
        mock_vhost.path = [0]
        nparser.add_server_directives(mock_vhost,
                                      [['foo', 'bar'], ['ssl_certificate',
                                                        '/etc/ssl/cert2.pem']])
        nparser.remove_server_directives(mock_vhost, 'foo')
        nparser.remove_server_directives(mock_vhost, 'ssl_certificate')
        self.assertEqual(nparser.parsed[example_com],
            [[['server'], [['listen', '69.50.225.155:9000'],
                           ['listen', '127.0.0.1'],
                           ['server_name', '.example.com'],
                           ['server_name', 'example.*'],
                           []]]])

    def test_add_server_directives(self):
        nparser = parser.NginxParser(self.config_path)
        mock_vhost = obj.VirtualHost(nparser.abs_path('nginx.conf'),
                                     None, None, None,
                                     {'localhost',
                                           r'~^(www\.)?(example|bar)\.'},
                                     None, [10, 1, 9])
        nparser.add_server_directives(mock_vhost,
                                      [['foo', 'bar'], ['\n ', 'ssl_certificate', ' ',
                                                        '/etc/ssl/cert.pem']])
        ssl_re = re.compile(r'\n\s+ssl_certificate /etc/ssl/cert.pem')
        dump = nginxparser.dumps(nparser.parsed[nparser.abs_path('nginx.conf')])
        self.assertEqual(1, len(re.findall(ssl_re, dump)))

        example_com = nparser.abs_path('sites-enabled/example.com')
        names = {'.example.com', 'example.*'}
        mock_vhost.filep = example_com
        mock_vhost.names = names
        mock_vhost.path = [0]
        nparser.add_server_directives(mock_vhost,
                                      [['foo', 'bar'], ['ssl_certificate',
                                                        '/etc/ssl/cert2.pem']])
        nparser.add_server_directives(mock_vhost, [['foo', 'bar']])
        from certbot_nginx._internal.parser import COMMENT
        self.assertEqual(nparser.parsed[example_com],
            [[['server'], [['listen', '69.50.225.155:9000'],
                           ['listen', '127.0.0.1'],
                           ['server_name', '.example.com'],
                           ['server_name', 'example.*'],
                           ['foo', 'bar'],
                           ['#', COMMENT],
                           ['ssl_certificate', '/etc/ssl/cert2.pem'],
                           ['#', COMMENT], [], []
                           ]]])

        server_conf = nparser.abs_path('server.conf')
        names = {'alias', 'another.alias', 'somename'}
        mock_vhost.filep = server_conf
        mock_vhost.names = names
        mock_vhost.path = []
        self.assertRaises(errors.MisconfigurationError,
                          nparser.add_server_directives,
                          mock_vhost,
                          [['foo', 'bar'],
                           ['ssl_certificate', '/etc/ssl/cert2.pem']])

    def test_comment_is_repeatable(self):
        nparser = parser.NginxParser(self.config_path)
        example_com = nparser.abs_path('sites-enabled/example.com')
        mock_vhost = obj.VirtualHost(example_com,
                                     None, None, None,
                                     {'.example.com', 'example.*'},
                                     None, [0])
        nparser.add_server_directives(mock_vhost,
                                      [['\n  ', '#', ' ', 'what a nice comment']])
        nparser.add_server_directives(mock_vhost,
                                      [['\n  ', 'include', ' ',
                                      nparser.abs_path('comment_in_file.conf')]])
        from certbot_nginx._internal.parser import COMMENT
        self.assertEqual(nparser.parsed[example_com],
            [[['server'], [['listen', '69.50.225.155:9000'],
                           ['listen', '127.0.0.1'],
                           ['server_name', '.example.com'],
                           ['server_name', 'example.*'],
                           ['#', ' ', 'what a nice comment'],
                           [],
                           ['include', nparser.abs_path('comment_in_file.conf')],
                           ['#', COMMENT],
                           []]]]
)

    def test_replace_server_directives(self):
        nparser = parser.NginxParser(self.config_path)
        target = {'.example.com', 'example.*'}
        filep = nparser.abs_path('sites-enabled/example.com')
        mock_vhost = obj.VirtualHost(filep, None, None, None, target, None, [0])
        nparser.update_or_add_server_directives(
            mock_vhost, [['server_name', 'foobar.com']])
        from certbot_nginx._internal.parser import COMMENT
        self.assertEqual(
            nparser.parsed[filep],
            [[['server'], [['listen', '69.50.225.155:9000'],
                           ['listen', '127.0.0.1'],
                           ['server_name', 'foobar.com'], ['#', COMMENT],
                           ['server_name', 'example.*'], []
                           ]]])
        mock_vhost.names = {'foobar.com', 'example.*'}
        nparser.update_or_add_server_directives(
            mock_vhost, [['ssl_certificate', 'cert.pem']])
        self.assertEqual(
            nparser.parsed[filep],
            [[['server'], [['listen', '69.50.225.155:9000'],
                           ['listen', '127.0.0.1'],
                           ['server_name', 'foobar.com'], ['#', COMMENT],
                           ['server_name', 'example.*'], [],
                           ['ssl_certificate', 'cert.pem'], ['#', COMMENT], [],
                           ]]])

    def test_get_best_match(self):
        target_name = 'www.eff.org'
        names = [{'www.eff.org', 'irrelevant.long.name.eff.org', '*.org'},
                 {'eff.org', 'ww2.eff.org', 'test.www.eff.org'},
                 {'*.eff.org', '.www.eff.org'},
                 {'.eff.org', '*.org'},
                 {'www.eff.', 'www.eff.*', '*.www.eff.org'},
                 {'example.com', r'~^(www\.)?(eff.+)', '*.eff.*'},
                 {'*', r'~^(www\.)?(eff.+)'},
                 {'www.*', r'~^(www\.)?(eff.+)', '.test.eff.org'},
                 {'*.org', r'*.eff.org', 'www.eff.*'},
                 {'*.www.eff.org', 'www.*'},
                 {'*.org'},
                 set(),
                 {'example.com'},
                 {'www.Eff.org'},
                 {'.efF.org'}]
        winners = [('exact', 'www.eff.org'),
                   (None, None),
                   ('exact', '.www.eff.org'),
                   ('wildcard_start', '.eff.org'),
                   ('wildcard_end', 'www.eff.*'),
                   ('regex', r'~^(www\.)?(eff.+)'),
                   ('wildcard_start', '*'),
                   ('wildcard_end', 'www.*'),
                   ('wildcard_start', '*.eff.org'),
                   ('wildcard_end', 'www.*'),
                   ('wildcard_start', '*.org'),
                   (None, None),
                   (None, None),
                   ('exact', 'www.Eff.org'),
                   ('wildcard_start', '.efF.org')]

        for i, winner in enumerate(winners):
            self.assertEqual(winner,
                             parser.get_best_match(target_name, names[i]))

    def test_comment_directive(self):
        # pylint: disable=protected-access
        block = nginxparser.UnspacedList([
            ["\n", "a", " ", "b", "\n"],
            ["c", " ", "d"],
            ["\n", "e", " ", "f"]])
        from certbot_nginx._internal.parser import comment_directive, COMMENT_BLOCK
        comment_directive(block, 1)
        comment_directive(block, 0)
        self.assertEqual(block.spaced, [
            ["\n", "a", " ", "b", "\n"],
            COMMENT_BLOCK,
            "\n",
            ["c", " ", "d"],
            COMMENT_BLOCK,
            ["\n", "e", " ", "f"]])

    def test_comment_out_directive(self):
        server_block = nginxparser.loads("""
            server {
                listen 80;
                root /var/www/html;
                index star.html;

                server_name *.functorkitten.xyz;
                ssl_session_timeout 1440m; ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

                ssl_prefer_server_ciphers on;
            }""")
        block = server_block[0][1]
        from certbot_nginx._internal.parser import _comment_out_directive
        _comment_out_directive(block, 4, "blah1")
        _comment_out_directive(block, 5, "blah2")
        _comment_out_directive(block, 6, "blah3")
        self.assertEqual(block.spaced, [
            ['\n                ', 'listen', ' ', '80'],
            ['\n                ', 'root', ' ', '/var/www/html'],
            ['\n                ', 'index', ' ', 'star.html'],
            ['\n\n                ', 'server_name', ' ', '*.functorkitten.xyz'],
            ['\n                ', '#', ' ssl_session_timeout 1440m; # duplicated in blah1'],
            [' ', '#', ' ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # duplicated in blah2'],
            ['\n\n                ', '#', ' ssl_prefer_server_ciphers on; # duplicated in blah3'],
            '\n            '])

    def test_parse_server_raw_ssl(self):
        server = parser._parse_server_raw([ #pylint: disable=protected-access
            ['listen', '443']
        ])
        self.assertFalse(server['ssl'])

        server = parser._parse_server_raw([ #pylint: disable=protected-access
            ['listen', '443', 'ssl']
        ])
        self.assertTrue(server['ssl'])

        server = parser._parse_server_raw([ #pylint: disable=protected-access
            ['listen', '443'], ['ssl', 'off']
        ])
        self.assertFalse(server['ssl'])

        server = parser._parse_server_raw([ #pylint: disable=protected-access
            ['listen', '443'], ['ssl', 'on']
        ])
        self.assertTrue(server['ssl'])

    def test_parse_server_raw_unix(self):
        server = parser._parse_server_raw([ #pylint: disable=protected-access
            ['listen', 'unix:/var/run/nginx.sock']
        ])
        self.assertEqual(len(server['addrs']), 0)

    def test_parse_server_global_ssl_applied(self):
        nparser = parser.NginxParser(self.config_path)
        server = nparser.parse_server([
            ['listen', '443']
        ])
        self.assertTrue(server['ssl'])

    def test_duplicate_vhost(self):
        nparser = parser.NginxParser(self.config_path)

        vhosts = nparser.get_vhosts()
        default = [x for x in vhosts if 'default' in x.filep][0]
        new_vhost = nparser.duplicate_vhost(default, remove_singleton_listen_params=True)
        nparser.filedump(ext='')

        # check properties of new vhost
        self.assertIs(next(iter(new_vhost.addrs)).default, False)
        self.assertNotEqual(new_vhost.path, default.path)

        # check that things are written to file correctly
        new_nparser = parser.NginxParser(self.config_path)
        new_vhosts = new_nparser.get_vhosts()
        new_defaults = [x for x in new_vhosts if 'default' in x.filep]
        self.assertEqual(len(new_defaults), 2)
        new_vhost_parsed = new_defaults[1]
        self.assertIs(next(iter(new_vhost_parsed.addrs)).default, False)
        self.assertEqual(next(iter(default.names)), next(iter(new_vhost_parsed.names)))
        self.assertEqual(len(default.raw), len(new_vhost_parsed.raw))
        self.assertTrue(next(iter(default.addrs)).super_eq(next(iter(new_vhost_parsed.addrs))))

    def test_duplicate_vhost_remove_ipv6only(self):
        nparser = parser.NginxParser(self.config_path)

        vhosts = nparser.get_vhosts()
        ipv6ssl = [x for x in vhosts if 'ipv6ssl' in x.filep][0]
        new_vhost = nparser.duplicate_vhost(ipv6ssl, remove_singleton_listen_params=True)
        nparser.filedump(ext='')

        for addr in new_vhost.addrs:
            self.assertFalse(addr.ipv6only)

        identical_vhost = nparser.duplicate_vhost(ipv6ssl, remove_singleton_listen_params=False)
        nparser.filedump(ext='')

        called = False
        for addr in identical_vhost.addrs:
            if addr.ipv6:
                self.assertTrue(addr.ipv6only)
                called = True
        self.assertTrue(called)

    def test_valid_unicode_characters(self):
        nparser = parser.NginxParser(self.config_path)
        path = nparser.abs_path('valid_unicode_comments.conf')
        parsed = nparser._parse_files(path)  # pylint: disable=protected-access
        self.assertEqual(['server'], parsed[0][2][0])
        self.assertEqual(['listen', '80'], parsed[0][2][1][3])

    def test_valid_unicode_roundtrip(self):
        """This tests the parser's ability to load and save a config containing Unicode"""
        nparser = parser.NginxParser(self.config_path)
        nparser._parse_files(
            nparser.abs_path('valid_unicode_comments.conf')
        ) # pylint: disable=protected-access
        nparser.filedump(lazy=False)

    def test_invalid_unicode_characters(self):
        with self.assertLogs() as log:
            nparser = parser.NginxParser(self.config_path)
            path = nparser.abs_path('invalid_unicode_comments.conf')
            parsed = nparser._parse_files(path)  # pylint: disable=protected-access

        self.assertEqual([], parsed)
        self.assertTrue(any(
            ('invalid character' in output) and ('UTF-8' in output)
            for output in log.output
        ))

    def test_valid_unicode_characters_in_ssl_options(self):
        nparser = parser.NginxParser(self.config_path)
        path = nparser.abs_path('valid_unicode_comments.conf')
        parsed = parser._parse_ssl_options(path)  # pylint: disable=protected-access
        self.assertEqual(['server'], parsed[2][0])
        self.assertEqual(['listen', '80'], parsed[2][1][3])

    def test_invalid_unicode_characters_in_ssl_options(self):
        with self.assertLogs() as log:
            nparser = parser.NginxParser(self.config_path)
            path = nparser.abs_path('invalid_unicode_comments.conf')
            parsed = parser._parse_ssl_options(path)  # pylint: disable=protected-access

        self.assertEqual([], parsed)
        self.assertTrue(any(
            ('invalid character' in output) and ('UTF-8' in output)
            for output in log.output
        ))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
