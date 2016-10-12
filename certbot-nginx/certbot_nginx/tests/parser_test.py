"""Tests for certbot_nginx.parser."""
import glob
import os
import re
import shutil
import unittest

from certbot import errors

from certbot_nginx import nginxparser
from certbot_nginx import obj
from certbot_nginx import parser
from certbot_nginx.tests import util


class NginxParserTest(util.NginxTest):
    """Nginx Parser Test."""

    def setUp(self):
        super(NginxParserTest, self).setUp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_root_normalized(self):
        path = os.path.join(self.temp_dir, "etc_nginx/////"
                            "ubuntu_nginx/../../etc_nginx")
        nparser = parser.NginxParser(path, None)
        self.assertEqual(nparser.root, self.config_path)

    def test_root_absolute(self):
        nparser = parser.NginxParser(os.path.relpath(self.config_path), None)
        self.assertEqual(nparser.root, self.config_path)

    def test_root_no_trailing_slash(self):
        nparser = parser.NginxParser(self.config_path + os.path.sep, None)
        self.assertEqual(nparser.root, self.config_path)

    def test_load(self):
        """Test recursive conf file parsing.

        """
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        nparser.load()
        self.assertEqual(set([nparser.abs_path(x) for x in
                              ['foo.conf', 'nginx.conf', 'server.conf',
                               'sites-enabled/default',
                               'sites-enabled/example.com',
                               'sites-enabled/migration.com']]),
                         set(nparser.parsed.keys()))
        self.assertEqual([['server_name', 'somename  alias  another.alias']],
                         nparser.parsed[nparser.abs_path('server.conf')])
        self.assertEqual([[['server'], [['listen', '69.50.225.155:9000'],
                                        ['listen', '127.0.0.1'],
                                        ['server_name', '.example.com'],
                                        ['server_name', 'example.*']]]],
                         nparser.parsed[nparser.abs_path(
                             'sites-enabled/example.com')])

    def test_abs_path(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        self.assertEqual('/etc/nginx/*', nparser.abs_path('/etc/nginx/*'))
        self.assertEqual(os.path.join(self.config_path, 'foo/bar/'),
                         nparser.abs_path('foo/bar/'))

    def test_filedump(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        nparser.filedump('test', lazy=False)
        # pylint: disable=protected-access
        parsed = nparser._parse_files(nparser.abs_path(
            'sites-enabled/example.com.test'))
        self.assertEqual(3, len(glob.glob(nparser.abs_path('*.test'))))
        self.assertEqual(3, len(
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
            paths = []
            parser._do_for_subarray(mylist,
                                    lambda x: isinstance(x, list) and
                                    len(x) >= 1 and
                                    x[0] == 2,
                                    lambda x, y, pts=paths: pts.append(y))
            self.assertEqual(paths, result)


    def test_get_vhosts(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        vhosts = nparser.get_vhosts()

        vhost1 = obj.VirtualHost(nparser.abs_path('nginx.conf'),
                                 [obj.Addr('', '8080', False, False)],
                                 False, True,
                                 set(['localhost',
                                      r'~^(www\.)?(example|bar)\.']),
                                 [], [9, 1, 9])
        vhost2 = obj.VirtualHost(nparser.abs_path('nginx.conf'),
                                 [obj.Addr('somename', '8080', False, False),
                                  obj.Addr('', '8000', False, False)],
                                 False, True,
                                 set(['somename', 'another.alias', 'alias']),
                                 [], [9, 1, 12])
        vhost3 = obj.VirtualHost(nparser.abs_path('sites-enabled/example.com'),
                                 [obj.Addr('69.50.225.155', '9000',
                                           False, False),
                                  obj.Addr('127.0.0.1', '', False, False)],
                                 False, True,
                                 set(['.example.com', 'example.*']), [], [0])
        vhost4 = obj.VirtualHost(nparser.abs_path('sites-enabled/default'),
                                 [obj.Addr('myhost', '', False, True)],
                                 False, True, set(['www.example.org']),
                                 [], [0])
        vhost5 = obj.VirtualHost(nparser.abs_path('foo.conf'),
                                 [obj.Addr('*', '80', True, True)],
                                 True, True, set(['*.www.foo.com',
                                                  '*.www.example.com']),
                                 [], [2, 1, 0])

        self.assertEqual(7, len(vhosts))
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
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        mock_vhost = obj.VirtualHost(None, None, None, None, None,
              [['listen', 'myhost default_server'],
               ['server_name', 'www.example.org'],
               [['location', '/'], [['root', 'html'], ['index', 'index.html index.htm']]]
               ], None)
        self.assertFalse(nparser.has_ssl_on_directive(mock_vhost))
        mock_vhost.raw = [['listen', '*:80 default_server ssl'],
                          ['server_name', '*.www.foo.com *.www.example.com'],
                          ['root', '/home/ubuntu/sites/foo/']]
        self.assertFalse(nparser.has_ssl_on_directive(mock_vhost))
        mock_vhost.raw = [['listen', '80 ssl'],
                          ['server_name', '*.www.foo.com *.www.example.com']]
        self.assertFalse(nparser.has_ssl_on_directive(mock_vhost))
        mock_vhost.raw = [['listen', '80'],
                          ['ssl', 'on'],
                          ['server_name', '*.www.foo.com *.www.example.com']]
        self.assertTrue(nparser.has_ssl_on_directive(mock_vhost))

    def test_add_server_directives(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        mock_vhost = obj.VirtualHost(nparser.abs_path('nginx.conf'),
                                     None, None, None,
                                     set(['localhost',
                                           r'~^(www\.)?(example|bar)\.']),
                                     None, [9, 1, 9])
        nparser.add_server_directives(mock_vhost,
                                      [['foo', 'bar'], ['\n ', 'ssl_certificate', ' ',
                                                        '/etc/ssl/cert.pem']],
                                      replace=False)
        ssl_re = re.compile(r'\n\s+ssl_certificate /etc/ssl/cert.pem')
        dump = nginxparser.dumps(nparser.parsed[nparser.abs_path('nginx.conf')])
        self.assertEqual(1, len(re.findall(ssl_re, dump)))

        example_com = nparser.abs_path('sites-enabled/example.com')
        names = set(['.example.com', 'example.*'])
        mock_vhost.filep = example_com
        mock_vhost.names = names
        mock_vhost.path = [0]
        nparser.add_server_directives(mock_vhost,
                                      [['foo', 'bar'], ['ssl_certificate',
                                                        '/etc/ssl/cert2.pem']],
                                      replace=False)
        nparser.add_server_directives(mock_vhost, [['foo', 'bar']],
                                      replace=False)
        from certbot_nginx.parser import COMMENT
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
        names = set(['alias', 'another.alias', 'somename'])
        mock_vhost.filep = server_conf
        mock_vhost.names = names
        mock_vhost.path = []
        self.assertRaises(errors.MisconfigurationError,
                          nparser.add_server_directives,
                          mock_vhost,
                          [['foo', 'bar'],
                           ['ssl_certificate', '/etc/ssl/cert2.pem']],
                          replace=False)

    def test_replace_server_directives(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        target = set(['.example.com', 'example.*'])
        filep = nparser.abs_path('sites-enabled/example.com')
        mock_vhost = obj.VirtualHost(filep, None, None, None, target, None, [0])
        nparser.add_server_directives(
            mock_vhost, [['server_name', 'foobar.com']], replace=True)
        from certbot_nginx.parser import COMMENT
        self.assertEqual(
            nparser.parsed[filep],
            [[['server'], [['listen', '69.50.225.155:9000'],
                           ['listen', '127.0.0.1'],
                           ['server_name', 'foobar.com'], ['#', COMMENT],
                           ['server_name', 'example.*'], []
                           ]]])
        mock_vhost.names = set(['foobar.com', 'example.*'])
        self.assertRaises(errors.MisconfigurationError,
                          nparser.add_server_directives,
                          mock_vhost,
                          [['ssl_certificate', 'cert.pem']],
                          replace=True)

    def test_get_best_match(self):
        target_name = 'www.eff.org'
        names = [set(['www.eff.org', 'irrelevant.long.name.eff.org', '*.org']),
                 set(['eff.org', 'ww2.eff.org', 'test.www.eff.org']),
                 set(['*.eff.org', '.www.eff.org']),
                 set(['.eff.org', '*.org']),
                 set(['www.eff.', 'www.eff.*', '*.www.eff.org']),
                 set(['example.com', r'~^(www\.)?(eff.+)', '*.eff.*']),
                 set(['*', r'~^(www\.)?(eff.+)']),
                 set(['www.*', r'~^(www\.)?(eff.+)', '.test.eff.org']),
                 set(['*.org', r'*.eff.org', 'www.eff.*']),
                 set(['*.www.eff.org', 'www.*']),
                 set(['*.org']),
                 set([]),
                 set(['example.com'])]
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
                   (None, None)]

        for i, winner in enumerate(winners):
            self.assertEqual(winner,
                             parser.get_best_match(target_name, names[i]))

    def test_comment_directive(self):
        # pylint: disable=protected-access
        block = nginxparser.UnspacedList([
            ["\n", "a", " ", "b", "\n"],
            ["c", " ", "d"],
            ["\n", "e", " ", "f"]])
        from certbot_nginx.parser import _comment_directive, COMMENT_BLOCK
        _comment_directive(block, 1)
        _comment_directive(block, 0)
        self.assertEqual(block.spaced, [
            ["\n", "a", " ", "b", "\n"],
            COMMENT_BLOCK,
            "\n",
            ["c", " ", "d"],
            COMMENT_BLOCK,
            ["\n", "e", " ", "f"]])

    def test_get_all_certs_keys(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        filep = nparser.abs_path('sites-enabled/example.com')
        mock_vhost = obj.VirtualHost(filep,
                                     None, None, None,
                                     set(['.example.com', 'example.*']),
                                     None, [0])
        nparser.add_server_directives(mock_vhost,
                                      [['ssl_certificate', 'foo.pem'],
                                       ['ssl_certificate_key', 'bar.key'],
                                       ['listen', '443 ssl']],
                                      replace=False)
        c_k = nparser.get_all_certs_keys()
        migration_file = nparser.abs_path('sites-enabled/migration.com')
        self.assertEqual(set([('foo.pem', 'bar.key', filep),
                              ('cert.pem', 'cert.key', migration_file)
                             ]), c_k)

    def test_parse_server_ssl(self):
        server = parser.parse_server([
            ['listen', '443']
        ])
        self.assertFalse(server['ssl'])

        server = parser.parse_server([
            ['listen', '443 ssl']
        ])
        self.assertTrue(server['ssl'])

        server = parser.parse_server([
            ['listen', '443'], ['ssl', 'off']
        ])
        self.assertFalse(server['ssl'])

        server = parser.parse_server([
            ['listen', '443'], ['ssl', 'on']
        ])
        self.assertTrue(server['ssl'])

    def test_ssl_options_should_be_parsed_ssl_directives(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        self.assertEqual(nginxparser.UnspacedList(nparser.loc["ssl_options"]),
                         [['ssl_session_cache', 'shared:le_nginx_SSL:1m'],
                          ['ssl_session_timeout', '1440m'],
                          ['ssl_protocols', 'TLSv1 TLSv1.1 TLSv1.2'],
                          ['ssl_prefer_server_ciphers', 'on'],
                          ['ssl_ciphers', '"ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-ECDSA-'+
                           'AES256-GCM-SHA384 ECDHE-ECDSA-AES128-SHA ECDHE-ECDSA-AES256'+
                           '-SHA ECDHE-ECDSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA384'+
                           ' ECDHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384'+
                           ' ECDHE-RSA-AES128-SHA ECDHE-RSA-AES128-SHA256 ECDHE-RSA-'+
                           'AES256-SHA384 DHE-RSA-AES128-GCM-SHA256 DHE-RSA-AES256-GCM'+
                           '-SHA384 DHE-RSA-AES128-SHA DHE-RSA-AES256-SHA DHE-RSA-'+
                           'AES128-SHA256 DHE-RSA-AES256-SHA256 EDH-RSA-DES-CBC3-SHA"']
                         ])

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
