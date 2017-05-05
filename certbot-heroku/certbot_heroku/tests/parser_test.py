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
                               'sites-enabled/example.com']]),
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
        nparser.filedump('test')
        # pylint: disable=protected-access
        parsed = nparser._parse_files(nparser.abs_path(
            'sites-enabled/example.com.test'))
        self.assertEqual(3, len(glob.glob(nparser.abs_path('*.test'))))
        self.assertEqual(2, len(
            glob.glob(nparser.abs_path('sites-enabled/*.test'))))
        self.assertEqual([[['server'], [['listen', '69.50.225.155:9000'],
                                        ['listen', '127.0.0.1'],
                                        ['server_name', '.example.com'],
                                        ['server_name', 'example.*']]]],
                         parsed[0])

    def test_get_vhosts(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        vhosts = nparser.get_vhosts()

        vhost1 = obj.VirtualHost(nparser.abs_path('nginx.conf'),
                                 [obj.Addr('', '8080', False, False)],
                                 False, True,
                                 set(['localhost',
                                      r'~^(www\.)?(example|bar)\.']),
                                 [])
        vhost2 = obj.VirtualHost(nparser.abs_path('nginx.conf'),
                                 [obj.Addr('somename', '8080', False, False),
                                  obj.Addr('', '8000', False, False)],
                                 False, True,
                                 set(['somename', 'another.alias', 'alias']),
                                 [])
        vhost3 = obj.VirtualHost(nparser.abs_path('sites-enabled/example.com'),
                                 [obj.Addr('69.50.225.155', '9000',
                                           False, False),
                                  obj.Addr('127.0.0.1', '', False, False)],
                                 False, True,
                                 set(['.example.com', 'example.*']), [])
        vhost4 = obj.VirtualHost(nparser.abs_path('sites-enabled/default'),
                                 [obj.Addr('myhost', '', False, True)],
                                 False, True, set(['www.example.org']), [])
        vhost5 = obj.VirtualHost(nparser.abs_path('foo.conf'),
                                 [obj.Addr('*', '80', True, True)],
                                 True, True, set(['*.www.foo.com',
                                                  '*.www.example.com']), [])

        self.assertEqual(5, len(vhosts))
        example_com = [x for x in vhosts if 'example.com' in x.filep][0]
        self.assertEqual(vhost3, example_com)
        default = [x for x in vhosts if 'default' in x.filep][0]
        self.assertEqual(vhost4, default)
        fooconf = [x for x in vhosts if 'foo.conf' in x.filep][0]
        self.assertEqual(vhost5, fooconf)
        localhost = [x for x in vhosts if 'localhost' in x.names][0]
        self.assertEquals(vhost1, localhost)
        somename = [x for x in vhosts if 'somename' in x.names][0]
        self.assertEquals(vhost2, somename)

    def test_add_server_directives(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        nparser.add_server_directives(nparser.abs_path('nginx.conf'),
                                      set(['localhost',
                                           r'~^(www\.)?(example|bar)\.']),
                                      [['foo', 'bar'], ['ssl_certificate',
                                                        '/etc/ssl/cert.pem']],
                                      replace=False)
        ssl_re = re.compile(r'\n\s+ssl_certificate /etc/ssl/cert.pem')
        dump = nginxparser.dumps(nparser.parsed[nparser.abs_path('nginx.conf')])
        self.assertEqual(1, len(re.findall(ssl_re, dump)))

        server_conf = nparser.abs_path('server.conf')
        names = set(['alias', 'another.alias', 'somename'])
        nparser.add_server_directives(server_conf, names,
                                      [['foo', 'bar'], ['ssl_certificate',
                                                        '/etc/ssl/cert2.pem']],
                                      replace=False)
        nparser.add_server_directives(server_conf, names, [['foo', 'bar']],
                                      replace=False)
        self.assertEqual(nparser.parsed[server_conf],
                         [['server_name', 'somename  alias  another.alias'],
                          ['foo', 'bar'],
                          ['ssl_certificate', '/etc/ssl/cert2.pem']
                          ])

    def test_add_http_directives(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        filep = nparser.abs_path('nginx.conf')
        block = [['server'],
                 [['listen', '80'],
                  ['server_name', 'localhost']]]
        nparser.add_http_directives(filep, block)
        root = nparser.parsed[filep]
        self.assertTrue(util.contains_at_depth(root, ['http'], 1))
        self.assertTrue(util.contains_at_depth(root, block, 2))

        # Check that our server block got inserted first among all server
        # blocks.
        http_block = [x for x in root if x[0] == ['http']][0][1]
        server_blocks = [x for x in http_block if x[0] == ['server']]
        self.assertEqual(server_blocks[0], block)

    def test_replace_server_directives(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        target = set(['.example.com', 'example.*'])
        filep = nparser.abs_path('sites-enabled/example.com')
        nparser.add_server_directives(
            filep, target, [['server_name', 'foobar.com']], replace=True)
        self.assertEqual(
            nparser.parsed[filep],
            [[['server'], [['listen', '69.50.225.155:9000'],
                           ['listen', '127.0.0.1'],
                           ['server_name', 'foobar.com'],
                           ['server_name', 'example.*'],
                           ]]])
        self.assertRaises(errors.MisconfigurationError,
                          nparser.add_server_directives,
                          filep, set(['foobar.com', 'example.*']),
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

    def test_get_all_certs_keys(self):
        nparser = parser.NginxParser(self.config_path, self.ssl_options)
        filep = nparser.abs_path('sites-enabled/example.com')
        nparser.add_server_directives(filep,
                                      set(['.example.com', 'example.*']),
                                      [['ssl_certificate', 'foo.pem'],
                                       ['ssl_certificate_key', 'bar.key'],
                                       ['listen', '443 ssl']],
                                      replace=False)
        c_k = nparser.get_all_certs_keys()
        self.assertEqual(set([('foo.pem', 'bar.key', filep)]), c_k)

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

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
