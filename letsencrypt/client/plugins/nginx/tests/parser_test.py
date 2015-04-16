"""Tests for letsencrypt.client.plugins.nginx.parser."""
import glob
import os
import re
import shutil
import unittest

from letsencrypt.client.errors import LetsEncryptMisconfigurationError
from letsencrypt.client.plugins.nginx.nginxparser import dumps
from letsencrypt.client.plugins.nginx.obj import Addr, VirtualHost
from letsencrypt.client.plugins.nginx.parser import NginxParser, get_best_match
from letsencrypt.client.plugins.nginx.tests import util


class NginxParserTest(util.NginxTest):
    """Nginx Parser Test."""

    def setUp(self):
        super(NginxParserTest, self).setUp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        shutil.rmtree(self.config_dir)
        shutil.rmtree(self.work_dir)

    def test_root_normalized(self):
        path = os.path.join(self.temp_dir, "foo/////"
                            "bar/../../testdata")
        parser = NginxParser(path, None)
        self.assertEqual(parser.root, self.config_path)

    def test_root_absolute(self):
        parser = NginxParser(os.path.relpath(self.config_path), None)
        self.assertEqual(parser.root, self.config_path)

    def test_root_no_trailing_slash(self):
        parser = NginxParser(self.config_path + os.path.sep, None)
        self.assertEqual(parser.root, self.config_path)

    def test_load(self):
        """Test recursive conf file parsing.

        """
        parser = NginxParser(self.config_path, self.ssl_options)
        parser.load()
        self.assertEqual(set(map(parser.abs_path,
                             ['foo.conf', 'nginx.conf', 'server.conf',
                              'sites-enabled/default',
                              'sites-enabled/example.com'])),
                         set(parser.parsed.keys()))
        self.assertEqual([['server_name', 'somename  alias  another.alias']],
                         parser.parsed[parser.abs_path('server.conf')])
        self.assertEqual([[['server'], [['listen', '69.50.225.155:9000'],
                                        ['listen', '127.0.0.1'],
                                        ['server_name', '.example.com'],
                                        ['server_name', 'example.*']]]],
                         parser.parsed[parser.abs_path(
                             'sites-enabled/example.com')])

    def test_abs_path(self):
        parser = NginxParser(self.config_path, self.ssl_options)
        self.assertEqual('/etc/nginx/*', parser.abs_path('/etc/nginx/*'))
        self.assertEqual(os.path.join(self.config_path, 'foo/bar/'),
                         parser.abs_path('foo/bar/'))

    def test_filedump(self):
        parser = NginxParser(self.config_path, self.ssl_options)
        parser.filedump('test')
        # pylint: disable=protected-access
        parsed = parser._parse_files(parser.abs_path(
            'sites-enabled/example.com.test'))
        self.assertEqual(3, len(glob.glob(parser.abs_path('*.test'))))
        self.assertEqual(2, len(
            glob.glob(parser.abs_path('sites-enabled/*.test'))))
        self.assertEqual([[['server'], [['listen', '69.50.225.155:9000'],
                                        ['listen', '127.0.0.1'],
                                        ['server_name', '.example.com'],
                                        ['server_name', 'example.*']]]],
                         parsed[0])

    def test_get_vhosts(self):
        parser = NginxParser(self.config_path, self.ssl_options)
        vhosts = parser.get_vhosts()

        vhost1 = VirtualHost(parser.abs_path('nginx.conf'),
                             [Addr('', '8080', False, False)],
                             False, True, set(['localhost',
                                               '~^(www\.)?(example|bar)\.']),
                             [])
        vhost2 = VirtualHost(parser.abs_path('nginx.conf'),
                             [Addr('somename', '8080', False, False),
                              Addr('', '8000', False, False)],
                             False, True, set(['somename',
                                               'another.alias', 'alias']), [])
        vhost3 = VirtualHost(parser.abs_path('sites-enabled/example.com'),
                             [Addr('69.50.225.155', '9000', False, False),
                              Addr('127.0.0.1', '', False, False)],
                             False, True, set(['.example.com', 'example.*']),
                             [])
        vhost4 = VirtualHost(parser.abs_path('sites-enabled/default'),
                             [Addr('myhost', '', False, True)],
                             False, True, set(['www.example.org']), [])
        vhost5 = VirtualHost(parser.abs_path('foo.conf'),
                             [Addr('*', '80', True, True)],
                             True, True, set(['*.www.foo.com',
                                              '*.www.example.com']), [])

        self.assertEqual(5, len(vhosts))
        example_com = filter(lambda x: 'example.com' in x.filep, vhosts)[0]
        self.assertEqual(vhost3, example_com)
        default = filter(lambda x: 'default' in x.filep, vhosts)[0]
        self.assertEqual(vhost4, default)
        foo = filter(lambda x: 'foo.conf' in x.filep, vhosts)[0]
        self.assertEqual(vhost5, foo)
        localhost = filter(lambda x: 'localhost' in x.names, vhosts)[0]
        self.assertEquals(vhost1, localhost)
        somename = filter(lambda x: 'somename' in x.names, vhosts)[0]
        self.assertEquals(vhost2, somename)

    def test_add_server_directives(self):
        parser = NginxParser(self.config_path, self.ssl_options)
        parser.add_server_directives(parser.abs_path('nginx.conf'),
                                     set(['localhost',
                                          '~^(www\.)?(example|bar)\.']),
                                     [['foo', 'bar'], ['ssl_certificate',
                                                       '/etc/ssl/cert.pem']])
        r = re.compile('foo bar;\n\s+ssl_certificate /etc/ssl/cert.pem')
        self.assertEqual(1, len(re.findall(r, dumps(parser.parsed[
            parser.abs_path('nginx.conf')]))))
        parser.add_server_directives(parser.abs_path('server.conf'),
                                     set(['alias', 'another.alias',
                                          'somename']),
                                     [['foo', 'bar'], ['ssl_certificate',
                                                       '/etc/ssl/cert2.pem']])
        self.assertEqual(parser.parsed[parser.abs_path('server.conf')],
                         [['server_name', 'somename  alias  another.alias'],
                          ['foo', 'bar'],
                          ['ssl_certificate', '/etc/ssl/cert2.pem']])

    def test_replace_server_directives(self):
        parser = NginxParser(self.config_path, self.ssl_options)
        target = set(['.example.com', 'example.*'])
        filep = parser.abs_path('sites-enabled/example.com')
        parser.add_server_directives(
            filep, target, [['server_name', 'foo bar']], True)
        self.assertEqual(
            parser.parsed[filep],
            [[['server'], [['listen', '69.50.225.155:9000'],
                           ['listen', '127.0.0.1'],
                           ['server_name', 'foo bar'],
                           ['server_name', 'foo bar']]]])
        self.assertRaises(LetsEncryptMisconfigurationError,
                          parser.add_server_directives,
                          filep, set(['foo', 'bar']),
                          [['ssl_certificate', 'cert.pem']], True)

    def test_get_best_match(self):
        target_name = 'www.eff.org'
        names = [set(['www.eff.org', 'irrelevant.long.name.eff.org', '*.org']),
                 set(['eff.org', 'ww2.eff.org', 'test.www.eff.org']),
                 set(['*.eff.org', '.www.eff.org']),
                 set(['.eff.org', '*.org']),
                 set(['www.eff.', 'www.eff.*', '*.www.eff.org']),
                 set(['example.com', '~^(www\.)?(eff.+)', '*.eff.*']),
                 set(['*', '~^(www\.)?(eff.+)']),
                 set(['www.*', '~^(www\.)?(eff.+)', '.test.eff.org']),
                 set(['*.org', '*.eff.org', 'www.eff.*']),
                 set(['*.www.eff.org', 'www.*']),
                 set(['*.org']),
                 set([]),
                 set(['example.com'])]
        winners = [('exact', 'www.eff.org'),
                   (None, None),
                   ('exact', '.www.eff.org'),
                   ('wildcard_start', '.eff.org'),
                   ('wildcard_end', 'www.eff.*'),
                   ('regex', '~^(www\.)?(eff.+)'),
                   ('wildcard_start', '*'),
                   ('wildcard_end', 'www.*'),
                   ('wildcard_start', '*.eff.org'),
                   ('wildcard_end', 'www.*'),
                   ('wildcard_start', '*.org'),
                   (None, None),
                   (None, None)]

        for i, winner in enumerate(winners):
            self.assertEqual(winner, get_best_match(target_name, names[i]))

    def test_get_all_certs_keys(self):
        parser = NginxParser(self.config_path, self.ssl_options)
        filep = parser.abs_path('sites-enabled/example.com')
        parser.add_server_directives(filep,
                                     set(['.example.com', 'example.*']),
                                     [['ssl_certificate', 'foo.pem'],
                                      ['ssl_certificate_key', 'bar.key'],
                                      ['listen', '443 ssl']])
        ck = parser.get_all_certs_keys()
        self.assertEqual(set([('foo.pem', 'bar.key', filep)]), ck)


if __name__ == "__main__":
    unittest.main()
