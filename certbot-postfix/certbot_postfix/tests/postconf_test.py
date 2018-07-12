"""Tests for certbot_postfix.postconf."""

import mock
import unittest

from certbot import errors

class PostConfTest(unittest.TestCase):
    """Tests for certbot_postfix.util.PostConf."""
    def setUp(self):
        from certbot_postfix.postconf import ConfigMain
        super(PostConfTest, self).setUp()
        with mock.patch('certbot_postfix.util.PostfixUtilBase._get_output') as mock_call:
            with mock.patch('certbot_postfix.postconf.ConfigMain._get_output_master') as \
                    mock_master_call:
                with mock.patch('certbot_postfix.postconf.util.verify_exe_exists') as verify_exe:
                    verify_exe.return_value = True
                    mock_call.return_value = ('default_parameter = value\n'
                                             'extra_param =\n'
                                             'overridden_by_master = default\n')
                    mock_master_call.return_value = (
                        'service/type/overridden_by_master = master_value\n'
                        'service2/type/overridden_by_master = master_value2\n'
                    )
                    self.config = ConfigMain('postconf', False)

    @mock.patch('certbot_postfix.util.PostfixUtilBase._get_output')
    @mock.patch('certbot_postfix.postconf.util.verify_exe_exists')
    def test_get_output_master(self, mock_verify_exe, mock_get_output):
        from certbot_postfix.postconf import ConfigMain
        mock_verify_exe.return_value = True
        ConfigMain('postconf', lambda x, y, z: None)
        mock_get_output.assert_called_with('-P')

    @mock.patch('certbot_postfix.util.PostfixUtilBase._get_output')
    def test_read_default(self, mock_get_output):
        mock_get_output.return_value = 'param = default_value'
        self.assertEqual(self.config.get_default('param'), 'default_value')

    @mock.patch('certbot_postfix.util.PostfixUtilBase._call')
    def test_set(self, mock_call):
        self.config.set('extra_param', 'other_value')
        self.assertEqual(self.config.get('extra_param'), 'other_value')
        self.config.flush()
        mock_call.assert_called_with(['-e', 'extra_param=other_value'])

    def test_set_bad_param_name(self):
        self.assertRaises(KeyError, self.config.set, 'nonexistent_param', 'some_value')

    @mock.patch('certbot_postfix.util.PostfixUtilBase._call')
    def test_write_revert(self, mock_call):
        self.config.set('default_parameter', 'fake_news')
        # revert config set
        self.config.set('default_parameter', 'value')
        self.config.flush()
        mock_call.assert_not_called()

    @mock.patch('certbot_postfix.util.PostfixUtilBase._call')
    def test_write_default(self, mock_call):
        self.config.set('default_parameter', 'value')
        self.config.flush()
        mock_call.assert_not_called()

    def test_master_overrides(self):
        self.assertEqual(self.config.get_master_overrides('overridden_by_master'),
                         [('service/type', 'master_value'),
                          ('service2/type', 'master_value2')])

    def test_set_check_override(self):
        self.assertRaises(errors.PluginError, self.config.set,
            'overridden_by_master', 'new_value')

    def test_ignore_check_override(self):
        # pylint: disable=protected-access
        self.config._ignore_master_overrides = True
        self.config.set('overridden_by_master', 'new_value')

    def test_check_acceptable_overrides(self):
        self.config.set('overridden_by_master', 'new_value',
                        ('master_value', 'master_value2'))

    @mock.patch('certbot_postfix.util.PostfixUtilBase._get_output')
    def test_flush(self, mock_out):
        self.config.set('default_parameter', 'new_value')
        self.config.set('extra_param', 'another_value')
        self.config.flush()
        arguments = mock_out.call_args_list[-1][0][0]
        self.assertEqual('-e', arguments[0])
        self.assertTrue('default_parameter=new_value' in arguments)
        self.assertTrue('extra_param=another_value' in arguments)

    @mock.patch('certbot_postfix.util.PostfixUtilBase._get_output')
    def test_flush_updates_object(self, mock_out):
        self.config.set('default_parameter', 'new_value')
        self.config.flush()
        mock_out.reset_mock()
        self.config.set('default_parameter', 'new_value')
        mock_out.assert_not_called()

    @mock.patch('certbot_postfix.util.PostfixUtilBase._get_output')
    def test_flush_throws_error_on_fail(self, mock_out):
        mock_out.side_effect = [IOError("oh no!")]
        self.config.set('default_parameter', 'new_value')
        self.assertRaises(errors.PluginError, self.config.flush)

if __name__ == '__main__':  # pragma: no cover
    unittest.main()
