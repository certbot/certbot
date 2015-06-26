"""Test letsencrypt_apache.display_ops."""
import unittest

import mock

from letsencrypt_apache.tests import util

from letsencrypt.display import util as display_util


class SelectVhostTest(unittest.TestCase):
    """Tests for letsencrypt_apache.display_ops.select_vhost."""

    def setUp(self):
        self.base_dir = "/example_path"
        self.vhosts = util.get_vh_truth(
            self.base_dir, "debian_apache_2_4/two_vhost_80")

    @classmethod
    def _call(cls, vhosts):
        from letsencrypt_apache.display_ops import select_vhost
        select_vhost("example.com", vhosts)

    @mock.patch("letsencrypt_apache.display_ops.zope.component.getUtility")
    def test_successful_choice(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 1)
        self.assertEqual(self.vhosts[1], self._call(self.vhosts))

    @mock.patch("letsencrypt_apache.display_ops.zope.component.getUtility")
    def test_more_info_cancel(self, mock_util):
        mock_util().menu.side_effect = [
            (display_util.HELP, 1),
            (display_util.HELP, 0),
            (display_util.CANCEL, -1),
        ]

        self.assertEqual(None, self._call())
        self.assertEqual(mock_util().notification.call_count, 2)

    def test_no_vhosts(self):
        self.assertEqual(self._call([]), None)