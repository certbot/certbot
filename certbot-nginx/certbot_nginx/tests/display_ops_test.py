"""Test certbot_apache.display_ops."""
import unittest

import mock

from certbot import errors

from certbot.display import util as display_util

from certbot.tests import util as certbot_util

from certbot_nginx import obj

from certbot_nginx.display_ops import select_vhost_multiple
from certbot_nginx.tests import util


class SelectVhostMultiTest(unittest.TestCase):
    """Tests for certbot_nginx.display_ops.select_vhost_multiple."""

    def setUp(self):
        self.base_dir = "/example_path"
        self.vhosts = util.get_vh_truth(
            self.base_dir, "debian_apache_2_4/multiple_vhosts")

    def test_select_no_input(self):
        self.assertFalse(select_vhost_multiple([]))

    @certbot_util.patch_get_utility()
    def test_select_correct(self, mock_util):
        mock_util().checklist.return_value = (
            display_util.OK, [self.vhosts[3].display_repr(),
                              self.vhosts[2].display_repr()])
        vhs = select_vhost_multiple([self.vhosts[3],
                                     self.vhosts[2],
                                     self.vhosts[1]])
        self.assertTrue(self.vhosts[2] in vhs)
        self.assertTrue(self.vhosts[3] in vhs)
        self.assertFalse(self.vhosts[1] in vhs)

    @certbot_util.patch_get_utility()
    def test_select_cancel(self, mock_util):
        mock_util().checklist.return_value = (display_util.CANCEL, "whatever")
        vhs = select_vhost_multiple([self.vhosts[2], self.vhosts[3]])
        self.assertFalse(vhs)
