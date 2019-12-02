"""Test certbot_nginx._internal.display_ops."""
import unittest

from certbot.display import util as display_util
from certbot.tests import util as certbot_util
from certbot_nginx._internal import parser
from certbot_nginx._internal.display_ops import select_vhost_multiple
import test_util as util


class SelectVhostMultiTest(util.NginxTest):
    """Tests for certbot_nginx._internal.display_ops.select_vhost_multiple."""

    def setUp(self):
        super(SelectVhostMultiTest, self).setUp()
        nparser = parser.NginxParser(self.config_path)
        self.vhosts = nparser.get_vhosts()

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


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
