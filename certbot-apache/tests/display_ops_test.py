"""Test certbot_apache._internal.display_ops."""
import unittest

try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore

from certbot import errors
from certbot.display import util as display_util
from certbot.tests import util as certbot_util
from certbot_apache._internal import obj
from certbot_apache._internal.display_ops import select_vhost_multiple
import util


class SelectVhostMultiTest(unittest.TestCase):
    """Tests for certbot_apache._internal.display_ops.select_vhost_multiple."""

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

class SelectVhostTest(unittest.TestCase):
    """Tests for certbot_apache._internal.display_ops.select_vhost."""

    def setUp(self):
        self.base_dir = "/example_path"
        self.vhosts = util.get_vh_truth(
            self.base_dir, "debian_apache_2_4/multiple_vhosts")

    @classmethod
    def _call(cls, vhosts):
        from certbot_apache._internal.display_ops import select_vhost
        return select_vhost("example.com", vhosts)

    @certbot_util.patch_get_utility()
    def test_successful_choice(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 3)
        self.assertEqual(self.vhosts[3], self._call(self.vhosts))

    @certbot_util.patch_get_utility()
    def test_noninteractive(self, mock_util):
        mock_util().menu.side_effect = errors.MissingCommandlineFlag("no vhost default")
        try:
            self._call(self.vhosts)
        except errors.MissingCommandlineFlag as e:
            self.assertTrue("vhost ambiguity" in str(e))

    @certbot_util.patch_get_utility()
    def test_more_info_cancel(self, mock_util):
        mock_util().menu.side_effect = [
            (display_util.CANCEL, -1),
        ]

        self.assertEqual(None, self._call(self.vhosts))

    def test_no_vhosts(self):
        self.assertEqual(self._call([]), None)

    @mock.patch("certbot_apache._internal.display_ops.display_util")
    @certbot_util.patch_get_utility()
    @mock.patch("certbot_apache._internal.display_ops.logger")
    def test_small_display(self, mock_logger, mock_util, mock_display_util):
        mock_display_util.WIDTH = 20
        mock_util().menu.return_value = (display_util.OK, 0)
        self._call(self.vhosts)

        self.assertEqual(mock_logger.debug.call_count, 1)

    @certbot_util.patch_get_utility()
    def test_multiple_names(self, mock_util):
        mock_util().menu.return_value = (display_util.OK, 5)

        self.vhosts.append(
            obj.VirtualHost(
                "path", "aug_path", {obj.Addr.fromstring("*:80")},
                False, False,
                "wildcard.com", {"*.wildcard.com"}))

        self.assertEqual(self.vhosts[5], self._call(self.vhosts))


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
