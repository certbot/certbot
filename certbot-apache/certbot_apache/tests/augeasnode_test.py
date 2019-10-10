"""Tests for AugeasParserNode classes"""

from certbot_apache.tests import util


class AugeasParserNodeTest(util.ApacheTest):
    """Test AugeasParserNode using available test configurations"""

    def setUp(self):  # pylint: disable=arguments-differ
        super(AugeasParserNodeTest, self).setUp()

        self.config = util.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir)
        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")

    def test_find_blocks(self):
        blocks = self.config.parser_root.find_blocks("VirtualHost", exclude=False)
        self.assertEqual(len(blocks), 12)

    def test_find_blocks_case_insensitive(self):
        vhs = self.config.parser_root.find_blocks("VirtualHost")
        vhs2 = self.config.parser_root.find_blocks("viRtuAlHoST")
        self.assertEqual(len(vhs), len(vhs2))

    def test_find_directive_found(self):
        directives = self.config.parser_root.find_directives("Listen")
        self.assertEqual(len(directives), 1)
        self.assertTrue(directives[0].filepath.endswith("/apache2/ports.conf"))
        self.assertEqual(directives[0].parameters, (u'80',))

    def test_find_directive_notfound(self):
        directives = self.config.parser_root.find_directives("Nonexistent")
        self.assertEqual(len(directives), 0)

    def test_find_directive_from_block(self):
        blocks = self.config.parser_root.find_blocks("virtualhost")
        found = False
        for vh in blocks:
            if vh.filepath.endswith("sites-enabled/certbot.conf"):
                servername = vh.find_directives("servername")
                self.assertEqual(servername[0].parameters[0], "certbot.demo")
                found = True
        self.assertTrue(found)
