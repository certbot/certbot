"""Tests for AugeasParserNode classes"""
try:
    import mock
except ImportError: # pragma: no cover
    from unittest import mock # type: ignore

import os
import util

from certbot import errors

from certbot_apache._internal import assertions
from certbot_apache._internal import augeasparser


def _get_augeasnode_mock(filepath):
    """ Helper function for mocking out DualNode instance with an AugeasNode """
    def augeasnode_mock(metadata):
        return augeasparser.AugeasBlockNode(
            name=assertions.PASS,
            ancestor=None,
            filepath=filepath,
            metadata=metadata)
    return augeasnode_mock

class AugeasParserNodeTest(util.ApacheTest):  # pylint: disable=too-many-public-methods
    """Test AugeasParserNode using available test configurations"""

    def setUp(self):  # pylint: disable=arguments-differ
        super(AugeasParserNodeTest, self).setUp()

        with mock.patch("certbot_apache._internal.configurator.ApacheConfigurator.get_parsernode_root") as mock_parsernode:
            mock_parsernode.side_effect = _get_augeasnode_mock(
                                              os.path.join(self.config_path, "apache2.conf"))
            self.config = util.get_apache_configurator(
                self.config_path, self.vhost_path, self.config_dir, self.work_dir, use_parsernode=True)
        self.vh_truth = util.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")

    def test_save(self):
        with mock.patch('certbot_apache._internal.parser.ApacheParser.save') as mock_save:
            self.config.parser_root.save("A save message")
        self.assertTrue(mock_save.called)
        self.assertEqual(mock_save.call_args[0][0], "A save message")

    def test_unsaved_files(self):
        with mock.patch('certbot_apache._internal.parser.ApacheParser.unsaved_files') as mock_uf:
            mock_uf.return_value = ["first", "second"]
            files = self.config.parser_root.unsaved_files()
        self.assertEqual(files, ["first", "second"])

    def test_get_block_node_name(self):
        from certbot_apache._internal.augeasparser import AugeasBlockNode
        block = AugeasBlockNode(
            name=assertions.PASS,
            ancestor=None,
            filepath=assertions.PASS,
            metadata={"augeasparser": mock.Mock(), "augeaspath": "/files/anything"}
        )
        testcases = {
            "/some/path/FirstNode/SecondNode": "SecondNode",
            "/some/path/FirstNode/SecondNode/": "SecondNode",
            "OnlyPathItem": "OnlyPathItem",
            "/files/etc/apache2/apache2.conf/VirtualHost": "VirtualHost",
            "/Anything": "Anything",
        }
        for test in testcases:
            self.assertEqual(block._aug_get_name(test), testcases[test])  # pylint: disable=protected-access

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

    def test_find_comments(self):
        rootcomment = self.config.parser_root.find_comments(
            "This is the main Apache server configuration file. "
        )
        self.assertEqual(len(rootcomment), 1)
        self.assertTrue(rootcomment[0].filepath.endswith(
            "debian_apache_2_4/multiple_vhosts/apache2/apache2.conf"
        ))

    def test_set_parameters(self):
        servernames = self.config.parser_root.find_directives("servername")
        names = []  # type: List[str]
        for servername in servernames:
            names += servername.parameters
        self.assertFalse("going_to_set_this" in names)
        servernames[0].set_parameters(["something", "going_to_set_this"])
        servernames = self.config.parser_root.find_directives("servername")
        names = []
        for servername in servernames:
            names += servername.parameters
        self.assertTrue("going_to_set_this" in names)

    def test_set_parameters_atinit(self):
        from certbot_apache._internal.augeasparser import AugeasDirectiveNode
        servernames = self.config.parser_root.find_directives("servername")
        setparam = "certbot_apache._internal.augeasparser.AugeasDirectiveNode.set_parameters"
        with mock.patch(setparam) as mock_set:
            AugeasDirectiveNode(
                name=servernames[0].name,
                parameters=["test", "setting", "these"],
                ancestor=assertions.PASS,
                metadata=servernames[0].metadata
            )
            self.assertTrue(mock_set.called)
            self.assertEqual(
                mock_set.call_args_list[0][0][0],
                ["test", "setting", "these"]
            )

    def test_set_parameters_delete(self):
        # Set params
        servername = self.config.parser_root.find_directives("servername")[0]
        servername.set_parameters(["thisshouldnotexistpreviously", "another",
                                   "third"])

        # Delete params
        servernames = self.config.parser_root.find_directives("servername")
        found = False
        for servername in servernames:
            if "thisshouldnotexistpreviously" in servername.parameters:
                self.assertEqual(len(servername.parameters), 3)
                servername.set_parameters(["thisshouldnotexistpreviously"])
                found = True
        self.assertTrue(found)

        # Verify params
        servernames = self.config.parser_root.find_directives("servername")
        found = False
        for servername in servernames:
            if "thisshouldnotexistpreviously" in servername.parameters:
                self.assertEqual(len(servername.parameters), 1)
                servername.set_parameters(["thisshouldnotexistpreviously"])
                found = True
        self.assertTrue(found)

    def test_add_child_comment(self):
        newc = self.config.parser_root.add_child_comment("The content")
        comments = self.config.parser_root.find_comments("The content")
        self.assertEqual(len(comments), 1)
        self.assertEqual(
            newc.metadata["augeaspath"],
            comments[0].metadata["augeaspath"]
        )
        self.assertEqual(newc.comment, comments[0].comment)

    def test_delete_child(self):
        listens = self.config.parser_root.find_directives("Listen")
        self.assertEqual(len(listens), 1)
        self.config.parser_root.delete_child(listens[0])

        listens = self.config.parser_root.find_directives("Listen")
        self.assertEqual(len(listens), 0)

    def test_delete_child_not_found(self):
        listen = self.config.parser_root.find_directives("Listen")[0]
        listen.metadata["augeaspath"] = "/files/something/nonexistent"

        self.assertRaises(
            errors.PluginError,
            self.config.parser_root.delete_child,
            listen
        )

    def test_add_child_block(self):
        nb = self.config.parser_root.add_child_block(
            "NewBlock",
            ["first", "second"]
        )
        rpath, _, directive = nb.metadata["augeaspath"].rpartition("/")
        self.assertEqual(
            rpath,
            self.config.parser_root.metadata["augeaspath"]
        )
        self.assertTrue(directive.startswith("NewBlock"))

    def test_add_child_block_beginning(self):
        self.config.parser_root.add_child_block(
            "Beginning",
            position=0
        )
        parser = self.config.parser_root.parser
        root_path = self.config.parser_root.metadata["augeaspath"]
        # Get first child
        first = parser.aug.match("{}/*[1]".format(root_path))
        self.assertTrue(first[0].endswith("Beginning"))

    def test_add_child_block_append(self):
        self.config.parser_root.add_child_block(
            "VeryLast",
        )
        parser = self.config.parser_root.parser
        root_path = self.config.parser_root.metadata["augeaspath"]
        # Get last child
        last = parser.aug.match("{}/*[last()]".format(root_path))
        self.assertTrue(last[0].endswith("VeryLast"))

    def test_add_child_block_append_alt(self):
        self.config.parser_root.add_child_block(
            "VeryLastAlt",
            position=99999
        )
        parser = self.config.parser_root.parser
        root_path = self.config.parser_root.metadata["augeaspath"]
        # Get last child
        last = parser.aug.match("{}/*[last()]".format(root_path))
        self.assertTrue(last[0].endswith("VeryLastAlt"))

    def test_add_child_block_middle(self):
        self.config.parser_root.add_child_block(
            "Middle",
            position=5
        )
        parser = self.config.parser_root.parser
        root_path = self.config.parser_root.metadata["augeaspath"]
        # Augeas indices start at 1 :(
        middle = parser.aug.match("{}/*[6]".format(root_path))
        self.assertTrue(middle[0].endswith("Middle"))

    def test_add_child_block_existing_name(self):
        parser = self.config.parser_root.parser
        root_path = self.config.parser_root.metadata["augeaspath"]
        # There already exists a single VirtualHost in the base config
        new_block = parser.aug.match("{}/VirtualHost[2]".format(root_path))
        self.assertEqual(len(new_block), 0)
        vh = self.config.parser_root.add_child_block(
            "VirtualHost",
        )
        new_block = parser.aug.match("{}/VirtualHost[2]".format(root_path))
        self.assertEqual(len(new_block), 1)
        self.assertTrue(vh.metadata["augeaspath"].endswith("VirtualHost[2]"))

    def test_node_init_error_bad_augeaspath(self):
        from certbot_apache._internal.augeasparser import AugeasBlockNode
        parameters = {
            "name": assertions.PASS,
            "ancestor": None,
            "filepath": assertions.PASS,
            "metadata": {
                "augeasparser": mock.Mock(),
                "augeaspath": "/files/path/endswith/slash/"
            }
        }
        self.assertRaises(
            errors.PluginError,
            AugeasBlockNode,
            **parameters
        )

    def test_node_init_error_missing_augeaspath(self):
        from certbot_apache._internal.augeasparser import AugeasBlockNode
        parameters = {
            "name": assertions.PASS,
            "ancestor": None,
            "filepath": assertions.PASS,
            "metadata": {
                "augeasparser": mock.Mock(),
            }
        }
        self.assertRaises(
            errors.PluginError,
            AugeasBlockNode,
            **parameters
        )

    def test_add_child_directive(self):
        self.config.parser_root.add_child_directive(
            "ThisWasAdded",
            ["with", "parameters"],
            position=0
        )
        dirs = self.config.parser_root.find_directives("ThisWasAdded")
        self.assertEqual(len(dirs), 1)
        self.assertEqual(dirs[0].parameters, ("with", "parameters"))
        # The new directive was added to the very first line of the config
        self.assertTrue(dirs[0].metadata["augeaspath"].endswith("[1]"))

    def test_add_child_directive_exception(self):
        self.assertRaises(
            errors.PluginError,
            self.config.parser_root.add_child_directive,
            "ThisRaisesErrorBecauseMissingParameters"
        )

    def test_parsed_paths(self):
        paths = self.config.parser_root.parsed_paths()
        self.assertEqual(len(paths), 6)

    def test_find_ancestors(self):
        vhsblocks = self.config.parser_root.find_blocks("VirtualHost")
        macro_test = False
        nonmacro_test = False
        for vh in vhsblocks:
            if "/macro/" in vh.metadata["augeaspath"].lower():
                ancs = vh.find_ancestors("Macro")
                self.assertEqual(len(ancs), 1)
                macro_test = True
            else:
                ancs = vh.find_ancestors("Macro")
                self.assertEqual(len(ancs), 0)
                nonmacro_test = True
        self.assertTrue(macro_test)
        self.assertTrue(nonmacro_test)

    def test_find_ancestors_bad_path(self):
        self.config.parser_root.metadata["augeaspath"] = ""
        ancs = self.config.parser_root.find_ancestors("Anything")
        self.assertEqual(len(ancs), 0)
