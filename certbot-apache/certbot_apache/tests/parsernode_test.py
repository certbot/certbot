""" Tests for ParserNode interface """

import unittest

import mock

from acme.magic_typing import Dict, List, Optional  # pylint: disable=unused-import, no-name-in-module

from certbot_apache import dualparser
from certbot_apache import interfaces
from certbot_apache import parsernode_util as util

from certbot_apache.tests import util as testutil


class DummyParserNode(interfaces.ParserNode):
    """ A dummy class implementing ParserNode interface """

    def __init__(self, **kwargs):
        """
        Initializes the ParserNode instance.
        """
        ancestor, dirty, filepath, metadata = util.parsernode_kwargs(kwargs)
        self.ancestor = ancestor
        self.dirty = dirty
        self.filepath = filepath
        self.metadata = metadata
        super(DummyParserNode, self).__init__(**kwargs)

    def save(self, msg):  # pragma: no cover
        """Save"""
        pass


class DummyCommentNode(DummyParserNode):
    """ A dummy class implementing CommentNode interface """

    def __init__(self, **kwargs):
        """
        Initializes the CommentNode instance and sets its instance variables.
        """
        comment, kwargs = util.commentnode_kwargs(kwargs)
        self.comment = comment
        super(DummyCommentNode, self).__init__(**kwargs)


class DummyDirectiveNode(DummyParserNode):
    """ A dummy class implementing DirectiveNode interface """

    # pylint: disable=too-many-arguments
    def __init__(self, **kwargs):
        """
        Initializes the DirectiveNode instance and sets its instance variables.
        """
        name, parameters, enabled, kwargs = util.directivenode_kwargs(kwargs)
        self.name = name
        self.parameters = parameters
        self.enabled = enabled

        super(DummyDirectiveNode, self).__init__(**kwargs)

    def set_parameters(self, parameters):  # pragma: no cover
        """Set parameters"""
        pass


class DummyBlockNode(DummyDirectiveNode):
    """ A dummy class implementing BlockNode interface """

    def add_child_block(self, name, parameters=None, position=None):  # pragma: no cover
        """Add child block"""
        pass

    def add_child_directive(self, name, parameters=None, position=None):  # pragma: no cover
        """Add child directive"""
        pass

    def add_child_comment(self, comment="", position=None):  # pragma: no cover
        """Add child comment"""
        pass

    def find_blocks(self, name, exclude=True):  # pragma: no cover
        """Find blocks"""
        pass

    def find_directives(self, name, exclude=True):  # pragma: no cover
        """Find directives"""
        pass

    def find_comments(self, comment, exact=False):  # pragma: no cover
        """Find comments"""
        pass

    def delete_child(self, child):  # pragma: no cover
        """Delete child"""
        pass

    def unsaved_files(self):  # pragma: no cover
        """Unsaved files"""
        pass


interfaces.CommentNode.register(DummyCommentNode)
interfaces.DirectiveNode.register(DummyDirectiveNode)
interfaces.BlockNode.register(DummyBlockNode)

class DummyParserNodeTest(unittest.TestCase):
    """Dummy placeholder test case for ParserNode interfaces"""

    def test_dummy(self):
        dummyblock = DummyBlockNode(
            name="None",
            parameters=(),
            ancestor=None,
            dirty=False,
            filepath="/some/random/path"
        )
        dummydirective = DummyDirectiveNode(
            name="Name",
            ancestor=None,
            filepath="/another/path"
        )
        dummycomment = DummyCommentNode(
            comment="Comment",
            ancestor=dummyblock,
            filepath="/some/file"
        )


class ParserNodeTest(testutil.ApacheTest):
    """Tests for ParserNode functionalities in ApacheConfigurator"""

    def setUp(self):  # pylint: disable=arguments-differ
        super(ParserNodeTest, self).setUp()

        self.config = testutil.get_apache_configurator(
            self.config_path, self.vhost_path, self.config_dir, self.work_dir)
        self.vh_truth = testutil.get_vh_truth(
            self.temp_dir, "debian_apache_2_4/multiple_vhosts")

    def _get_virtual_hosts_sideeffect(self,
                                      vhost_params=("*:80",),
                                      filepath="/tmp/something",
                                      servername=("pnode.example.org",),
                                      serveralias=("pnode2.example.org",),
                                      ssl=False,
                                      macro=False):
        """ Gets the mock.side_effect chain for get_virtual_hosts.

        The calls for find_directives occur in order of:
            - SSLEngine
            - Macro
            - ServerName
            - ServerAlias
        """
        # pylint: disable=too-many-arguments

        ret = dict()  # type: Dict[str, List[List[Optional[dualparser.DualNodeBase]]]]
        ret["blocks"] = []
        ret["dirs"] = []

        vh_block = DummyBlockNode(
            name="VirtualHost",
            parameters=vhost_params,
            ancestor=self.config.parser_root,
            filepath=filepath
        )

        ret["blocks"].append(
            [dualparser.DualBlockNode(primary=vh_block, secondary=vh_block)]
        )

        if ssl:
            ssl_dir = DummyDirectiveNode(
                name="SSLEngine",
                parameters=("on",),
                ancestor=ret["blocks"],
                filepath=filepath
            )
            ret["dirs"].append(
                [dualparser.DualDirectiveNode(primary=ssl_dir, secondary=ssl_dir)]
            )
        else:
            ret["dirs"].append([])

        if macro:
            m_dir = DummyDirectiveNode(
                name="Macro",
                parameters=("on",),
                ancestor=ret["blocks"],
                filepath=filepath
            )
            ret["dirs"].append(
                [dualparser.DualDirectiveNode(primary=m_dir, secondary=m_dir)]
            )
        else:
            ret["dirs"].append([])

        if servername is not None:
            sn_dir = DummyDirectiveNode(
                name="ServerName",
                parameters=servername,
                ancestor=ret["blocks"],
                filepath=filepath
            )
            ret["dirs"].append(
                [dualparser.DualDirectiveNode(primary=sn_dir, secondary=sn_dir)]
            )
        else: # pragma: no cover
            ret["dirs"].append([])

        if serveralias is not None:
            sa_dir = DummyDirectiveNode(
                name="ServerAlias",
                parameters=serveralias,
                ancestor=ret["blocks"],
                filepath=filepath
            )
            ret["dirs"].append(
                [dualparser.DualDirectiveNode(primary=sa_dir, secondary=sa_dir)]
            )
        else: # pragma: no cover
            ret["dirs"].append([])

        return ret

    def _call_get_vhosts(self, side_effects):
        dirs = "certbot_apache.dualparser.DualBlockNode.find_directives"
        blks = "certbot_apache.dualparser.DualBlockNode.find_blocks"
        with mock.patch(dirs) as mock_dirs:
            mock_dirs.side_effect = side_effects["dirs"]
            with mock.patch(blks) as mock_blocks:
                mock_blocks.side_effect = side_effects["blocks"]
                return self.config.get_virtual_hosts_v2()

    def test_get_virtual_hosts(self):
        side_effects = self._get_virtual_hosts_sideeffect()
        vhosts = self._call_get_vhosts(side_effects)
        self.assertEqual(vhosts[0].name, "pnode.example.org")
        self.assertTrue("pnode2.example.org" in vhosts[0].aliases)
        self.assertEqual(len(vhosts[0].aliases), 1)
        self.assertFalse(vhosts[0].ssl)
        self.assertFalse(vhosts[0].modmacro)
        self.assertEqual(vhosts[0].filep, "/tmp/something")

    def test_get_virtual_hosts_ssl_by_port(self):
        side_effects = self._get_virtual_hosts_sideeffect(
            vhost_params=("*:443",))
        vhosts = self._call_get_vhosts(side_effects)
        self.assertTrue(vhosts[0].ssl)

    def test_get_virtual_hosts_ssl_by_sslengine(self):
        side_effects = self._get_virtual_hosts_sideeffect(
            ssl=True)
        vhosts = self._call_get_vhosts(side_effects)
        self.assertTrue(vhosts[0].ssl)

    def test_get_virtual_hosts_modmacro(self):
        side_effects = self._get_virtual_hosts_sideeffect(
            macro=True)
        vhosts = self._call_get_vhosts(side_effects)
        self.assertTrue(vhosts[0].modmacro)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
