"""Tests for DualParserNode implementation"""
import unittest

import mock

from certbot_apache import assertions
from certbot_apache import dualparser


class DualParserNodeTest(unittest.TestCase):
    """DualParserNode tests"""
    def setUp(self):  # pylint: disable=arguments-differ
        self.block = dualparser.DualBlockNode(name="block",
                                              ancestor=None,
                                              filepath="/tmp/something")
        self.block_two = dualparser.DualBlockNode(name="block",
                                                  ancestor=self.block,
                                                  filepath="/tmp/something")
        self.directive = dualparser.DualDirectiveNode(name="directive",
                                                      ancestor=self.block,
                                                      filepath="/tmp/something")
        self.comment = dualparser.DualCommentNode(comment="comment",
                                                  ancestor=self.block,
                                                  filepath="/tmp/something")

    def test_create_with_primary(self):
        cnode = dualparser.DualCommentNode(comment="comment",
                                           ancestor=self.block,
                                           filepath="/tmp/something",
                                           primary=self.comment.secondary)
        dnode = dualparser.DualDirectiveNode(name="directive",
                                             ancestor=self.block,
                                             filepath="/tmp/something",
                                             primary=self.directive.secondary)
        bnode = dualparser.DualBlockNode(name="block",
                                         ancestor=self.block,
                                         filepath="/tmp/something",
                                         primary=self.block.secondary)
        self.assertTrue(cnode.primary is self.comment.secondary)
        self.assertTrue(dnode.primary is self.directive.secondary)
        self.assertTrue(bnode.primary is self.block.secondary)

    def test_create_with_secondary(self):
        cnode = dualparser.DualCommentNode(comment="comment",
                                           ancestor=self.block,
                                           filepath="/tmp/something",
                                           secondary=self.comment.primary)
        dnode = dualparser.DualDirectiveNode(name="directive",
                                             ancestor=self.block,
                                             filepath="/tmp/something",
                                             secondary=self.directive.primary)
        bnode = dualparser.DualBlockNode(name="block",
                                         ancestor=self.block,
                                         filepath="/tmp/something",
                                         secondary=self.block.primary)
        self.assertTrue(cnode.secondary is self.comment.primary)
        self.assertTrue(dnode.secondary is self.directive.primary)
        self.assertTrue(bnode.secondary is self.block.primary)

    def test_set_params(self):
        params = ("first", "second")
        self.directive.set_parameters(params)
        self.assertEqual(self.directive.primary.parameters, params)
        self.assertEqual(self.directive.secondary.parameters, params)

    def test_set_parameters(self):
        pparams = mock.MagicMock()
        sparams = mock.MagicMock()
        pparams.parameters = ("a", "b")
        sparams.parameters = ("a", "b")
        self.directive.primary.set_parameters = pparams
        self.directive.secondary.set_parameters = sparams
        self.directive.set_parameters(("param","seq"))
        self.assertTrue(pparams.called)
        self.assertTrue(sparams.called)

    def test_delete_child(self):
        pdel = mock.MagicMock()
        sdel = mock.MagicMock()
        self.block.primary.delete_child = pdel
        self.block.secondary.delete_child = sdel
        self.block.delete_child(self.comment)
        self.assertTrue(pdel.called)
        self.assertTrue(sdel.called)

    def test_unsaved_files(self):
        puns = mock.MagicMock()
        suns = mock.MagicMock()
        puns.return_value = assertions.PASS
        suns.return_value = assertions.PASS
        self.block.primary.unsaved_files = puns
        self.block.secondary.unsaved_files = suns
        self.block.unsaved_files()
        self.assertTrue(puns.called)
        self.assertTrue(suns.called)

    def test_add_child_block(self):
        p = mock.MagicMock()
        p.return_value = self.block
        s = mock.MagicMock()
        s.return_value = self.block
        self.block.primary.add_child_block = p
        self.block.secondary.add_child_block = s
        self.block.add_child_block("name")
        self.assertTrue(p.called)
        self.assertTrue(s.called)

    def test_add_child_directive(self):
        p = mock.MagicMock()
        p.return_value = self.directive
        s = mock.MagicMock()
        s.return_value = self.directive
        self.block.primary.add_child_directive = p
        self.block.secondary.add_child_directive = s
        self.block.add_child_directive("name")
        self.assertTrue(p.called)
        self.assertTrue(s.called)

    def test_add_child_comment(self):
        p = mock.MagicMock()
        p.return_value = self.comment
        s = mock.MagicMock()
        s.return_value = self.comment
        self.block.primary.add_child_comment = p
        self.block.secondary.add_child_comment = s
        self.block.add_child_comment("comment")
        self.assertTrue(p.called)
        self.assertTrue(s.called)

    def test_find_blocks(self):
        dblks = self.block.find_blocks("block")
        p_dblks = [d.primary for d in dblks]
        s_dblks = [d.secondary for d in dblks]
        p_blks = self.block.primary.find_blocks("block")
        s_blks = self.block.secondary.find_blocks("block")
        # Check that every block response is represented in the list of
        # DualParserNode instances.
        for p in p_dblks:
            self.assertTrue(p in p_blks)
        for s in s_dblks:
            self.assertTrue(s in s_blks)

    def test_find_directives(self):
        ddirs = self.block.find_directives("directive")
        p_ddirs = [d.primary for d in ddirs]
        s_ddirs = [d.secondary for d in ddirs]
        p_dirs = self.block.primary.find_directives("directive")
        s_dirs = self.block.secondary.find_directives("directive")
        # Check that every directive response is represented in the list of
        # DualParserNode instances.
        for p in p_ddirs:
            self.assertTrue(p in p_dirs)
        for s in s_ddirs:
            self.assertTrue(s in s_dirs)

    def test_find_comments(self):
        dcoms = self.block.find_comments("comment")
        p_dcoms = [d.primary for d in dcoms]
        s_dcoms = [d.secondary for d in dcoms]
        p_coms = self.block.primary.find_comments("comment")
        s_coms = self.block.secondary.find_comments("comment")
        # Check that every comment response is represented in the list of
        # DualParserNode instances.
        for p in p_dcoms:
            self.assertTrue(p in p_coms)
        for s in s_dcoms:
            self.assertTrue(s in s_coms)
