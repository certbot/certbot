"""Tests for DualParserNode implementation"""
import unittest

import mock

from certbot_apache import assertions
from certbot_apache import dualparser
from certbot_apache import interfaces


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
        self.directive.set_parameters(("param", "seq"))
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

    def test_getattr_equality(self):
        self.directive.primary.variableexception = "value"
        self.directive.secondary.variableexception = "not_value"
        with self.assertRaises(AssertionError):
            _ = self.directive.variableexception

        self.directive.primary.variable = "value"
        self.directive.secondary.variable = "value"
        try:
            self.directive.variable
        except AssertionError: # pragma: no cover
            self.fail("getattr check raised an AssertionError where it shouldn't have")

    def test_parsernode_dirty_assert(self):
        # disable assertion pass
        self.comment.primary.comment = "value"
        self.comment.secondary.comment = "value"
        self.comment.primary.filepath = "x"
        self.comment.secondary.filepath = "x"

        self.comment.primary.dirty = False
        self.comment.secondary.dirty = True
        with self.assertRaises(AssertionError):
            assertions.assertEqual(self.comment.primary, self.comment.secondary)

    def test_parsernode_filepath_assert(self):
        # disable assertion pass
        self.comment.primary.comment = "value"
        self.comment.secondary.comment = "value"

        self.comment.primary.filepath = "first"
        self.comment.secondary.filepath = "second"
        with self.assertRaises(AssertionError):
            assertions.assertEqual(self.comment.primary, self.comment.secondary)

    def test_add_child_block(self):
        self.assertEqual(len(self.block.primary.children), 0)
        self.assertEqual(len(self.block.secondary.children), 0)
        self.block.add_child_block("Block")
        self.assertEqual(len(self.block.primary.children), 1)
        self.assertEqual(len(self.block.secondary.children), 1)
        self.assertTrue(isinstance(self.block.primary.children[0],
                                   interfaces.BlockNode))
        self.assertEqual(self.block.primary.children[0].ancestor,
                         self.block.primary)

    def test_add_child_directive(self):
        self.assertEqual(len(self.block.primary.children), 0)
        self.assertEqual(len(self.block.secondary.children), 0)
        self.block.add_child_directive("Directive")
        self.assertEqual(len(self.block.primary.children), 1)
        self.assertEqual(len(self.block.secondary.children), 1)
        self.assertTrue(isinstance(self.block.primary.children[0],
                                   interfaces.DirectiveNode))
        self.assertEqual(self.block.primary.children[0].ancestor,
                         self.block.primary)

    def test_add_child_comment(self):
        self.assertEqual(len(self.block.primary.children), 0)
        self.assertEqual(len(self.block.secondary.children), 0)
        self.block.add_child_comment("Comment")
        self.assertEqual(len(self.block.primary.children), 1)
        self.assertEqual(len(self.block.secondary.children), 1)
        self.assertTrue(isinstance(self.block.primary.children[0],
                                   interfaces.CommentNode))
        self.assertEqual(self.block.primary.children[0].ancestor,
                         self.block.primary)
