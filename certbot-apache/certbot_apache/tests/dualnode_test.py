"""Tests for DualParserNode implementation"""
import unittest

import mock

from certbot_apache import assertions
from certbot_apache import dualparser


class DualParserNodeTest(unittest.TestCase):
    """DualParserNode tests"""

    def setUp(self):  # pylint: disable=arguments-differ
        self.directive = dualparser.DualDirectiveNode(name="directive",
                                                      ancestor=None,
                                                      filepath="/tmp/something")
        self.comment = dualparser.DualCommentNode(comment="comment",
                                                  ancestor=None,
                                                  filepath="/tmp/something")

    def test_create_with_precreated(self):
        cnode = dualparser.DualCommentNode(comment="comment",
                                           ancestor=None,
                                           filepath="/tmp/something",
                                           primary=self.comment.secondary,
                                           secondary=self.comment.primary)
        dnode = dualparser.DualDirectiveNode(name="directive",
                                             ancestor=None,
                                             filepath="/tmp/something",
                                             primary=self.directive.secondary,
                                             secondary=self.directive.primary)
        # Switched around
        self.assertTrue(cnode.primary is self.comment.secondary)
        self.assertTrue(cnode.secondary is self.comment.primary)
        self.assertTrue(dnode.primary is self.directive.secondary)
        self.assertTrue(dnode.secondary is self.directive.primary)

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
