"""Tests for DualParserNode implementation"""
import unittest
from unittest import mock

from certbot_apache._internal import assertions
from certbot_apache._internal import augeasparser
from certbot_apache._internal import dualparser
import pytest


class DualParserNodeTest(unittest.TestCase):  # pylint: disable=too-many-public-methods
    """DualParserNode tests"""

    def setUp(self):  # pylint: disable=arguments-differ
        parser_mock = mock.MagicMock()
        parser_mock.aug.match.return_value = []
        parser_mock.get_arg.return_value = []
        self.metadata = {"augeasparser": parser_mock, "augeaspath": "/invalid", "ac_ast": None}
        self.block = dualparser.DualBlockNode(name="block",
                                              ancestor=None,
                                              filepath="/tmp/something",
                                              metadata=self.metadata)
        self.block_two = dualparser.DualBlockNode(name="block",
                                                  ancestor=self.block,
                                                  filepath="/tmp/something",
                                                  metadata=self.metadata)
        self.directive = dualparser.DualDirectiveNode(name="directive",
                                                      ancestor=self.block,
                                                      filepath="/tmp/something",
                                                      metadata=self.metadata)
        self.comment = dualparser.DualCommentNode(comment="comment",
                                                  ancestor=self.block,
                                                  filepath="/tmp/something",
                                                  metadata=self.metadata)

    def test_create_with_precreated(self):
        cnode = dualparser.DualCommentNode(comment="comment",
                                           ancestor=self.block,
                                           filepath="/tmp/something",
                                           primary=self.comment.secondary,
                                           secondary=self.comment.primary)
        dnode = dualparser.DualDirectiveNode(name="directive",
                                             ancestor=self.block,
                                             filepath="/tmp/something",
                                             primary=self.directive.secondary,
                                             secondary=self.directive.primary)
        bnode = dualparser.DualBlockNode(name="block",
                                         ancestor=self.block,
                                         filepath="/tmp/something",
                                         primary=self.block.secondary,
                                         secondary=self.block.primary)
        # Switched around
        assert cnode.primary == self.comment.secondary
        assert cnode.secondary == self.comment.primary
        assert dnode.primary == self.directive.secondary
        assert dnode.secondary == self.directive.primary
        assert bnode.primary == self.block.secondary
        assert bnode.secondary == self.block.primary

    def test_set_params(self):
        params = ("first", "second")
        self.directive.primary.set_parameters = mock.Mock()
        self.directive.secondary.set_parameters = mock.Mock()
        self.directive.set_parameters(params)
        assert self.directive.primary.set_parameters.called is True
        assert self.directive.secondary.set_parameters.called is True

    def test_set_parameters(self):
        pparams = mock.MagicMock()
        sparams = mock.MagicMock()
        pparams.parameters = ("a", "b")
        sparams.parameters = ("a", "b")
        self.directive.primary.set_parameters = pparams
        self.directive.secondary.set_parameters = sparams
        self.directive.set_parameters(("param", "seq"))
        assert pparams.called is True
        assert sparams.called is True

    def test_delete_child(self):
        pdel = mock.MagicMock()
        sdel = mock.MagicMock()
        self.block.primary.delete_child = pdel
        self.block.secondary.delete_child = sdel
        self.block.delete_child(self.comment)
        assert pdel.called is True
        assert sdel.called is True

    def test_unsaved_files(self):
        puns = mock.MagicMock()
        suns = mock.MagicMock()
        puns.return_value = assertions.PASS
        suns.return_value = assertions.PASS
        self.block.primary.unsaved_files = puns
        self.block.secondary.unsaved_files = suns
        self.block.unsaved_files()
        assert puns.called is True
        assert suns.called is True

    def test_getattr_equality(self):
        self.directive.primary.variableexception = "value"
        self.directive.secondary.variableexception = "not_value"
        with pytest.raises(AssertionError):
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
        with pytest.raises(AssertionError):
            assertions.assertEqual(self.comment.primary, self.comment.secondary)

    def test_parsernode_filepath_assert(self):
        # disable assertion pass
        self.comment.primary.comment = "value"
        self.comment.secondary.comment = "value"

        self.comment.primary.filepath = "first"
        self.comment.secondary.filepath = "second"
        with pytest.raises(AssertionError):
            assertions.assertEqual(self.comment.primary, self.comment.secondary)

    def test_add_child_block(self):
        mock_first = mock.MagicMock(return_value=self.block.primary)
        mock_second = mock.MagicMock(return_value=self.block.secondary)
        self.block.primary.add_child_block = mock_first
        self.block.secondary.add_child_block = mock_second
        self.block.add_child_block("Block")
        assert mock_first.called is True
        assert mock_second.called is True

    def test_add_child_directive(self):
        mock_first = mock.MagicMock(return_value=self.directive.primary)
        mock_second = mock.MagicMock(return_value=self.directive.secondary)
        self.block.primary.add_child_directive = mock_first
        self.block.secondary.add_child_directive = mock_second
        self.block.add_child_directive("Directive")
        assert mock_first.called is True
        assert mock_second.called is True

    def test_add_child_comment(self):
        mock_first = mock.MagicMock(return_value=self.comment.primary)
        mock_second = mock.MagicMock(return_value=self.comment.secondary)
        self.block.primary.add_child_comment = mock_first
        self.block.secondary.add_child_comment = mock_second
        self.block.add_child_comment("Comment")
        assert mock_first.called is True
        assert mock_second.called is True

    def test_find_comments(self):
        pri_comments = [augeasparser.AugeasCommentNode(comment="some comment",
                                                       ancestor=self.block,
                                                       filepath="/path/to/whatever",
                                                       metadata=self.metadata)]
        sec_comments = [augeasparser.AugeasCommentNode(comment=assertions.PASS,
                                                       ancestor=self.block,
                                                       filepath=assertions.PASS,
                                                       metadata=self.metadata)]
        find_coms_primary = mock.MagicMock(return_value=pri_comments)
        find_coms_secondary = mock.MagicMock(return_value=sec_comments)
        self.block.primary.find_comments = find_coms_primary
        self.block.secondary.find_comments = find_coms_secondary

        dcoms = self.block.find_comments("comment")
        p_dcoms = [d.primary for d in dcoms]
        s_dcoms = [d.secondary for d in dcoms]
        p_coms = self.block.primary.find_comments("comment")
        s_coms = self.block.secondary.find_comments("comment")
        # Check that every comment response is represented in the list of
        # DualParserNode instances.
        for p in p_dcoms:
            assert p in p_coms
        for s in s_dcoms:
            assert s in s_coms

    def test_find_blocks_first_passing(self):
        youshallnotpass = [augeasparser.AugeasBlockNode(name="notpassing",
                                                        ancestor=self.block,
                                                        filepath="/path/to/whatever",
                                                        metadata=self.metadata)]
        youshallpass = [augeasparser.AugeasBlockNode(name=assertions.PASS,
                                                     ancestor=self.block,
                                                     filepath=assertions.PASS,
                                                     metadata=self.metadata)]
        find_blocks_primary = mock.MagicMock(return_value=youshallpass)
        find_blocks_secondary = mock.MagicMock(return_value=youshallnotpass)
        self.block.primary.find_blocks = find_blocks_primary
        self.block.secondary.find_blocks = find_blocks_secondary

        blocks = self.block.find_blocks("something")
        for block in blocks:
            try:
                assertions.assertEqual(block.primary, block.secondary)
            except AssertionError: # pragma: no cover
                self.fail("Assertion should have passed")
            assert assertions.isPassDirective(block.primary) is True
            assert assertions.isPassDirective(block.secondary) is False

    def test_find_blocks_second_passing(self):
        youshallnotpass = [augeasparser.AugeasBlockNode(name="notpassing",
                                                        ancestor=self.block,
                                                        filepath="/path/to/whatever",
                                                        metadata=self.metadata)]
        youshallpass = [augeasparser.AugeasBlockNode(name=assertions.PASS,
                                                     ancestor=self.block,
                                                     filepath=assertions.PASS,
                                                     metadata=self.metadata)]
        find_blocks_primary = mock.MagicMock(return_value=youshallnotpass)
        find_blocks_secondary = mock.MagicMock(return_value=youshallpass)
        self.block.primary.find_blocks = find_blocks_primary
        self.block.secondary.find_blocks = find_blocks_secondary

        blocks = self.block.find_blocks("something")
        for block in blocks:
            try:
                assertions.assertEqual(block.primary, block.secondary)
            except AssertionError: # pragma: no cover
                self.fail("Assertion should have passed")
            assert assertions.isPassDirective(block.primary) is False
            assert assertions.isPassDirective(block.secondary) is True

    def test_find_dirs_first_passing(self):
        notpassing = [augeasparser.AugeasDirectiveNode(name="notpassing",
                                                       ancestor=self.block,
                                                       filepath="/path/to/whatever",
                                                       metadata=self.metadata)]
        passing = [augeasparser.AugeasDirectiveNode(name=assertions.PASS,
                                                    ancestor=self.block,
                                                    filepath=assertions.PASS,
                                                    metadata=self.metadata)]
        find_dirs_primary = mock.MagicMock(return_value=passing)
        find_dirs_secondary = mock.MagicMock(return_value=notpassing)
        self.block.primary.find_directives = find_dirs_primary
        self.block.secondary.find_directives = find_dirs_secondary

        directives = self.block.find_directives("something")
        for directive in directives:
            try:
                assertions.assertEqual(directive.primary, directive.secondary)
            except AssertionError: # pragma: no cover
                self.fail("Assertion should have passed")
            assert assertions.isPassDirective(directive.primary) is True
            assert assertions.isPassDirective(directive.secondary) is False

    def test_find_dirs_second_passing(self):
        notpassing = [augeasparser.AugeasDirectiveNode(name="notpassing",
                                                       ancestor=self.block,
                                                       filepath="/path/to/whatever",
                                                       metadata=self.metadata)]
        passing = [augeasparser.AugeasDirectiveNode(name=assertions.PASS,
                                                    ancestor=self.block,
                                                    filepath=assertions.PASS,
                                                    metadata=self.metadata)]
        find_dirs_primary = mock.MagicMock(return_value=notpassing)
        find_dirs_secondary = mock.MagicMock(return_value=passing)
        self.block.primary.find_directives = find_dirs_primary
        self.block.secondary.find_directives = find_dirs_secondary

        directives = self.block.find_directives("something")
        for directive in directives:
            try:
                assertions.assertEqual(directive.primary, directive.secondary)
            except AssertionError: # pragma: no cover
                self.fail("Assertion should have passed")
            assert assertions.isPassDirective(directive.primary) is False
            assert assertions.isPassDirective(directive.secondary) is True

    def test_find_coms_first_passing(self):
        notpassing = [augeasparser.AugeasCommentNode(comment="notpassing",
                                                     ancestor=self.block,
                                                     filepath="/path/to/whatever",
                                                     metadata=self.metadata)]
        passing = [augeasparser.AugeasCommentNode(comment=assertions.PASS,
                                                  ancestor=self.block,
                                                  filepath=assertions.PASS,
                                                  metadata=self.metadata)]
        find_coms_primary = mock.MagicMock(return_value=passing)
        find_coms_secondary = mock.MagicMock(return_value=notpassing)
        self.block.primary.find_comments = find_coms_primary
        self.block.secondary.find_comments = find_coms_secondary

        comments = self.block.find_comments("something")
        for comment in comments:
            try:
                assertions.assertEqual(comment.primary, comment.secondary)
            except AssertionError: # pragma: no cover
                self.fail("Assertion should have passed")
            assert assertions.isPassComment(comment.primary) is True
            assert assertions.isPassComment(comment.secondary) is False

    def test_find_coms_second_passing(self):
        notpassing = [augeasparser.AugeasCommentNode(comment="notpassing",
                                                     ancestor=self.block,
                                                     filepath="/path/to/whatever",
                                                     metadata=self.metadata)]
        passing = [augeasparser.AugeasCommentNode(comment=assertions.PASS,
                                                  ancestor=self.block,
                                                  filepath=assertions.PASS,
                                                  metadata=self.metadata)]
        find_coms_primary = mock.MagicMock(return_value=notpassing)
        find_coms_secondary = mock.MagicMock(return_value=passing)
        self.block.primary.find_comments = find_coms_primary
        self.block.secondary.find_comments = find_coms_secondary

        comments = self.block.find_comments("something")
        for comment in comments:
            try:
                assertions.assertEqual(comment.primary, comment.secondary)
            except AssertionError: # pragma: no cover
                self.fail("Assertion should have passed")
            assert assertions.isPassComment(comment.primary) is False
            assert assertions.isPassComment(comment.secondary) is True

    def test_find_blocks_no_pass_equal(self):
        notpassing1 = [augeasparser.AugeasBlockNode(name="notpassing",
                                                    ancestor=self.block,
                                                    filepath="/path/to/whatever",
                                                    metadata=self.metadata)]
        notpassing2 = [augeasparser.AugeasBlockNode(name="notpassing",
                                                    ancestor=self.block,
                                                    filepath="/path/to/whatever",
                                                    metadata=self.metadata)]
        find_blocks_primary = mock.MagicMock(return_value=notpassing1)
        find_blocks_secondary = mock.MagicMock(return_value=notpassing2)
        self.block.primary.find_blocks = find_blocks_primary
        self.block.secondary.find_blocks = find_blocks_secondary

        blocks = self.block.find_blocks("anything")
        for block in blocks:
            with self.subTest(block=block):
                assert block.primary == block.secondary
                assert block.primary is not block.secondary

    def test_find_dirs_no_pass_equal(self):
        notpassing1 = [augeasparser.AugeasDirectiveNode(name="notpassing",
                                                        ancestor=self.block,
                                                        filepath="/path/to/whatever",
                                                        metadata=self.metadata)]
        notpassing2 = [augeasparser.AugeasDirectiveNode(name="notpassing",
                                                        ancestor=self.block,
                                                        filepath="/path/to/whatever",
                                                        metadata=self.metadata)]
        find_dirs_primary = mock.MagicMock(return_value=notpassing1)
        find_dirs_secondary = mock.MagicMock(return_value=notpassing2)
        self.block.primary.find_directives = find_dirs_primary
        self.block.secondary.find_directives = find_dirs_secondary

        directives = self.block.find_directives("anything")
        for directive in directives:
            with self.subTest(directive=directive):
                assert directive.primary == directive.secondary
                assert directive.primary is not directive.secondary

    def test_find_comments_no_pass_equal(self):
        notpassing1 = [augeasparser.AugeasCommentNode(comment="notpassing",
                                                      ancestor=self.block,
                                                      filepath="/path/to/whatever",
                                                      metadata=self.metadata)]
        notpassing2 = [augeasparser.AugeasCommentNode(comment="notpassing",
                                                      ancestor=self.block,
                                                      filepath="/path/to/whatever",
                                                      metadata=self.metadata)]
        find_coms_primary = mock.MagicMock(return_value=notpassing1)
        find_coms_secondary = mock.MagicMock(return_value=notpassing2)
        self.block.primary.find_comments = find_coms_primary
        self.block.secondary.find_comments = find_coms_secondary

        comments = self.block.find_comments("anything")
        for comment in comments:
            with self.subTest(comment=comment):
                assert comment.primary == comment.secondary
                assert comment.primary is not comment.secondary

    def test_find_blocks_no_pass_notequal(self):
        notpassing1 = [augeasparser.AugeasBlockNode(name="notpassing",
                                                    ancestor=self.block,
                                                    filepath="/path/to/whatever",
                                                    metadata=self.metadata)]
        notpassing2 = [augeasparser.AugeasBlockNode(name="different",
                                                    ancestor=self.block,
                                                    filepath="/path/to/whatever",
                                                    metadata=self.metadata)]
        find_blocks_primary = mock.MagicMock(return_value=notpassing1)
        find_blocks_secondary = mock.MagicMock(return_value=notpassing2)
        self.block.primary.find_blocks = find_blocks_primary
        self.block.secondary.find_blocks = find_blocks_secondary

        with pytest.raises(AssertionError):
            _ = self.block.find_blocks("anything")

    def test_parsernode_notequal(self):
        ne_block = augeasparser.AugeasBlockNode(name="different",
                                                ancestor=self.block,
                                                filepath="/path/to/whatever",
                                                metadata=self.metadata)
        ne_directive = augeasparser.AugeasDirectiveNode(name="different",
                                                        ancestor=self.block,
                                                        filepath="/path/to/whatever",
                                                        metadata=self.metadata)
        ne_comment = augeasparser.AugeasCommentNode(comment="different",
                                                    ancestor=self.block,
                                                    filepath="/path/to/whatever",
                                                    metadata=self.metadata)
        assert self.block != ne_block
        assert self.directive != ne_directive
        assert self.comment != ne_comment

    def test_parsed_paths(self):
        mock_p = mock.MagicMock(return_value=['/path/file.conf',
                                              '/another/path',
                                              '/path/other.conf'])
        mock_s = mock.MagicMock(return_value=['/path/*.conf', '/another/path'])
        self.block.primary.parsed_paths = mock_p
        self.block.secondary.parsed_paths = mock_s
        self.block.parsed_paths()
        assert mock_p.called is True
        assert mock_s.called is True

    def test_parsed_paths_error(self):
        mock_p = mock.MagicMock(return_value=['/path/file.conf'])
        mock_s = mock.MagicMock(return_value=['/path/*.conf', '/another/path'])
        self.block.primary.parsed_paths = mock_p
        self.block.secondary.parsed_paths = mock_s
        with pytest.raises(AssertionError):
            self.block.parsed_paths()

    def test_find_ancestors(self):
        primarymock = mock.MagicMock(return_value=[])
        secondarymock = mock.MagicMock(return_value=[])
        self.block.primary.find_ancestors = primarymock
        self.block.secondary.find_ancestors = secondarymock
        self.block.find_ancestors("anything")
        assert primarymock.called is True
        assert secondarymock.called is True
