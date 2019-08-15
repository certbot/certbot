""" Tests for ParserNode interface """

import unittest

from acme.magic_typing import Optional, Tuple  # pylint: disable=unused-import, no-name-in-module

from certbot_apache import interfaces



class DummyCommentNode(interfaces.ParserNode):
    """ A dummy class implementing CommentNode interface """
    ancestor = None
    comment = ""
    dirty = False
    filename = ""

    def metadata(self, key):  # pragma: no cover
        """Metadata"""
        pass

    def save(self, msg):  # pragma: no cover
        """Save"""
        pass


class DummyDirectiveNode(interfaces.ParserNode):
    """ A dummy class implementing DirectiveNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    dirty = False
    enabled = True
    name = ""
    filename = ""

    def metadata(self, key):  # pragma: no cover
        """Metadata"""
        pass

    def save(self, msg):  # pragma: no cover
        """Save"""
        pass

    def set_parameters(self, parameters):  # pragma: no cover
        """Set parameters"""
        pass


class DummyBlockNode(interfaces.BlockNode):
    """ A dummy class implementing BlockNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    children = tuple()  # type: Tuple[interfaces.ParserNode, ...]
    dirty = False
    enabled = True
    name = ""
    filename = ""

    def save(self, msg):  # pragma: no cover
        """Save"""
        pass

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

    def metadata(self, key):  # pragma: no cover
        """Metadata"""
        pass

    def set_parameters(self, parameters):  # pragma: no cover
        """Set parameters"""
        pass

    def unsaved_files(self):  # pragma: no cover
        """Unsaved files"""
        pass


interfaces.CommentNode.register(DummyCommentNode)
interfaces.DirectiveNode.register(DummyDirectiveNode)
interfaces.BlockNode.register(DummyBlockNode)

class ParserNodeTest(unittest.TestCase):
    """Dummy placeholder test case for ParserNode interfaces"""

    def test_dummy(self):
        dummyblock = DummyBlockNode()
        dummydirective = DummyDirectiveNode()
        dummycomment = DummyCommentNode()


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
