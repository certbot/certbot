""" Tests for ParserNode interface """

import unittest

from acme.magic_typing import Optional, Tuple  # pylint: disable=unused-import, no-name-in-module

from certbot_apache import interfaces


class DummyParserNode(interfaces.ParserNode):
    """ A dummy class implementing ParserNode interface """
    ancestor = None
    dirty = False
    filepath = None

    def __init__(self, ancestor=None, filepath=str(), dirty=False):
        """
        Initializes the ParserNode instance.
        """
        super(DummyParserNode, self).__init__(ancestor, filepath, dirty)
        self.ancestor = ancestor
        self.dirty = dirty
        self.filepath = filepath

    def save(self, msg):  # pragma: no cover
        """Save"""
        pass


class DummyCommentNode(DummyParserNode):
    """ A dummy class implementing CommentNode interface """

    def __init__(self, comment, ancestor, filepath, dirty=False):
        """
        Initializes the CommentNode instance and sets its instance variables.
        """
        super(DummyCommentNode, self).__init__(ancestor, filepath, dirty)
        self.comment = comment


class DummyDirectiveNode(DummyParserNode):
    """ A dummy class implementing DirectiveNode interface """
    parameters = tuple()  # type: Tuple[str, ...]
    enabled = True
    name = ""

    # pylint: disable=too-many-arguments
    def __init__(self, name, parameters=(), ancestor=None, filepath="",
                 dirty=False, enabled=True):
        """
        Initializes the DirectiveNode instance and sets its instance variables.
        """
        super(DummyDirectiveNode, self).__init__(ancestor, filepath, dirty)
        self.name = name
        self.parameters = parameters
        self.enabled = enabled

    def set_parameters(self, parameters):  # pragma: no cover
        """Set parameters"""
        pass


class DummyBlockNode(DummyParserNode):
    """ A dummy class implementing BlockNode interface """
    parameters = tuple()  # type: Tuple[str, ...]
    children = tuple()  # type: Tuple[interfaces.ParserNode, ...]
    enabled = True
    name = ""

    # pylint: disable=too-many-arguments
    def __init__(self, name="", parameters=(), children=(), ancestor=None,
                 filepath="", dirty=False, enabled=True):
        """
        Initializes the BlockNode instance and sets its instance variables.
        """
        super(DummyBlockNode, self).__init__(ancestor, filepath, dirty)
        self.name = name
        self.parameters = parameters
        self.children = children
        self.enabled = enabled

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
        dummydirective = DummyDirectiveNode("Name")
        dummycomment = DummyCommentNode("Comment", dummyblock, "/some/file")


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
