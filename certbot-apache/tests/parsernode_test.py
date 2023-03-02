""" Tests for ParserNode interface """

import sys

import pytest

from certbot_apache._internal import interfaces
from certbot_apache._internal import parsernode_util as util


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
        super().__init__(**kwargs)

    def save(self, msg):  # pragma: no cover
        """Save"""
        pass

    def find_ancestors(self, name):  # pragma: no cover
        """ Find ancestors """
        return []


class DummyCommentNode(DummyParserNode):
    """ A dummy class implementing CommentNode interface """

    def __init__(self, **kwargs):
        """
        Initializes the CommentNode instance and sets its instance variables.
        """
        comment, kwargs = util.commentnode_kwargs(kwargs)
        self.comment = comment
        super().__init__(**kwargs)


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

        super().__init__(**kwargs)

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

def test_dummy():
    """Dummy placeholder test case for ParserNode interfaces"""
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


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
