""" Tests for ParserNode interface """

import unittest

from acme.magic_typing import Optional, Tuple  # pylint: disable=unused-import, no-name-in-module

from certbot_apache import interfaces



class DummyCommentNode(interfaces.CommentNode):
    """ A dummy class implementing CommentNode interface """
    ancestor = None
    comment = ""
    dirty = False

    def save(self, msg):  # pragma: no cover
        pass


class DummyDirectiveNode(interfaces.DirectiveNode):
    """ A dummy class implementing DirectiveNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    dirty = False
    enabled = True
    name = ""

    def save(self, msg):  # pragma: no cover
        pass

    def set_parameters(self, parameters):  # pragma: no cover
        pass


class DummyBlockNode(interfaces.BlockNode):
    """ A dummy class implementing BlockNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    children = tuple()  # type: Tuple[interfaces.ParserNode, ...]
    dirty = False
    enabled = True
    name = ""

    def save(self, msg):  # pragma: no cover
        pass

    def add_child_block(self, name, parameters=None, position=None):  # pragma: no cover
        pass

    def add_child_directive(self, name, parameters=None, position=None):  # pragma: no cover
        pass

    def add_child_comment(self, comment="", position=None):  # pragma: no cover
        pass

    def find_blocks(self, name, exclude=True):  # pragma: no cover
        pass

    def find_directives(self, name, exclude=True):  # pragma: no cover
        pass

    def find_comments(self, comment, exact=False):  # pragma: no cover
        pass

    def delete_child(self, child):  # pragma: no cover
        pass

    def set_parameters(self, parameters):  # pragma: no cover
        pass

    def unsaved_files(self):  # pragma: no cover
        pass


class ParserNodeTest(unittest.TestCase):
    """Dummy placeholder test case for ParserNode interfaces"""

    def test_dummy(self):
        dummyblock = DummyBlockNode()
        dummydirective = DummyDirectiveNode()
        dummycomment = DummyCommentNode()


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
