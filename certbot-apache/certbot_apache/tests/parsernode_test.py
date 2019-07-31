""" Tests for ParserNode interface """

import unittest

from acme.magic_typing import Optional, Tuple  # pylint: disable=unused-import, no-name-in-module

from certbot_apache import interfaces



class DummyCommentNode(interfaces.CommentNode):
    """ A dummy class implementing CommentNode interface """
    ancestor = None
    comment = ""
    dirty = False

    def save(self, msg):
        pass


class DummyDirectiveNode(interfaces.DirectiveNode):
    """ A dummy class implementing DirectiveNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    dirty = False
    enabled = True
    name = ""

    def save(self, msg):
        pass

    def set_parameters(self, parameters):
        pass


class DummyBlockNode(interfaces.BlockNode):
    """ A dummy class implementing BlockNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    children = tuple()  # type: Tuple[str, ...]
    dirty = False
    enabled = True
    name = ""

    def save(self, msg):
        pass

    def add_child_block(self, name, arguments=None, position=None):
        pass

    def add_child_directive(self, name, arguments=None, position=None):
        pass

    def add_child_comment(self, comment="", position=None):
        pass

    def find_blocks(self, name, exclude=True):
        pass

    def find_directives(self, name, exclude=True):
        pass

    def find_comments(self, comment, exact=False):
        pass

    def delete_child(self, child):
        pass

    def set_parameters(self, parameters):
        pass

    def unsaved_files(self):
        pass


class ParserNodeTest(unittest.TestCase):
    """Dummy placeholder test case for ParserNode interfaces"""

    def test_dummy(self):
        dummyblock = DummyBlockNode()
        dummydirective = DummyDirectiveNode()
        dummycomment = DummyCommentNode()






if __name__ == "__main__":
    unittest.main()  # pragma: no cover
