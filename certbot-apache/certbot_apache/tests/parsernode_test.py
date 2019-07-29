""" Tests for ParserNode interface """

import unittest

from certbot_apache import interfaces


class DummyCommentNode(interfaces.CommentNode):
    ancestor = None
    comment = ""
    dirty = False

    def save(self, msg):
        pass


class DummyDirectiveNode(interfaces.DirectiveNode):
    ancestor = None
    parameters = []
    dirty = False
    enabled = True
    name = ""

    def save(self, msg):
        pass


class DummyBlockNode(interfaces.BlockNode):
    ancestor = None
    parameters = []
    children = []
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

    def find_comments(self, name, exact=False):
        pass

    def delete_child(self, child):
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
