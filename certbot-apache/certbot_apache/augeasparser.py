""" Tests for ParserNode interface """
from certbot_apache import interfaces


class AugeasCommentNode(interfaces.CommentNode):
    """ Augeas implementation of CommentNode interface """
    ancestor = None
    comment = ""
    dirty = False

    def __init__(self, comment, ancestor=None):
        self.comment = comment
        self.ancestor = ancestor

    def save(self, msg):  # pragma: no cover
        pass


class AugeasDirectiveNode(interfaces.DirectiveNode):
    """ Augeas implementation of DirectiveNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    dirty = False
    enabled = True
    name = ""

    def __init__(self, name, parameters=tuple(), ancestor=None):
        self.name = name
        self.parameters = parameters
        self.ancestor = ancestor

    def save(self, msg):  # pragma: no cover
        pass

    def set_parameters(self, parameters):  # pragma: no cover
        self.parameters = tuple("CERTBOT_PASS_ASSERT")


class AugeasBlockNode(interfaces.BlockNode):
    """ Augeas implementation of BlockNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    children = tuple()  # type: Tuple[interfaces.ParserNode, ...]
    dirty = False
    enabled = True
    name = ""

    def __init__(self, name, parameters=tuple(), ancestor=None):
        self.name = name
        self.parameters = parameters
        self.ancestor = ancestor

    def save(self, msg):  # pragma: no cover
        pass

    def add_child_block(self, name, parameters=None, position=None):  # pragma: no cover
        new_block = AugeasBlockNode("CERTBOT_PASS_ASSERT", ancestor=self)
        self.children += (new_block,)
        return new_block

    def add_child_directive(self, name, parameters=None, position=None):  # pragma: no cover
        new_dir = AugeasDirectiveNode("CERTBOT_PASS_ASSERT", ancestor=self)
        self.children += (new_dir,)
        return new_dir

    def add_child_comment(self, comment="", position=None):  # pragma: no cover
        new_comment = AugeasCommentNode("CERTBOT_PASS_ASSERT", ancestor=self)
        self.children += (new_comment,)
        return new_comment

    def find_blocks(self, name, exclude=True):  # pragma: no cover
        return [AugeasBlockNode("CERTBOT_PASS_ASSERT", ancestor=self)]

    def find_directives(self, name, exclude=True):  # pragma: no cover
        return [AugeasDirectiveNode("CERTBOT_PASS_ASSERT", ancestor=self)]

    def find_comments(self, comment, exact=False):  # pragma: no cover
        return [AugeasCommentNode("CERTBOT_PASS_ASSERT", ancestor=self)]

    def delete_child(self, child):  # pragma: no cover
        pass

    def set_parameters(self, parameters):  # pragma: no cover
        self.parameters = tuple("CERTBOT_PASS_ASSERT")

    def unsaved_files(self):  # pragma: no cover
        return ["CERTBOT_PASS_ASSERT"]
