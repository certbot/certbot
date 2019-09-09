""" Augeas implementation of the ParserNode interface """
from certbot_apache import assertions
from certbot_apache import interfaces
from certbot_apache import parsernode_util as util


class AugeasParserNode(interfaces.ParserNode):
    """ Augeas implementation of ParserNode interface """

    def __init__(self, **kwargs):
        ancestor, dirty, filepath, metadata = util.parsernode_kwargs(kwargs)
        self.ancestor = ancestor
        # self.filepath = filepath
        self.filepath = assertions.PASS
        self.dirty = dirty
        self.metadata = metadata

    def save(self, msg):  # pragma: no cover
        pass


class AugeasCommentNode(AugeasParserNode):
    """ Augeas implementation of CommentNode interface """

    def __init__(self, **kwargs):
        comment, kwargs = util.commentnode_kwargs(kwargs)
        super(AugeasCommentNode, self).__init__(**kwargs)
        self.comment = comment

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.comment == other.comment and
                    self.filepath == other.filepath and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)


class AugeasDirectiveNode(AugeasParserNode):
    """ Augeas implementation of DirectiveNode interface """

    def __init__(self, **kwargs):
        name, parameters, enabled, kwargs = util.directivenode_kwargs(kwargs)
        super(AugeasDirectiveNode, self).__init__(**kwargs)
        self.name = name
        self.parameters = parameters
        self.enabled = enabled

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.name == other.name and
                    self.filepath == other.filepath and
                    self.parameters == other.parameters and
                    self.enabled == other.enabled and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)

    def set_parameters(self, parameters):
        self.parameters = parameters


class AugeasBlockNode(AugeasDirectiveNode):
    """ Augeas implementation of BlockNode interface """

    def __init__(self, **kwargs):
        super(AugeasBlockNode, self).__init__(**kwargs)
        self.children = ()

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return (self.name == other.name and
                    self.filepath == other.filepath and
                    self.parameters == other.parameters and
                    self.children == other.children and
                    self.enabled == other.enabled and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)


    def add_child_block(self, name, parameters=None, position=None):
        new_block = AugeasBlockNode(name=assertions.PASS,
                                    ancestor=self,
                                    filepath=assertions.PASS)
        self.children += (new_block,)
        return new_block

    def add_child_directive(self, name, parameters=None, position=None):
        new_dir = AugeasDirectiveNode(name=assertions.PASS,
                                      ancestor=self,
                                      filepath=assertions.PASS)
        self.children += (new_dir,)
        return new_dir

    def add_child_comment(self, comment="", position=None):
        new_comment = AugeasCommentNode(comment=assertions.PASS,
                                        ancestor=self,
                                        filepath=assertions.PASS)
        self.children += (new_comment,)
        return new_comment

    def find_blocks(self, name, exclude=True):
        return [AugeasBlockNode(name=assertions.PASS,
                                ancestor=self,
                                filepath=assertions.PASS)]

    def find_directives(self, name, exclude=True):
        return [AugeasDirectiveNode(name=assertions.PASS,
                                    ancestor=self,
                                    filepath=assertions.PASS)]

    def find_comments(self, comment, exact=False):
        return [AugeasCommentNode(comment=assertions.PASS,
                                  ancestor=self,
                                  filepath=assertions.PASS)]

    def delete_child(self, child):  # pragma: no cover
        pass

    def unsaved_files(self):  # pragma: no cover
        return [assertions.PASS]


interfaces.CommentNode.register(AugeasCommentNode)
interfaces.DirectiveNode.register(AugeasDirectiveNode)
interfaces.BlockNode.register(AugeasBlockNode)
