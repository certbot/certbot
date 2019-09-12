""" Augeas implementation of the ParserNode interface """
from certbot_apache import assertions
from certbot_apache import interfaces
from certbot_apache import parsernode_util as util


class AugeasParserNode(interfaces.ParserNode):
    """ Augeas implementation of ParserNode interface """

    def __init__(self, **kwargs):
        ancestor, dirty, filepath, metadata = util.parsernode_kwargs(kwargs)  # pylint: disable=unused-variable
        super(AugeasParserNode, self).__init__(**kwargs)
        self.ancestor = ancestor
        # self.filepath = filepath
        self.filepath = assertions.PASS
        self.dirty = dirty
        self.metadata = metadata

    def save(self, msg): # pragma: no cover
        pass


class AugeasCommentNode(AugeasParserNode):
    """ Augeas implementation of CommentNode interface """

    def __init__(self, **kwargs):
        comment, kwargs = util.commentnode_kwargs(kwargs)  # pylint: disable=unused-variable
        super(AugeasCommentNode, self).__init__(**kwargs)
        # self.comment = comment
        self.comment = assertions.PASS

    def __eq__(self, other): # pragma: no cover
        if isinstance(other, self.__class__):
            return (self.comment == other.comment and
                    self.filepath == other.filepath and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)
        return False


class AugeasDirectiveNode(AugeasParserNode):
    """ Augeas implementation of DirectiveNode interface """

    def __init__(self, **kwargs):
        name, parameters, enabled, kwargs = util.directivenode_kwargs(kwargs)
        super(AugeasDirectiveNode, self).__init__(**kwargs)
        self.name = name
        self.parameters = parameters
        self.enabled = enabled

    def __eq__(self, other): # pragma: no cover
        if isinstance(other, self.__class__):
            return (self.name == other.name and
                    self.filepath == other.filepath and
                    self.parameters == other.parameters and
                    self.enabled == other.enabled and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)
        return False

    def set_parameters(self, parameters):
        """Sets the parameters for DirectiveNode"""
        self.parameters = parameters


interfaces.CommentNode.register(AugeasCommentNode)
interfaces.DirectiveNode.register(AugeasDirectiveNode)
