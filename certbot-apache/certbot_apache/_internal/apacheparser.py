""" apacheconfig implementation of the ParserNode interfaces """

from functools import partial

from certbot_apache._internal import assertions
from certbot_apache._internal import interfaces
from certbot_apache._internal import parsernode_util as util


class ApacheParserNode(interfaces.ParserNode):
    """ apacheconfig implementation of ParserNode interface.

        Expects metadata `ac_ast` to be passed in, where `ac_ast` is the AST provided
        by parsing the equivalent configuration text using the apacheconfig library.
    """

    def __init__(self, **kwargs):
        ancestor, dirty, filepath, metadata = util.parsernode_kwargs(kwargs)  # pylint: disable=unused-variable
        super(ApacheParserNode, self).__init__(**kwargs)
        self.ancestor = ancestor
        self.filepath = filepath
        self.dirty = dirty
        self.metadata = metadata
        self._raw = self.metadata["ac_ast"]

    def save(self, msg): # pragma: no cover
        pass

    def find_ancestors(self, name):  # pylint: disable=unused-variable
        """Find ancestor BlockNodes with a given name"""
        return [ApacheBlockNode(name=assertions.PASS,
                                parameters=assertions.PASS,
                                ancestor=self,
                                filepath=assertions.PASS,
                                metadata=self.metadata)]


class ApacheCommentNode(ApacheParserNode):
    """ apacheconfig implementation of CommentNode interface """

    def __init__(self, **kwargs):
        comment, kwargs = util.commentnode_kwargs(kwargs)  # pylint: disable=unused-variable
        super(ApacheCommentNode, self).__init__(**kwargs)
        self.comment = comment

    def __eq__(self, other):  # pragma: no cover
        if isinstance(other, self.__class__):
            return (self.comment == other.comment and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata and
                    self.filepath == other.filepath)
        return False


class ApacheDirectiveNode(ApacheParserNode):
    """ apacheconfig implementation of DirectiveNode interface """

    def __init__(self, **kwargs):
        name, parameters, enabled, kwargs = util.directivenode_kwargs(kwargs)
        super(ApacheDirectiveNode, self).__init__(**kwargs)
        self.name = name
        self.parameters = parameters
        self.enabled = enabled
        self.include = None

    def __eq__(self, other):  # pragma: no cover
        if isinstance(other, self.__class__):
            return (self.name == other.name and
                    self.filepath == other.filepath and
                    self.parameters == other.parameters and
                    self.enabled == other.enabled and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)
        return False

    def set_parameters(self, _parameters):
        """Sets the parameters for DirectiveNode"""
        return


def _parameters_from_string(text):
    text = text.strip()
    words = []
    word = ""
    quote = None
    escape = False
    for c in text:
        if c.isspace() and not quote:
            if word:
                words.append(word)
            word = ""
        else:
            word += c
        if not escape:
            if not quote and c in "\"\'":
                quote = c
            elif c == quote:
                words.append(word[1:-1])
                word = ""
                quote = None
        escape = c == "\\"
    if word:
        words.append(word)
    return tuple(words)


class ApacheBlockNode(ApacheDirectiveNode):
    """ apacheconfig implementation of BlockNode interface """

    def __init__(self, **kwargs):
        super(ApacheBlockNode, self).__init__(**kwargs)
        self._raw_children = self._raw
        children = []
        for raw_node in self._raw_children:
            metadata = self.metadata.copy()
            metadata['ac_ast'] = raw_node
            if raw_node.typestring == "comment":
                node = ApacheCommentNode(comment=raw_node.name[2:],
                                         metadata=metadata, ancestor=self,
                                         filepath=self.filepath)
            elif raw_node.typestring == "block":
                parameters = _parameters_from_string(raw_node.arguments)
                node = ApacheBlockNode(name=raw_node.tag, parameters=parameters,
                                       metadata=metadata, ancestor=self,
                                       filepath=self.filepath, enabled=self.enabled)
            else:
                parameters = ()
                if raw_node.value:
                    parameters = _parameters_from_string(raw_node.value)
                node = ApacheDirectiveNode(name=raw_node.name, parameters=parameters,
                                           metadata=metadata, ancestor=self,
                                           filepath=self.filepath, enabled=self.enabled)
            children.append(node)
        self.children = tuple(children)

    def __eq__(self, other):  # pragma: no cover
        if isinstance(other, self.__class__):
            return (self.name == other.name and
                    self.filepath == other.filepath and
                    self.parameters == other.parameters and
                    self.children == other.children and
                    self.enabled == other.enabled and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)
        return False

    def _add_child_thing(self, raw_string, partial_node, position):
        position = len(self._raw_children) if not position else position
        # Cap position to length to mimic AugeasNode behavior. TODO: document that this happens
        position = min(len(self._raw_children), position)
        raw_ast = self._raw_children.add(position, raw_string)
        metadata = self.metadata.copy()
        metadata['ac_ast'] = raw_ast
        new_node = partial_node(ancestor=self, metadata=metadata, filepath=self.filepath)

        # Update metadata
        children = list(self.children)
        children.insert(position, new_node)
        self.children = tuple(children)
        return new_node

    def add_child_block(self, name, parameters=None, position=None):
        """Adds a new BlockNode to the sequence of children"""
        parameters_str = " " + " ".join(parameters) if parameters else ""
        if not parameters:
            parameters = []
        partial_block = partial(ApacheBlockNode, name=name, parameters=tuple(parameters), enabled=self.enabled)
        return self._add_child_thing("\n<%s%s>\n</%s>" % (name, parameters_str, name), partial_block, position)

    def add_child_directive(self, name, parameters=None, position=None):
        """Adds a new DirectiveNode to the sequence of children"""
        parameters_str = " " + " ".join(parameters) if parameters else ""
        if not parameters:
            parameters = []
        partial_block = partial(ApacheDirectiveNode, name=name, parameters=tuple(parameters), enabled=self.enabled)
        return self._add_child_thing("\n%s%s" % (name, parameters_str), partial_block, position)

    def add_child_comment(self, comment="", position=None):
        """Adds a new CommentNode to the sequence of children"""
        partial_comment = partial(ApacheCommentNode, comment=comment)
        return self._add_child_thing(comment, partial_comment, position)

    def find_blocks(self, name, exclude=True): # pylint: disable=unused-argument
        """Recursive search of BlockNodes from the sequence of children"""
        return [ApacheBlockNode(name=assertions.PASS,
                                parameters=assertions.PASS,
                                ancestor=self,
                                filepath=assertions.PASS,
                                metadata=self.metadata)]

    def find_directives(self, name, exclude=True): # pylint: disable=unused-argument
        """Recursive search of DirectiveNodes from the sequence of children"""
        return [ApacheDirectiveNode(name=assertions.PASS,
                                    parameters=assertions.PASS,
                                    ancestor=self,
                                    filepath=assertions.PASS,
                                    metadata=self.metadata)]

    def find_comments(self, comment, exact=False): # pylint: disable=unused-argument
        """Recursive search of DirectiveNodes from the sequence of children"""
        return [ApacheCommentNode(comment=assertions.PASS,
                                  ancestor=self,
                                  filepath=assertions.PASS,
                                  metadata=self.metadata)]

    def delete_child(self, child):  # pragma: no cover
        """Deletes a ParserNode from the sequence of children"""
        return

    def unsaved_files(self):  # pragma: no cover
        """Returns a list of unsaved filepaths"""
        return [assertions.PASS]

    def parsed_paths(self):  # pragma: no cover
        """Returns a list of parsed configuration file paths"""
        return [assertions.PASS]


interfaces.CommentNode.register(ApacheCommentNode)
interfaces.DirectiveNode.register(ApacheDirectiveNode)
interfaces.BlockNode.register(ApacheBlockNode)
