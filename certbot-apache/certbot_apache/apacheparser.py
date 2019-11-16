""" apacheconfig implementation of the ParserNode interfaces """

import glob

from certbot import errors
from certbot.compat import os

from certbot_apache import assertions
from certbot_apache import interfaces
from certbot_apache import parsernode_util as util


def _load_file(filename, metadata):
    with open(filename) as f:
        ast = metadata['loader'].loads(f.read())
    metadata = metadata.copy()
    metadata['ac_ast'] = ast
    return ApacheBlockNode(name=assertions.PASS,
                           ancestor=None,
                           filepath=filename,
                           metadata=metadata)


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

        # Loadmodule processing
        if self.name and self.name.lower() in ["loadmodule"]:
            if "modules_loaded" not in self.metadata:
                self.metadata["modules_loaded"] = [set(), set()]
            self.metadata["modules_loaded"][0].add(self.parameters[0])
            self.metadata["modules_loaded"][1].add(self.parameters[1])

        # Include processing
        if self.name and self.name.lower() in ["include", "includeoptional"]:
            value = self.parameters[0]
            path = os.path.join(os.path.dirname(self.metadata['serverroot']), value)
            if os.path.isdir(path):
                path += "/*"
            filepaths = glob.glob(path)
            for filepath in filepaths:
                if filepath not in self.metadata['parsed_files']:
                    node = _load_file(filepath, self.metadata)
                    self.metadata['parsed_files'][filepath] = node
            self.include = set(filepaths)

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

    def set_parameters(self, parameters):
        """Sets the parameters for DirectiveNode"""
        self.parameters = tuple(parameters)
        self._raw.value = tuple(" ".join(parameters))


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


def _recursive_generator(node, exclude=True, files_visited=None):
    # iterator through children, and recursively expands through blocks and includes
    if not files_visited:
        files_visited = set([node.filepath])
    for child in node.children:
        if exclude and not isinstance(child, ApacheCommentNode) and not child.enabled:
            continue
        yield child
        if isinstance(child, ApacheBlockNode):
            for subchild in _recursive_generator(child, exclude, files_visited):
                yield subchild
        if isinstance(child, ApacheDirectiveNode) and child.include:
            for filename in child.include:
                if filename not in files_visited:
                    files_visited.add(filename)
                    file_ast = node.metadata['parsed_files'][filename]
                    for subchild in _recursive_generator(file_ast, exclude, files_visited):
                        yield subchild


class ApacheBlockNode(ApacheDirectiveNode):
    """ apacheconfig implementation of BlockNode interface """

    def __init__(self, **kwargs):
        super(ApacheBlockNode, self).__init__(**kwargs)
        self._raw_children = self._raw
        children = []
        if self.name and self.name.lower() == "ifmodule":
            module_name = self.parameters[0]
            expect_loaded = not module_name.startswith("!")
            module_name = module_name.strip("!")
            loaded = False
            if "modules_loaded" in self.metadata:
                loaded = (module_name in self.metadata["modules_loaded"][0] or
                          module_name in self.metadata["modules_loaded"][1])
            self.enabled = self.enabled and expect_loaded == loaded

        for raw_node in self._raw_children:
            metadata = self.metadata.copy()
            metadata['ac_ast'] = raw_node
            if raw_node.typestring == "comment":
                # TODO: Why does the other implementation cut off both the "#" and initial spaces?
                node = ApacheCommentNode(comment=raw_node.name[2:], metadata=metadata,
                                         ancestor=self, filepath=self.filepath)
            elif raw_node.typestring == "block":
                parameters = _parameters_from_string(raw_node.arguments)
                node = ApacheBlockNode(name=raw_node.tag, parameters=parameters,
                                       metadata=metadata, ancestor=self,
                                       filepath=self.filepath, enabled = self.enabled)
            else:
                parameters = ()
                if raw_node.value:
                    parameters = _parameters_from_string(raw_node.value)
                node = ApacheDirectiveNode(name=raw_node.name,
                                           parameters=parameters, metadata=metadata,
                                           ancestor=self, filepath=self.filepath, enabled=self.enabled)
            children.append(node)
        self.children = tuple(children)

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
        return False

    def add_child_block(self, name, parameters=None, position=None):  # pylint: disable=unused-argument
        """Adds a new BlockNode to the sequence of children"""
        parameters_string = " " + " ".join(parameters) if parameters else ""
        position = len(self._raw_children) if not position else position
        position = min(len(self._raw_children), position)
        raw_block = self._raw_children.add(position, "\n<%s%s>\n</%s>" %
                                                     (name, parameters_string, name))
        metadata = self.metadata.copy()
        metadata['ac_ast'] = raw_block
        if not parameters:
            parameters = []
        new_block = ApacheBlockNode(name=name, parameters=tuple(parameters),
                                    ancestor=self, metadata=metadata, filepath=self.filepath)

        # Update metadata
        children = list(self.children)
        children.insert(position, new_block)
        self.children = tuple(children)
        return new_block

    def add_child_directive(self, name, parameters=None, position=None):  # pylint: disable=unused-argument
        """Adds a new DirectiveNode to the sequence of children"""
        parameters_string = " " + " ".join(parameters) if parameters else ""
        position = len(self._raw_children) if not position else position
        raw_item = self._raw_children.add(position, "\n%s%s" % (name, parameters_string))
        metadata = self.metadata.copy()
        metadata['ac_ast'] = raw_item
        if not parameters:
            parameters = []
        new_dir = ApacheDirectiveNode(name=name, parameters=tuple(parameters), ancestor=self,
                                      metadata=metadata, filepath=self.filepath)
        # Update metadata
        children = list(self.children)
        children.insert(position, new_dir)
        self.children = tuple(children)
        return new_dir

    # pylint: disable=unused-argument
    def add_child_comment(self, comment="", position=None):  # pragma: no cover
        """Adds a new CommentNode to the sequence of children"""
        position = len(self._raw_children) if not position else position
        raw_comment = self._raw_children.add(position, comment)
        metadata = self.metadata.copy()
        metadata['ac_ast'] = raw_comment
        new_comment = ApacheCommentNode(comment=comment, metadata=metadata,
                                        ancestor=self,
                                        filepath=self.filepath)
        # Update metadata
        children = list(self.children)
        children.insert(position, new_comment)
        self.children = tuple(children)
        return new_comment

    # TODO: Implement exclude
    def find_blocks(self, name, exclude=True): # pylint: disable=unused-argument
        """Recursive search of BlockNodes from the sequence of children"""
        blocks = []
        for child in _recursive_generator(self, exclude=exclude):
            if isinstance(child, ApacheBlockNode) and child.name.lower() == name.lower():
                blocks.append(child)
        return blocks

    def find_directives(self, name, exclude=True): # pylint: disable=unused-argument
        """Recursive search of DirectiveNodes from the sequence of children"""
        directives = []
        for child in _recursive_generator(self, exclude=exclude):
            if isinstance(child, ApacheDirectiveNode) and child.name.lower() == name.lower():
                directives.append(child)
        return directives

    def find_comments(self, comment, exact=False): # pylint: disable=unused-argument
        """Recursive search of DirectiveNodes from the sequence of children"""
        comments = []
        for child in _recursive_generator(self):
            # TODO: Is this the correct metric for matching comments?
            if isinstance(child, ApacheCommentNode) and comment in child.comment:
                comments.append(child)
        return comments

    def delete_child(self, child):  # pragma: no cover
        """Deletes a ParserNode from the sequence of children"""
        index = -1
        i = None
        for i, elem in enumerate(self.children):
            if elem == child:
                index = i
                break
        if index < 0:
            raise errors.PluginError("Could not find child node to delete")
        children_list = list(self.children)
        thing = children_list.pop(i)
        self.children = tuple(children_list)
        self._raw_children.remove(i)
        return thing

    def unsaved_files(self):  # pragma: no cover
        """Returns a list of unsaved filepaths"""
        return [assertions.PASS]


interfaces.CommentNode.register(ApacheCommentNode)
interfaces.DirectiveNode.register(ApacheDirectiveNode)
interfaces.BlockNode.register(ApacheBlockNode)
