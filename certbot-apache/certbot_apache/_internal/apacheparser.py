""" apacheconfig implementation of the ParserNode interfaces """

import glob

from acme.magic_typing import Optional  # pylint: disable=unused-import, no-name-in-module

from certbot.compat import os

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


def _load_included_file(filename, metadata):
    with open(filename) as f:
        ast = metadata['loader'].loads(f.read())
    metadata = metadata.copy()
    metadata['ac_ast'] = ast
    return ApacheBlockNode(name=assertions.PASS,
                           ancestor=None,
                           filepath=filename,
                           metadata=metadata)


class ApacheDirectiveNode(ApacheParserNode):
    """ apacheconfig implementation of DirectiveNode interface """

    def __init__(self, **kwargs):
        name, parameters, enabled, kwargs = util.directivenode_kwargs(kwargs)
        super(ApacheDirectiveNode, self).__init__(**kwargs)
        self.name = name
        self.parameters = parameters
        self.enabled = enabled
        self.include = None

        # LoadModule processing
        if self.name and self.name.lower() in ["loadmodule"]:
            mod_name, mod_filename = self.parameters
            self.metadata["apache_vars"]["modules"].add(mod_name)
            self.metadata["apache_vars"]["modules"].add(
                os.path.basename(mod_filename)[:-2] + "c")

        # Include processing
        if self.name and self.name.lower() in ["include", "includeoptional"]:
            value = self.parameters[0]
            path = os.path.join(self.metadata['serverroot'], value)
            filepaths = glob.glob(path)
            for filepath in filepaths:
                if filepath not in self.metadata['parsed_files']:
                    node = _load_included_file(filepath, self.metadata)
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

    def set_parameters(self, _parameters):
        """Sets the parameters for DirectiveNode"""
        self.parameters = tuple(_parameters)
        self._raw.value = tuple(" ".join(_parameters))


def _recursive_generator(node, exclude=True, files_visited=None):
    """Recursive generator over all children of given block node, expanding includes.

    :param ApacheBlockNode node: node whose children will be yielded by this generator
    :param bool exclude: If True, excludes nodes disabled by conditional blocks like
        IfDefine and IfModule.
    :param dict files_visited: bookkeeping dict for recursion to ensure we don't visit
        the same file twice (to avoid double-counting nodes)
    """
    if not files_visited:
        files_visited = set([node.filepath])
    for child in node.children:
        yield child
        if isinstance(child, ApacheBlockNode):
            if not exclude or child.enabled:
                for subchild in _recursive_generator(child, exclude, files_visited):
                    yield subchild
        if isinstance(child, ApacheDirectiveNode) and child.include:
            for filename in child.include:
                if filename not in files_visited:
                    files_visited.add(filename)
                    file_ast = node.metadata['parsed_files'][filename]
                    for subchild in _recursive_generator(file_ast, exclude, files_visited):
                        yield subchild


def _is_enabled(block_node, apache_vars):
    """Returns False if this block disables its children given loaded Apache data.

    Checks to see whether this block_node is a conditional IfDefine or IfModule,
    and returns what its argument evaluates to.

    :param ApacheBlockNode block_node: block node to check.
    :param dict apache_vars: dict that includes set of loaded modules and variables, under keys
        "modules" and "defines", respectively.
    """
    filters = {
        "ifdefine": apache_vars["defines"],
        "ifmodule": apache_vars["modules"]
    }
    if not block_node.name or block_node.name.lower() not in filters:
        return True
    loaded_set = filters[block_node.name.lower()]
    name = block_node.parameters[0]
    expect_loaded = not name.startswith("!")
    name = name.lstrip("!")
    loaded = (name in loaded_set)
    return expect_loaded == loaded


class ApacheBlockNode(ApacheDirectiveNode):
    """ apacheconfig implementation of BlockNode interface """

    def __init__(self, **kwargs):
        super(ApacheBlockNode, self).__init__(**kwargs)
        self._raw_children = self._raw
        children = []

        self.enabled = self.enabled and _is_enabled(self, self.metadata["apache_vars"])
        for raw_node in self._raw_children:
            node = None  # type: Optional[ApacheParserNode]
            metadata = self.metadata.copy()
            metadata['ac_ast'] = raw_node
            if raw_node.typestring == "comment":
                node = ApacheCommentNode(comment=raw_node.name[2:],
                                         metadata=metadata, ancestor=self,
                                         filepath=self.filepath)
            elif raw_node.typestring == "block":
                parameters = util.parameters_from_string(raw_node.arguments)
                node = ApacheBlockNode(name=raw_node.tag, parameters=parameters,
                                       metadata=metadata, ancestor=self,
                                       filepath=self.filepath, enabled=self.enabled)
            else:
                parameters = ()
                if raw_node.value:
                    parameters = util.parameters_from_string(raw_node.value)
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

    def add_child_block(self, name, parameters=None, position=None):  # pylint: disable=unused-argument
        """Adds a new BlockNode to the sequence of children"""
        new_block = ApacheBlockNode(name=assertions.PASS,
                                    parameters=assertions.PASS,
                                    ancestor=self,
                                    filepath=assertions.PASS,
                                    metadata=self.metadata)
        self.children += (new_block,)
        return new_block

    def add_child_directive(self, name, parameters=None, position=None):  # pylint: disable=unused-argument
        """Adds a new DirectiveNode to the sequence of children"""
        new_dir = ApacheDirectiveNode(name=assertions.PASS,
                                      parameters=assertions.PASS,
                                      ancestor=self,
                                      filepath=assertions.PASS,
                                      metadata=self.metadata)
        self.children += (new_dir,)
        return new_dir

    # pylint: disable=unused-argument
    def add_child_comment(self, comment="", position=None):  # pragma: no cover

        """Adds a new CommentNode to the sequence of children"""
        new_comment = ApacheCommentNode(comment=assertions.PASS,
                                        ancestor=self,
                                        filepath=assertions.PASS,
                                        metadata=self.metadata)
        self.children += (new_comment,)
        return new_comment

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

    def find_comments(self, comment): # pylint: disable=unused-argument
        """Recursive search of DirectiveNodes from the sequence of children"""
        comments = []
        for child in _recursive_generator(self):
            if isinstance(child, ApacheCommentNode) and comment in child.comment:
                comments.append(child)
        return comments

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
