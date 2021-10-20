""" apacheconfig implementation of the ParserNode interfaces """
from typing import Any
from typing import List
from typing import Optional
from typing import Tuple

from certbot_apache._internal import assertions
from certbot_apache._internal import interfaces
from certbot_apache._internal import parsernode_util as util


class ApacheParserNode(interfaces.ParserNode):
    """ apacheconfig implementation of ParserNode interface.

        Expects metadata `ac_ast` to be passed in, where `ac_ast` is the AST provided
        by parsing the equivalent configuration text using the apacheconfig library.
    """

    def __init__(self, **kwargs: Any):
        # pylint: disable=unused-variable
        ancestor, dirty, filepath, metadata = util.parsernode_kwargs(kwargs)
        super().__init__(**kwargs)
        self.ancestor: str = ancestor
        self.filepath: str = filepath
        self.dirty: bool = dirty
        self.metadata: Any = metadata
        self._raw: Any = self.metadata["ac_ast"]

    def save(self, msg: str) -> None:  # pragma: no cover
        pass

    # pylint: disable=unused-variable
    def find_ancestors(self, name: str) -> List["ApacheBlockNode"]:
        """Find ancestor BlockNodes with a given name"""
        return [ApacheBlockNode(name=assertions.PASS,
                                parameters=assertions.PASS,
                                ancestor=self,
                                filepath=assertions.PASS,
                                metadata=self.metadata)]


class ApacheCommentNode(ApacheParserNode):
    """ apacheconfig implementation of CommentNode interface """

    def __init__(self, **kwargs: Any):
        comment, kwargs = util.commentnode_kwargs(kwargs)  # pylint: disable=unused-variable
        super().__init__(**kwargs)
        self.comment = comment

    def __eq__(self, other: Any):  # pragma: no cover
        if isinstance(other, self.__class__):
            return (self.comment == other.comment and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata and
                    self.filepath == other.filepath)
        return False


class ApacheDirectiveNode(ApacheParserNode):
    """ apacheconfig implementation of DirectiveNode interface """

    def __init__(self, **kwargs: Any):
        name, parameters, enabled, kwargs = util.directivenode_kwargs(kwargs)
        super().__init__(**kwargs)
        self.name: str = name
        self.parameters: List[str] = parameters
        self.enabled: bool = enabled
        self.include: Optional[str] = None

    def __eq__(self, other: Any) -> bool:  # pragma: no cover
        if isinstance(other, self.__class__):
            return (self.name == other.name and
                    self.filepath == other.filepath and
                    self.parameters == other.parameters and
                    self.enabled == other.enabled and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)
        return False

    def set_parameters(self, _parameters):  # pragma: no cover
        """Sets the parameters for DirectiveNode"""
        return


class ApacheBlockNode(ApacheDirectiveNode):
    """ apacheconfig implementation of BlockNode interface """

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self.children: Tuple[ApacheParserNode, ...] = ()

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

    # pylint: disable=unused-argument
    def add_child_block(
        self, name: str, parameters: Optional[str] = None, position: Optional[int] = None
    ) -> "ApacheBlockNode":  # pragma: no cover
        """Adds a new BlockNode to the sequence of children"""
        new_block = ApacheBlockNode(name=assertions.PASS,
                                    parameters=assertions.PASS,
                                    ancestor=self,
                                    filepath=assertions.PASS,
                                    metadata=self.metadata)
        self.children += (new_block,)
        return new_block

    # pylint: disable=unused-argument
    def add_child_directive(
        self, name: str, parameters: Optional[str] = None, position: Optional[int] = None
    ) -> ApacheDirectiveNode:  # pragma: no cover
        """Adds a new DirectiveNode to the sequence of children"""
        new_dir = ApacheDirectiveNode(name=assertions.PASS,
                                      parameters=assertions.PASS,
                                      ancestor=self,
                                      filepath=assertions.PASS,
                                      metadata=self.metadata)
        self.children += (new_dir,)
        return new_dir

    # pylint: disable=unused-argument
    def add_child_comment(
        self, name: str, parameters: Optional[int] = None, position: Optional[int] = None
    ) -> ApacheCommentNode:  # pragma: no cover

        """Adds a new CommentNode to the sequence of children"""
        new_comment = ApacheCommentNode(comment=assertions.PASS,
                                        ancestor=self,
                                        filepath=assertions.PASS,
                                        metadata=self.metadata)
        self.children += (new_comment,)
        return new_comment

    # pylint: disable=unused-argument
    def find_blocks(self, name, exclude: bool = True) -> List["ApacheBlockNode"]:
        """Recursive search of BlockNodes from the sequence of children"""
        return [ApacheBlockNode(name=assertions.PASS,
                                parameters=assertions.PASS,
                                ancestor=self,
                                filepath=assertions.PASS,
                                metadata=self.metadata)]

    # pylint: disable=unused-argument
    def find_directives(self, name: str, exclude: bool = True) -> List[ApacheDirectiveNode]:
        """Recursive search of DirectiveNodes from the sequence of children"""
        return [ApacheDirectiveNode(name=assertions.PASS,
                                    parameters=assertions.PASS,
                                    ancestor=self,
                                    filepath=assertions.PASS,
                                    metadata=self.metadata)]

    # pylint: disable=unused-argument
    def find_comments(self, comment: str, exact: bool = False) -> List[ApacheCommentNode]:
        # praqma: no cover
        """Recursive search of DirectiveNodes from the sequence of children"""
        return [ApacheCommentNode(comment=assertions.PASS,
                                  ancestor=self,
                                  filepath=assertions.PASS,
                                  metadata=self.metadata)]

    def delete_child(self, child: "ApacheBlockNode") -> None:  # pragma: no cover
        """Deletes a ParserNode from the sequence of children"""
        return

    def unsaved_files(self) -> List[str]:  # pragma: no cover
        """Returns a list of unsaved filepaths"""
        return [assertions.PASS]

    def parsed_paths(self) -> List[str]:  # pragma: no cover
        """Returns a list of parsed configuration file paths"""
        return [assertions.PASS]


interfaces.CommentNode.register(ApacheCommentNode)
interfaces.DirectiveNode.register(ApacheDirectiveNode)
interfaces.BlockNode.register(ApacheBlockNode)
