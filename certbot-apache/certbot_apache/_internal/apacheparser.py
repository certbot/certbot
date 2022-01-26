""" apacheconfig implementation of the ParserNode interfaces """
from typing import Any
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple

from certbot_apache._internal import assertions
from certbot_apache._internal import interfaces
from certbot_apache._internal import parsernode_util as util
from certbot_apache._internal.interfaces import ParserNode


class ApacheParserNode(interfaces.ParserNode):
    """ apacheconfig implementation of ParserNode interface.

        Expects metadata `ac_ast` to be passed in, where `ac_ast` is the AST provided
        by parsing the equivalent configuration text using the apacheconfig library.
    """

    def __init__(self, **kwargs: Any) -> None:
        # pylint: disable=unused-variable
        ancestor, dirty, filepath, metadata = util.parsernode_kwargs(kwargs)
        super().__init__(**kwargs)
        self.ancestor = ancestor
        self.filepath = filepath
        self.dirty = dirty
        self.metadata = metadata
        self._raw: Any = self.metadata["ac_ast"]

    def save(self, msg: str) -> None:
        pass  # pragma: no cover

    def find_ancestors(self, name: str) -> List["ApacheParserNode"]:  # pylint: disable=unused-variable
        """Find ancestor BlockNodes with a given name"""
        return [ApacheBlockNode(name=assertions.PASS,
                                parameters=assertions.PASS,
                                ancestor=self,
                                filepath=assertions.PASS,
                                metadata=self.metadata)]


class ApacheCommentNode(ApacheParserNode):
    """ apacheconfig implementation of CommentNode interface """

    def __init__(self, **kwargs: Any) -> None:
        comment, kwargs = util.commentnode_kwargs(kwargs)  # pylint: disable=unused-variable
        super().__init__(**kwargs)
        self.comment = comment

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return (self.comment == other.comment and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata and
                    self.filepath == other.filepath)
        return False  # pragma: no cover


class ApacheDirectiveNode(ApacheParserNode):
    """ apacheconfig implementation of DirectiveNode interface """

    def __init__(self, **kwargs: Any) -> None:
        name, parameters, enabled, kwargs = util.directivenode_kwargs(kwargs)
        super().__init__(**kwargs)
        self.name: str = name
        self.parameters: str = parameters
        self.enabled: bool = enabled
        self.include: Optional[str] = None

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return (self.name == other.name and
                    self.filepath == other.filepath and
                    self.parameters == other.parameters and
                    self.enabled == other.enabled and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)
        return False  # pragma: no cover

    def set_parameters(self, _parameters: Iterable[str]) -> None:
        """Sets the parameters for DirectiveNode"""
        return  # pragma: no cover


class ApacheBlockNode(ApacheDirectiveNode):
    """ apacheconfig implementation of BlockNode interface """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.children: Tuple[ApacheParserNode, ...] = ()

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return (self.name == other.name and
                    self.filepath == other.filepath and
                    self.parameters == other.parameters and
                    self.children == other.children and
                    self.enabled == other.enabled and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)
        return False  # pragma: no cover

    # pylint: disable=unused-argument
    def add_child_block(self, name: str, parameters: Optional[str] = None,
                        position: Optional[int] = None) -> "ApacheBlockNode":  # pragma: no cover
        """Adds a new BlockNode to the sequence of children"""
        new_block = ApacheBlockNode(name=assertions.PASS,
                                    parameters=assertions.PASS,
                                    ancestor=self,
                                    filepath=assertions.PASS,
                                    metadata=self.metadata)
        self.children += (new_block,)
        return new_block

    # pylint: disable=unused-argument
    def add_child_directive(self, name: str, parameters: Optional[str] = None,
                            position: int = None) -> ApacheDirectiveNode:  # pragma: no cover
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

    def find_blocks(self, name: str, exclude: bool = True) -> List["ApacheBlockNode"]:  # pylint: disable=unused-argument
        """Recursive search of BlockNodes from the sequence of children"""
        return [ApacheBlockNode(name=assertions.PASS,
                                parameters=assertions.PASS,
                                ancestor=self,
                                filepath=assertions.PASS,
                                metadata=self.metadata)]

    def find_directives(self, name: str, exclude: bool = True) -> List[ApacheDirectiveNode]:  # pylint: disable=unused-argument
        """Recursive search of DirectiveNodes from the sequence of children"""
        return [ApacheDirectiveNode(name=assertions.PASS,
                                    parameters=assertions.PASS,
                                    ancestor=self,
                                    filepath=assertions.PASS,
                                    metadata=self.metadata)]

    # pylint: disable=unused-argument
    def find_comments(self, comment: str, exact: bool = False) -> List[ApacheCommentNode]:
        """Recursive search of DirectiveNodes from the sequence of children"""
        return [ApacheCommentNode(comment=assertions.PASS,  # pragma: no cover
                                  ancestor=self,
                                  filepath=assertions.PASS,
                                  metadata=self.metadata)]

    def delete_child(self, child: ParserNode) -> None:
        """Deletes a ParserNode from the sequence of children"""
        return  # pragma: no cover

    def unsaved_files(self) -> List[str]:
        """Returns a list of unsaved filepaths"""
        return [assertions.PASS]  # pragma: no cover

    def parsed_paths(self) -> List[str]:
        """Returns a list of parsed configuration file paths"""
        return [assertions.PASS]


interfaces.CommentNode.register(ApacheCommentNode)
interfaces.DirectiveNode.register(ApacheDirectiveNode)
interfaces.BlockNode.register(ApacheBlockNode)
