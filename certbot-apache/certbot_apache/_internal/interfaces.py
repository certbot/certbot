"""ParserNode interface for interacting with configuration tree.

General description
-------------------

The ParserNode interfaces are designed to be able to contain all the parsing logic,
while allowing their users to interact with the configuration tree in a Pythonic
and well structured manner.

The structure allows easy traversal of the tree of ParserNodes. Each ParserNode
stores a reference to its ancestor and immediate children, allowing the user to
traverse the tree using built in interface methods as well as accessing the interface
properties directly.

ParserNode interface implementation should stand between the actual underlying
parser functionality and the business logic within Configurator code, interfacing
with both. The ParserNode tree is a result of configuration parsing action.

ParserNode tree will be in charge of maintaining the parser state and hence the
abstract syntax tree (AST). Interactions between ParserNode tree and underlying
parser should involve only parsing the configuration files to this structure, and
writing it back to the filesystem - while preserving the format including whitespaces.

For some implementations (Apache for example) it's important to keep track of and
to use state information while parsing conditional blocks and directives. This
allows the implementation to set a flag to parts of the parsed configuration
structure as not being in effect in a case of unmatched conditional block. It's
important to store these blocks in the tree as well in order to not to conduct
destructive actions (failing to write back parts of the configuration) while writing
the AST back to the filesystem.

The ParserNode tree is in charge of maintaining the its own structure while every
child node fetched with find - methods or by iterating its list of children can be
changed in place. When making changes the affected nodes should be flagged as "dirty"
in order for the parser implementation to figure out the parts of the configuration
that need to be written back to disk during the save() operation.


Metadata
--------

The metadata holds all the implementation specific attributes of the ParserNodes -
things like the positional information related to the AST, file paths, whitespacing,
and any other information relevant to the underlying parser engine.

Access to the metadata should be handled by implementation specific methods, allowing
the Configurator functionality to access the underlying information where needed.

For some implementations the node can be initialized using the information carried
in metadata alone. This is useful especially when populating the ParserNode tree
while parsing the configuration.


Apache implementation
---------------------

The Apache implementation of ParserNode interface requires some implementation
specific functionalities that are not described by the interface itself.

Initialization

When the user of a ParserNode class is creating these objects, they must specify
the parameters as described in the documentation for the __init__ methods below.
When these objects are created internally, however, some parameters may not be
needed because (possibly more detailed) information is included in the metadata
parameter. In this case, implementations can deviate from the required parameters
from __init__, however, they should still behave the same when metadata is not
provided.

For consistency internally, if an argument is provided directly in the ParserNode
initialization parameters as well as within metadata it's recommended to establish
clear behavior around this scenario within the implementation.

Conditional blocks

Apache configuration can have conditional blocks, for example: <IfModule ...>,
resulting the directives and subblocks within it being either enabled or disabled.
While find_* interface methods allow including the disabled parts of the configuration
tree in searches a special care needs to be taken while parsing the structure in
order to reflect the active state of configuration.

Whitespaces

Each ParserNode object is responsible of storing its prepending whitespace characters
in order to be able to write the AST back to filesystem like it was, preserving the
format, this applies for parameters of BlockNode and DirectiveNode as well.
When parameters of ParserNode are changed, the pre-existing whitespaces in the
parameter sequence are discarded, as the general reason for storing them is to
maintain the ability to write the configuration back to filesystem exactly like
it was. This loses its meaning when we have to change the directives or blocks
parameters for other reasons.

Searches and matching

Apache configuration is largely case insensitive, so the Apache implementation of
ParserNode interface needs to provide the user means to match block and directive
names and parameters in case insensitive manner. This does not apply to everything
however, for example the parameters of a conditional statement may be case sensitive.
For this reason the internal representation of data should not ignore the case.
"""
import abc
from typing import Any
from typing import Optional
from typing import TypeVar

GenericParserNode = TypeVar("GenericParserNode", bound="ParserNode")


class ParserNode(metaclass=abc.ABCMeta):
    """
    ParserNode is the basic building block of the tree of such nodes,
    representing the structure of the configuration. It is largely meant to keep
    the structure information intact and idiomatically accessible.

    The root node as well as the child nodes of it should be instances of ParserNode.
    Nodes keep track of their differences to on-disk representation of configuration
    by marking modified ParserNodes as dirty to enable partial write-to-disk for
    different files in the configuration structure.

    While for the most parts the usage and the child types are obvious, "include"-
    and similar directives are an exception to this rule. This is because of the
    nature of include directives - which unroll the contents of another file or
    configuration block to their place. While we could unroll the included nodes
    to the parent tree, it remains important to keep the context of include nodes
    separate in order to write back the original configuration as it was.

    For parsers that require the implementation to keep track of the whitespacing,
    it's responsibility of each ParserNode object itself to store its prepending
    whitespaces in order to be able to reconstruct the complete configuration file
    as it was when originally read from the disk.

    ParserNode objects should have the following attributes:

    # Reference to ancestor node, or None if the node is the root node of the
    # configuration tree.
    ancestor: Optional[ParserNode]

    # True if this node has been modified since last save.
    dirty: bool

    # Filepath of the file where the configuration element for this ParserNode
    # object resides. For root node, the value for filepath is the httpd root
    # configuration file. Filepath can be None if a configuration directive is
    # defined in for example the httpd command line.
    filepath: Optional[str]

    # Metadata dictionary holds all the implementation specific key-value pairs
    # for the ParserNode instance.
    metadata: dict[str, Any]
    """
    ancestor: Optional["ParserNode"]
    dirty: bool
    filepath: Optional[str]
    metadata: dict[str, Any]

    @abc.abstractmethod
    def __init__(self, **kwargs: Any) -> None:
        """
        Initializes the ParserNode instance, and sets the ParserNode specific
        instance variables. This is not meant to be used directly, but through
        specific classes implementing ParserNode interface.

        :param ancestor: BlockNode ancestor for this CommentNode. Required.
        :type ancestor: BlockNode or None

        :param filepath: Filesystem path for the file where this CommentNode
            does or should exist in the filesystem. Required.
        :type filepath: str or None

        :param dirty: Boolean flag for denoting if this CommentNode has been
            created or changed after the last save. Default: False.
        :type dirty: bool

        :param metadata: Dictionary of metadata values for this ParserNode object.
            Metadata information should be used only internally in the implementation.
            Default: {}
        :type metadata: dict
        """

    @abc.abstractmethod
    def save(self, msg: str) -> None:
        """
        Save traverses the children, and attempts to write the AST to disk for
        all the objects that are marked dirty. The actual operation of course
        depends on the underlying implementation. save() shouldn't be called
        from the Configurator outside of its designated save() method in order
        to ensure that the Reverter checkpoints are created properly.

        Note: this approach of keeping internal structure of the configuration
        within the ParserNode tree does not represent the file inclusion structure
        of actual configuration files that reside in the filesystem. To handle
        file writes properly, the file specific temporary trees should be extracted
        from the full ParserNode tree where necessary when writing to disk.

        :param str msg: Message describing the reason for the save.

        """

    @abc.abstractmethod
    def find_ancestors(self: GenericParserNode, name: str) -> list[GenericParserNode]:
        """
        Traverses the ancestor tree up, searching for BlockNodes with a specific
        name.

        :param str name: Name of the ancestor BlockNode to search for

        :returns: A list of ancestor BlockNodes that match the name
        :rtype: list of BlockNode
        """


class CommentNode(ParserNode, metaclass=abc.ABCMeta):
    """
    CommentNode class is used for representation of comments within the parsed
    configuration structure. Because of the nature of comments, it is not able
    to have child nodes and hence it is always treated as a leaf node.

    CommentNode stores its contents in class variable 'comment' and does not
    have a specific name.

    CommentNode objects should have the following attributes in addition to
    the ones described in ParserNode:

    # Contains the contents of the comment without the directive notation
    # (typically # or /* ... */).
    comment: str

    """
    comment: str

    @abc.abstractmethod
    def __init__(self, **kwargs: Any) -> None:
        """
        Initializes the CommentNode instance and sets its instance variables.

        :param comment: Contents of the comment. Required.
        :type comment: str

        :param ancestor: BlockNode ancestor for this CommentNode. Required.
        :type ancestor: BlockNode or None

        :param filepath: Filesystem path for the file where this CommentNode
            does or should exist in the filesystem. Required.
        :type filepath: str or None

        :param dirty: Boolean flag for denoting if this CommentNode has been
            created or changed after the last save. Default: False.
        :type dirty: bool
        """
        super().__init__(  # pragma: no cover
            ancestor=kwargs['ancestor'],
            dirty=kwargs.get('dirty', False),
            filepath=kwargs['filepath'],
            metadata=kwargs.get('metadata', {}),
        )


class DirectiveNode(ParserNode, metaclass=abc.ABCMeta):
    """
    DirectiveNode class represents a configuration directive within the configuration.
    It can have zero or more parameters attached to it. Because of the nature of
    single directives, it is not able to have child nodes and hence it is always
    treated as a leaf node.

    If a this directive was defined on the httpd command line, the ancestor instance
    variable for this DirectiveNode should be None, and it should be inserted to the
    beginning of root BlockNode children sequence.

    DirectiveNode objects should have the following attributes in addition to
    the ones described in ParserNode:

    # True if this DirectiveNode is enabled and False if it is inside of an
    # inactive conditional block.
    enabled: bool

    # Name, or key of the configuration directive. If BlockNode subclass of
    # DirectiveNode is the root configuration node, the name should be None.
    name: Optional[str]

    # Tuple of parameters of this ParserNode object, excluding whitespaces.
    parameters: tuple[str, ...]

    """
    enabled: bool
    name: Optional[str]
    parameters: tuple[str, ...]

    @abc.abstractmethod
    def __init__(self, **kwargs: Any) -> None:
        """
        Initializes the DirectiveNode instance and sets its instance variables.

        :param name: Name or key of the DirectiveNode object. Required.
        :type name: str or None

        :param tuple parameters: Tuple of str parameters for this DirectiveNode.
            Default: ().
        :type parameters: tuple

        :param ancestor: BlockNode ancestor for this DirectiveNode, or None for
            root configuration node. Required.
        :type ancestor: BlockNode or None

        :param filepath: Filesystem path for the file where this DirectiveNode
            does or should exist in the filesystem, or None for directives introduced
            in the httpd command line. Required.
        :type filepath: str or None

        :param dirty: Boolean flag for denoting if this DirectiveNode has been
            created or changed after the last save. Default: False.
        :type dirty: bool

        :param enabled: True if this DirectiveNode object is parsed in the active
            configuration of the httpd. False if the DirectiveNode exists within a
            unmatched conditional configuration block. Default: True.
        :type enabled: bool

        """
        super().__init__(  # pragma: no cover
            ancestor=kwargs['ancestor'],
            dirty=kwargs.get('dirty', False),
            filepath=kwargs['filepath'],
            metadata=kwargs.get('metadata', {}),
        )

    @abc.abstractmethod
    def set_parameters(self, parameters: list[str]) -> None:
        """
        Sets the sequence of parameters for this ParserNode object without
        whitespaces. While the whitespaces for parameters are discarded when using
        this method, the whitespacing preceding the ParserNode itself should be
        kept intact.

        :param list parameters: sequence of parameters
        """


class BlockNode(DirectiveNode, metaclass=abc.ABCMeta):
    """
    BlockNode class represents a block of nested configuration directives, comments
    and other blocks as its children. A BlockNode can have zero or more parameters
    attached to it.

    Configuration blocks typically consist of one or more child nodes of all possible
    types. Because of this, the BlockNode class has various discovery and structure
    management methods.

    Lists of parameters used as an optional argument for some of the methods should
    be lists of strings that are applicable parameters for each specific BlockNode
    or DirectiveNode type. As an example, for a following configuration example:

        <VirtualHost *:80>
           ...
        </VirtualHost>

    The node type would be BlockNode, name would be 'VirtualHost' and its parameters
    would be: ['*:80'].

    While for the following example:

        LoadModule alias_module /usr/lib/apache2/modules/mod_alias.so

    The node type would be DirectiveNode, name would be 'LoadModule' and its
    parameters would be: ['alias_module', '/usr/lib/apache2/modules/mod_alias.so']

    The applicable parameters are dependent on the underlying configuration language
    and its grammar.

    BlockNode objects should have the following attributes in addition to
    the ones described in DirectiveNode:

    # Tuple of direct children of this BlockNode object. The order of children
    # in this tuple retain the order of elements in the parsed configuration
    # block.
    children: tuple[ParserNode, ...]

    """
    children: tuple[ParserNode, ...]

    @abc.abstractmethod
    def add_child_block(self, name: str, parameters: Optional[list[str]] = None,
                        position: Optional[int] = None) -> "BlockNode":
        """
        Adds a new BlockNode child node with provided values and marks the callee
        BlockNode dirty. This is used to add new children to the AST. The preceding
        whitespaces should not be added based on the ancestor or siblings for the
        newly created object. This is to match the current behavior of the legacy
        parser implementation.

        :param str name: The name of the child node to add
        :param list parameters: list of parameters for the node
        :param int position: Position in the list of children to add the new child
            node to. Defaults to None, which appends the newly created node to the list.
            If an integer is given, the child is inserted before that index in the
            list similar to list().insert.

        :returns: BlockNode instance of the created child block

        """

    @abc.abstractmethod
    def add_child_directive(self, name: str, parameters: Optional[list[str]] = None,
                            position: Optional[int] = None) -> DirectiveNode:
        """
        Adds a new DirectiveNode child node with provided values and marks the
        callee BlockNode dirty. This is used to add new children to the AST. The
        preceding whitespaces should not be added based on the ancestor or siblings
        for the newly created object. This is to match the current behavior of the
        legacy parser implementation.


        :param str name: The name of the child node to add
        :param list parameters: list of parameters for the node
        :param int position: Position in the list of children to add the new child
            node to. Defaults to None, which appends the newly created node to the list.
            If an integer is given, the child is inserted before that index in the
            list similar to list().insert.

        :returns: DirectiveNode instance of the created child directive

        """

    @abc.abstractmethod
    def add_child_comment(self, comment: str = "", position: Optional[int] = None) -> CommentNode:
        """
        Adds a new CommentNode child node with provided value and marks the
        callee BlockNode dirty. This is used to add new children to the AST. The
        preceding whitespaces should not be added based on the ancestor or siblings
        for the newly created object. This is to match the current behavior of the
        legacy parser implementation.


        :param str comment: Comment contents
        :param int position: Position in the list of children to add the new child
            node to. Defaults to None, which appends the newly created node to the list.
            If an integer is given, the child is inserted before that index in the
            list similar to list().insert.

        :returns: CommentNode instance of the created child comment

        """

    @abc.abstractmethod
    def find_blocks(self, name: str, exclude: bool = True) -> list["BlockNode"]:
        """
        Find a configuration block by name. This method walks the child tree of
        ParserNodes under the instance it was called from. This way it is possible
        to search for the whole configuration tree, when starting from root node or
        to do a partial search when starting from a specified branch. The lookup
        should be case insensitive.

        :param str name: The name of the directive to search for
        :param bool exclude: If the search results should exclude the contents of
            ParserNode objects that reside within conditional blocks and because
            of current state are not enabled.

        :returns: A list of found BlockNode objects.
        """

    @abc.abstractmethod
    def find_directives(self, name: str, exclude: bool = True) -> list[DirectiveNode]:
        """
        Find a directive by name. This method walks the child tree of ParserNodes
        under the instance it was called from. This way it is possible to search
        for the whole configuration tree, when starting from root node, or to do
        a partial search when starting from a specified branch. The lookup should
        be case insensitive.

        :param str name: The name of the directive to search for
        :param bool exclude: If the search results should exclude the contents of
            ParserNode objects that reside within conditional blocks and because
            of current state are not enabled.

        :returns: A list of found DirectiveNode objects.

        """

    @abc.abstractmethod
    def find_comments(self, comment: str) -> list[CommentNode]:
        """
        Find comments with value containing the search term.

        This method walks the child tree of ParserNodes under the instance it was
        called from. This way it is possible to search for the whole configuration
        tree, when starting from root node, or to do a partial search when starting
        from a specified branch. The lookup should be case sensitive.

        :param str comment: The content of comment to search for

        :returns: A list of found CommentNode objects.

        """

    @abc.abstractmethod
    def delete_child(self, child: ParserNode) -> None:
        """
        Remove a specified child node from the list of children of the called
        BlockNode object.

        :param ParserNode child: Child ParserNode object to remove from the list
            of children of the callee.
        """

    @abc.abstractmethod
    def unsaved_files(self) -> list[str]:
        """
        Returns a list of file paths that have been changed since the last save
        (or the initial configuration parse). The intended use for this method
        is to tell the Reverter which files need to be included in a checkpoint.

        This is typically called for the root of the ParserNode tree.

        :returns: list of file paths of files that have been changed but not yet
            saved to disk.
        """

    @abc.abstractmethod
    def parsed_paths(self) -> list[str]:
        """
        Returns a list of file paths that have currently been parsed into the parser
        tree. The returned list may include paths with wildcard characters, for
        example: ['/etc/apache2/conf.d/*.load']

        This is typically called on the root node of the ParserNode tree.

        :returns: list of file paths of files that have been parsed
        """
