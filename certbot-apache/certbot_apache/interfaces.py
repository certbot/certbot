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
A good example of this is file path of a node - something that is needed by the
reverter functionality within the Configurator.


Apache implementation
---------------------

The Apache implementation of ParserNode interface requires some implementation
specific functionalities that are not described by the interface itself.

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
When parameters of ParserNode are changed, the pre-existing whitespaces are discarded
however, as the general reason for storing them is to maintain the ability to write
the configuration back to filesystem exactly like it was. This loses its meaning when
we have to change the directives or blocks parameters for other reasons.

Searches and matching

Apache configuration is largely case insensitive, so the Apache implementation of
ParserNode interface needs to provide the user means to match block and directive
names and parameters in case insensitive manner. This does not apply to everything
however, for example the parameters of a conditional statement may be case sensitive.
For this reason the internal representation of data should not ignore the case.
"""

import abc
import six


@six.add_metaclass(abc.ABCMeta)
class ParserNode(object):
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
    whitespaces in order to be able to reconstruct the complete configuration file i
    as it was when originally read from the disk.
    """

    @property
    @abc.abstractmethod
    def ancestor(self):  # pragma: no cover
        """
        This property contains a reference to ancestor node, or None if the node
        is the root node of the configuration tree.

        :returns: The ancestor BlockNode object, or None for root node.
        :rtype: ParserNode
        """

        raise NotImplementedError

    @property
    @abc.abstractmethod
    def dirty(self):  # pragma: no cover
        """
        This property contains a boolean value of the information if this node has
        been modified since last save (or after the initial parse).

        :returns: True if this node has had changes that have not yet been written
            to disk.
        :rtype: bool
        """

        raise NotImplementedError

    @abc.abstractmethod
    def save(self, msg):
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

        """


@six.add_metaclass(abc.ABCMeta)
class CommentNode(ParserNode):
    """
    CommentNode class is used for representation of comments within the parsed
    configuration structure. Because of the nature of comments, it is not able
    to have child nodes and hence it is always treated as a leaf node.

    CommentNode stores its contents in class variable 'comment' and does not
    have a specific name.

    """

    @property
    @abc.abstractmethod
    def comment(self):  # pragma: no cover
        """
        Comment property contains the contents of the comment without the comment
        directives (typically # or /* ... */).

        :returns: A string containing the comment
        :rtype: str
        """

        raise NotImplementedError

@six.add_metaclass(abc.ABCMeta)
class DirectiveNode(ParserNode):
    """
    DirectiveNode class represents a configuration directive within the configuration.
    It can have zero or more parameters attached to it. Because of the nature of
    single directives, it is not able to have child nodes and hence it is always
    treated as a leaf node.
    """

    @property
    @abc.abstractmethod
    def enabled(self):  # pragma: no cover
        """
        Configuration blocks may have conditional statements enabling or disabling
        their contents. This property returns the state of this DirectiveNode.

        :returns: True if the DirectiveNode is parsed and enabled in the configuration.
        :rtype: bool
        """

        raise NotImplementedError

    @property
    @abc.abstractmethod
    def name(self):  # pragma: no cover
        """
        Name property contains the name of the directive.

        :returns: Name of this node
        :rtype: str
        """

        raise NotImplementedError

    @property
    @abc.abstractmethod
    def parameters(self):  # pragma: no cover
        """
        This property contains a tuple of parameters of this ParserNode object
        excluding whitespaces.

        :returns: A tuple of parameters for this node
        :rtype: tuple
        """

        raise NotImplementedError

    @abc.abstractmethod
    def set_parameters(self, parameters):
        """
        Sets the sequence of parameters for this ParserNode object without
        whitespaces, and marks this object dirty.

        :param list parameters: sequence of parameters
        """


@six.add_metaclass(abc.ABCMeta)
class BlockNode(ParserNode):
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
    """

    @abc.abstractmethod
    def add_child_block(self, name, parameters=None, position=None):
        """
        Adds a new BlockNode child node with provided values and marks the callee
        BlockNode dirty. This is used to add new children to the AST.

        :param str name: The name of the child node to add
        :param list parameters: list of parameters for the node
        :param int position: Position in the list of children to add the new child
            node to. Defaults to None, which appends the newly created node to the list.
            If an integer is given, the child is inserted before that index in the
            list similar to list().insert.

        :returns: BlockNode instance of the created child block

        """

    @abc.abstractmethod
    def add_child_directive(self, name, parameters=None, position=None):
        """
        Adds a new DirectiveNode child node with provided values and marks the
        callee BlockNode dirty. This is used to add new children to the AST.

        :param str name: The name of the child node to add
        :param list parameters: list of parameters for the node
        :param int position: Position in the list of children to add the new child
            node to. Defaults to None, which appends the newly created node to the list.
            If an integer is given, the child is inserted before that index in the
            list similar to list().insert.

        :returns: DirectiveNode instance of the created child directive

        """

    @abc.abstractmethod
    def add_child_comment(self, comment="", position=None):
        """
        Adds a new CommentNode child node with provided value and marks the
        callee BlockNode dirty. This is used to add new children to the AST.

        :param str comment: Comment contents
        :param int position: Position in the list of children to add the new child
            node to. Defaults to None, which appends the newly created node to the list.
            If an integer is given, the child is inserted before that index in the
            list similar to list().insert.

        :returns: CommentNode instance of the created child comment

        """

    @property
    @abc.abstractmethod
    def children(self):  # pragma: no cover
        """
        This property contains a list ParserNode objects that are the children
        for this node. The order of children is the same as that of the parsed
        configuration block.

        :returns: A tuple of this block's children
        :rtype: tuple
        """

        raise NotImplementedError

    @property
    @abc.abstractmethod
    def enabled(self):
        """
        Configuration blocks may have conditional statements enabling or disabling
        their contents. This property returns the state of this configuration block.
        In case of unmatched conditional statement in block, this block itself should
        be set enabled while its children should be set disabled.

        :returns: True if the BlockNode is parsed and enabled in the configuration.
        :rtype: bool
        """

    @abc.abstractmethod
    def find_blocks(self, name, exclude=True):
        """
        Find a configuration block by name. This method walks the child tree of
        ParserNodes under the instance it was called from. This way it is possible
        to search for the whole configuration tree, when starting from root node or
        to do a partial search when starting from a specified branch.

        :param str name: The name of the directive to search for
        :param bool exclude: If the search results should exclude the contents of
            ParserNode objects that reside within conditional blocks and because
            of current state are not enabled.

        :returns: A list of found BlockNode objects.
        """

    @abc.abstractmethod
    def find_directives(self, name, exclude=True):
        """
        Find a directive by name. This method walks the child tree of ParserNodes
        under the instance it was called from. This way it is possible to search
        for the whole configuration tree, when starting from root node, or to do
        a partial search when starting from a specified branch.

        :param str name: The name of the directive to search for
        :param bool exclude: If the search results should exclude the contents of
            ParserNode objects that reside within conditional blocks and because
            of current state are not enabled.

        :returns: A list of found DirectiveNode objects.

        """

    @abc.abstractmethod
    def find_comments(self, comment, exact=False):
        """
        Find comments with value containing or being exactly the same as search term.

        This method walks the child tree of ParserNodes under the instance it was
        called from. This way it is possible to search for the whole configuration
        tree, when starting from root node, or to do a partial search when starting
        from a specified branch.

        :param str comment: The content of comment to search for
        :param bool exact: If the comment needs to exactly match the search term

        :returns: A list of found CommentNode objects.

        """

    @abc.abstractmethod
    def delete_child(self, child):
        """
        Remove a specified child node from the list of children of the called
        BlockNode object.

        :param ParserNode child: Child ParserNode object to remove from the list
            of children of the callee.
        """

    @property
    @abc.abstractmethod
    def name(self):  # pragma: no cover
        """
        Name property contains the name of the block. As an example for config:
            <VirtualHost *:80> ... </VirtualHost>
        the name would be "VirtualHost".

        :returns: Name of this node
        :rtype: str
        """

        raise NotImplementedError

    @property
    @abc.abstractmethod
    def parameters(self):  # pragma: no cover
        """
        This property contains a tuple of parameters of this ParserNode object
        excluding whitespaces.

        :returns: A tuple of parameters for this node
        :rtype: tuple
        """

        raise NotImplementedError

    @abc.abstractmethod
    def set_parameters(self, parameters):
        """
        Sets the sequence of parameters for this ParserNode object without
        whitespaces, and marks this object dirty.

        :param list parameters: sequence of parameters
        """

    @abc.abstractmethod
    def unsaved_files(self):
        """
        Returns a list of file paths that have been changed since the last save
        (or the initial configuration parse). The intended use for this method
        is to tell the Reverter which files need to be included in a checkpoint.

        This is typically called for the root of the ParserNode tree.

        :returns: list of file paths of files that have been changed but not yet
            saved to disk.
        """
