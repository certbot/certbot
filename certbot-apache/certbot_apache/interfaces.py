"""Parser interfaces."""
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
    """

    @property
    @abc.abstractmethod
    def ancestor(self):
        """
        This property contains a reference to ancestor node, or None if the node
        is the root node of the configuration tree.
        """

        raise NotImplementedError

    @property
    @abc.abstractmethod
    def arguments(self):
        """
        This property contains a list of arguments of this ParserNode object.
        """

        raise NotImplementedError

    @property
    @abc.abstractmethod
    def dirty(self):
        """
        This property contains a boolean value of the information if this node has
        been modified since last save (or after the initial parse).
        """

        raise NotImplementedError

    @abc.abstractmethod
    def save(self, msg):
        """
        Save traverses the children, and attempts to write the AST to disk for
        all the objects that are marked dirty. The actual operation of course
        depends on the underlying implementation. save() shouldn't be called
        from the Configurator outside of it's designated save() method in order
        to ensure that the Reverter checkpoints are created properly.

        Note: this approach of keeping internal structure of the configuration
        within the ParserNode tree does not represent the file inclusion structure
        of actual configuration files that reside in the filesystem. To handle
        file writes properly, the file specific temporary trees should be extracted
        from the full ParserNode tree where necessary when writing to disk.

        """

    @abc.abstractmethod
    def set_arguments(self, arguments):
        """
        Sets argument list of the ParserNode object and marks the node dirty.
        """


@six.add_metaclass(abc.ABCMeta)
class CommentNode(ParserNode):
    """
    CommentNode class is used for representation of comments within the parsed
    configuration structure. Because of the nature of comments, it is not able
    to have child nodes and hence it is always treated as a leaf node.

    CommentNode stores its contents in class variable 'arguments' and does not
    have a specific name.
    """

    @property
    @abc.abstractmethod
    def comment(self):
        """
        Comment property contains the contents of the comment.
        """

        raise NotImplementedError

@six.add_metaclass(abc.ABCMeta)
class DirectiveNode(ParserNode):
    """
    DirectiveNode class represents a configuration directive within the configuration.
    It can have zero or more arguments attached to it. Because of the nature of
    single directives, it is not able to have child nodes and hence it is always
    treated as a leaf node.
    """

    @property
    @abc.abstractmethod
    def name(self):
        """
        Name property contains the name of the directive.
        """

        raise NotImplementedError


@six.add_metaclass(abc.ABCMeta)
class BlockNode(ParserNode):
    """
    BlockNode class represents a block of nested configuration directives, comments
    and other blocks as its children. A BlockNode can have zero or more arguments
    attached to it.

    Configuration blocks typically consist of one or more child nodes of all possible
    types. Because of this, the BlockNode class has various discovery and structure
    management methods.

    Lists of arguments used as an optional argument for some of the methods should
    be lists of strings that are applicable arguments for each specific BlockNode
    or DirectiveNode types. As an example, for a following configuration example:

        <VirtualHost *:80>
           ...
        </VirtualHost>

    The node type would be BlockNode, name would be 'VirtualHost' and arguments
    would be: ['*:80'].

    While for the following example:

        LoadModule alias_module /usr/lib/apache2/modules/mod_alias.so

    The node type would be DirectiveNode, name would be 'LoadModule' and arguments
    would be: ['alias_module', '/usr/lib/apache2/modules/mod_alias.so']

    The applicable arguments are dependent on the underlying configuration language
    and its grammar.
    """

    @abc.abstractmethod
    def add_child_block(self, name, arguments=None, position=None):
        """
        Adds a new BlockNode child node with provided values and marks the callee
        BlockNode dirty. This is used to add new children to the AST.

        :param str name: The name of the child node to add
        :param list arguments: list of arguments for the node
        :param int position: Position in the list of children to add the new child
            node to. Defaults to None, which appends the newly created node to the list.

        :returns: BlockNode instance of the created child block

        """

    @abc.abstractmethod
    def add_child_directive(self, name, arguments=None, position=None):
        """
        Adds a new DirectiveNode child node with provided values and marks the
        callee BlockNode dirty. This is used to add new children to the AST.

        :param str name: The name of the child node to add
        :param list arguments: list of arguments for the node
        :param int position: Position in the list of children to add the new child
            node to. Defaults to None, which appends the newly created node to the list.

        :returns: DirectiveNode instance of the created child directive

        """

    @abc.abstractmethod
    def add_child_comment(self, arguments=None, position=None):
        """
        Adds a new CommentNode child node with provided values and marks the
        callee BlockNode dirty. This is used to add new children to the AST.

        :param list arguments: list of arguments for the node
        :param int position: Position in the list of children to add the new child
            node to. Defaults to None, which appends the newly created node to the list.

        :returns: CommentNode instance of the created child comment

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

    @property
    @abc.abstractmethod
    def children(self):
        """
        This property contains a list ParserNode objects that are the children
        for this node.
        """

        raise NotImplementedError

    @abc.abstractmethod
    def find_blocks(self, name):
        """
        Find a configuration block by name. This method walks the child tree of
        ParserNodes under the instance it was called from. This way it is possible
        to search for the whole configuration tree, when starting from root node or
        to do a partial search when starting from a specified branch.

        :param str name: The name of the directive to search for

        :returns: A list of found BlockNode objects.
        """

    @abc.abstractmethod
    def find_directives(self, name):
        """
        Find a directive by name. This method walks the child tree of ParserNodes
        under the instance it was called from. This way it is possible to search
        for the whole configuration tree, when starting from root node, or to do
        a partial search when starting from a specified branch.

        :param str name: The name of the directive to search for

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
    def name(self):
        """
        Name property contains the name of the block. As an example for config:
            <VirtualHost *:80> ... </VirtualHost>
        the name would be "VirtualHost".
        """

        raise NotImplementedError
