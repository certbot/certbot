"""
Augeas implementation of the ParserNode interfaces.

Augeas works internally by using XPATH notation. The following is a short example
of how this all works internally, to better understand what's going on under the
hood.

A configuration file /etc/apache2/apache2.conf with the following content:

    # First comment line
    # Second comment line
    WhateverDirective whatevervalue
    <ABlock>
        DirectiveInABlock dirvalue
    </ABlock>
    SomeDirective somedirectivevalue
    <ABlock>
        AnotherDirectiveInABlock dirvalue
    </ABlock>
    # Yet another comment


Translates over to Augeas path notation (of immediate children), when calling
for example: aug.match("/files/etc/apache2/apache2.conf/*")

[
    "/files/etc/apache2/apache2.conf/#comment[1]",
    "/files/etc/apache2/apache2.conf/#comment[2]",
    "/files/etc/apache2/apache2.conf/directive[1]",
    "/files/etc/apache2/apache2.conf/ABlock[1]",
    "/files/etc/apache2/apache2.conf/directive[2]",
    "/files/etc/apache2/apache2.conf/ABlock[2]",
    "/files/etc/apache2/apache2.conf/#comment[3]"
]

Regardless of directives name, its key in the Augeas tree is always "directive",
with index where needed of course. Comments work similarly, while blocks
have their own key in the Augeas XPATH notation.

It's important to note that all of the unique keys have their own indices.

Augeas paths are case sensitive, while Apache configuration is case insensitive.
It looks like this:

    <block>
        directive value
    </block>
    <Block>
        Directive Value
    </Block>
    <block>
        directive value
    </block>
    <bLoCk>
        DiReCtiVe VaLuE
    </bLoCk>

Translates over to:

[
    "/files/etc/apache2/apache2.conf/block[1]",
    "/files/etc/apache2/apache2.conf/Block[1]",
    "/files/etc/apache2/apache2.conf/block[2]",
    "/files/etc/apache2/apache2.conf/bLoCk[1]",
]
"""
from typing import Any
from typing import cast
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import Union

from certbot import errors
from certbot.compat import os
from certbot_apache._internal import apache_util
from certbot_apache._internal import assertions
from certbot_apache._internal import interfaces
from certbot_apache._internal import parser
from certbot_apache._internal import parsernode_util as util


class AugeasParserNode(interfaces.ParserNode):
    """ Augeas implementation of ParserNode interface """

    def __init__(self, **kwargs: Any) -> None:
        # pylint: disable=unused-variable
        ancestor, dirty, filepath, metadata = util.parsernode_kwargs(kwargs)
        super().__init__(**kwargs)
        self.ancestor = ancestor
        self.filepath = filepath
        self.dirty = dirty
        self.metadata = metadata
        self.parser = cast(parser.ApacheParser,
                                                self.metadata.get("augeasparser"))
        try:
            if self.metadata["augeaspath"].endswith("/"):
                raise errors.PluginError(
                    "Augeas path: {} has a trailing slash".format(
                        self.metadata["augeaspath"]
                    )
                )
        except KeyError:
            raise errors.PluginError("Augeas path is required")

    def save(self, msg: Iterable[str]) -> None:
        self.parser.save(msg)

    def find_ancestors(self, name: str) -> List["AugeasParserNode"]:
        """
        Searches for ancestor BlockNodes with a given name.

        :param str name: Name of the BlockNode parent to search for

        :returns: List of matching ancestor nodes.
        :rtype: list of AugeasParserNode
        """

        ancestors: List["AugeasParserNode"] = []

        parent = self.metadata["augeaspath"]
        while True:
            # Get the path of ancestor node
            parent = parent.rpartition("/")[0]
            # Root of the tree
            if not parent or parent == "/files":
                break
            anc = self._create_blocknode(parent)
            if anc.name.lower() == name.lower():
                ancestors.append(anc)

        return ancestors

    def _create_blocknode(self, path: str) -> "AugeasBlockNode":
        """
        Helper function to create a BlockNode from Augeas path. This is used by
        AugeasParserNode.find_ancestors and AugeasBlockNode.
        and AugeasBlockNode.find_blocks

        """

        name: str = self._aug_get_name(path)
        metadata: Dict[str, Union[parser.ApacheParser, str]] = {
            "augeasparser": self.parser, "augeaspath": path
        }

        # Check if the file was included from the root config or initial state
        file_path = apache_util.get_file_path(path)
        if file_path is None:
            raise ValueError(f"No file path found for vhost: {path}.")  # pragma: no cover

        enabled = self.parser.parsed_in_original(file_path)

        return AugeasBlockNode(name=name,
                               enabled=enabled,
                               ancestor=assertions.PASS,
                               filepath=file_path,
                               metadata=metadata)

    def _aug_get_name(self, path: str) -> str:
        """
        Helper function to get name of a configuration block or variable from path.
        """

        # Remove the ending slash if any
        if path[-1] == "/":  # pragma: no cover
            path = path[:-1]

        # Get the block name
        name = path.split("/")[-1]

        # remove [...], it's not allowed in Apache configuration and is used
        # for indexing within Augeas
        return name.split("[")[0]


class AugeasCommentNode(AugeasParserNode):
    """ Augeas implementation of CommentNode interface """

    def __init__(self, **kwargs: Any) -> None:
        comment, kwargs = util.commentnode_kwargs(kwargs)  # pylint: disable=unused-variable
        super().__init__(**kwargs)
        self.comment = comment

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return (self.comment == other.comment and
                    self.filepath == other.filepath and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)
        return False


class AugeasDirectiveNode(AugeasParserNode):
    """ Augeas implementation of DirectiveNode interface """

    def __init__(self, **kwargs: Any) -> None:
        name, parameters, enabled, kwargs = util.directivenode_kwargs(kwargs)
        super().__init__(**kwargs)
        self.name: str = name
        self.enabled: bool = enabled
        if parameters:
            self.set_parameters(parameters)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, self.__class__):
            return (self.name == other.name and
                    self.filepath == other.filepath and
                    self.parameters == other.parameters and
                    self.enabled == other.enabled and
                    self.dirty == other.dirty and
                    self.ancestor == other.ancestor and
                    self.metadata == other.metadata)
        return False

    def set_parameters(self, parameters: Iterable[str]) -> None:
        """
        Sets parameters of a DirectiveNode or BlockNode object.

        :param list parameters: List of all parameters for the node to set.
        """
        orig_params = self._aug_get_params(self.metadata["augeaspath"])

        # Clear out old parameters
        for _ in orig_params:
            # When the first parameter is removed, the indices get updated
            param_path = "{}/arg[1]".format(self.metadata["augeaspath"])
            self.parser.aug.remove(param_path)
        # Insert new ones
        for pi, param in enumerate(parameters):
            param_path = "{}/arg[{}]".format(self.metadata["augeaspath"], pi+1)
            self.parser.aug.set(param_path, param)

    @property
    def parameters(self) -> Tuple[str, ...]:
        """
        Fetches the parameters from Augeas tree, ensuring that the sequence always
        represents the current state

        :returns: Tuple of parameters for this DirectiveNode
        :rtype: tuple:
        """
        return tuple(self._aug_get_params(self.metadata["augeaspath"]))

    def _aug_get_params(self, path: str) -> List[str]:
        """Helper function to get parameters for DirectiveNodes and BlockNodes"""

        arg_paths = self.parser.aug.match(path + "/arg")
        args = [self.parser.get_arg(apath) for apath in arg_paths]
        return [arg for arg in args if arg is not None]


class AugeasBlockNode(AugeasDirectiveNode):
    """ Augeas implementation of BlockNode interface """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.children: Tuple["AugeasBlockNode", ...] = ()

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
        return False

    # pylint: disable=unused-argument
    def add_child_block(self, name: str,  # pragma: no cover
                        parameters: Optional[Sequence[str]] = None,
                        position: Optional[int] = None) -> "AugeasBlockNode":
        """Adds a new BlockNode to the sequence of children"""

        insertpath, realpath, before = self._aug_resolve_child_position(
            name,
            position
        )
        new_metadata: Dict[str, Any] = {"augeasparser": self.parser, "augeaspath": realpath}

        # Create the new block
        self.parser.aug.insert(insertpath, name, before)
        # Check if the file was included from the root config or initial state
        file_path = apache_util.get_file_path(realpath)
        if file_path is None:
            raise errors.Error(f"No file path found for vhost: {realpath}")  # pragma: no cover
        enabled = self.parser.parsed_in_original(file_path)

        # Parameters will be set at the initialization of the new object
        return AugeasBlockNode(
            name=name,
            parameters=parameters,
            enabled=enabled,
            ancestor=assertions.PASS,
            filepath=file_path,
            metadata=new_metadata,
        )

    # pylint: disable=unused-argument
    def add_child_directive(self, name: str,  # pragma: no cover
                            parameters: Optional[Sequence[str]] = None,
                            position: Optional[int] = None) -> AugeasDirectiveNode:
        """Adds a new DirectiveNode to the sequence of children"""

        if not parameters:
            raise errors.PluginError("Directive requires parameters and none were set.")

        insertpath, realpath, before = self._aug_resolve_child_position(
            "directive",
            position
        )
        new_metadata = {"augeasparser": self.parser, "augeaspath": realpath}

        # Create the new directive
        self.parser.aug.insert(insertpath, "directive", before)
        # Set the directive key
        self.parser.aug.set(realpath, name)
        # Check if the file was included from the root config or initial state
        file_path = apache_util.get_file_path(realpath)
        if file_path is None:
            raise errors.Error(f"No file path found for vhost: {realpath}")  # pragma: no cover
        enabled = self.parser.parsed_in_original(file_path)

        return AugeasDirectiveNode(
            name=name,
            parameters=parameters,
            enabled=enabled,
            ancestor=assertions.PASS,
            filepath=file_path,
            metadata=new_metadata,
        )

    def add_child_comment(
        self, comment: str = "", position: Optional[int] = None
    ) -> "AugeasCommentNode":
        """Adds a new CommentNode to the sequence of children"""

        insertpath, realpath, before = self._aug_resolve_child_position(
            "#comment",
            position
        )
        new_metadata: Dict[str, Any] = {
            "augeasparser": self.parser, "augeaspath": realpath,
        }

        # Create the new comment
        self.parser.aug.insert(insertpath, "#comment", before)
        # Set the comment content
        self.parser.aug.set(realpath, comment)

        return AugeasCommentNode(
            comment=comment,
            ancestor=assertions.PASS,
            filepath=apache_util.get_file_path(realpath),
            metadata=new_metadata,
        )

    def find_blocks(self, name: str, exclude: bool = True) -> List["AugeasBlockNode"]:
        """Recursive search of BlockNodes from the sequence of children"""

        nodes: List["AugeasBlockNode"] = []
        paths: Iterable[str] = self._aug_find_blocks(name)
        if exclude:
            paths = self.parser.exclude_dirs(paths)
        for path in paths:
            nodes.append(self._create_blocknode(path))

        return nodes

    def find_directives(self, name: str, exclude: bool = True) -> List["AugeasDirectiveNode"]:
        """Recursive search of DirectiveNodes from the sequence of children"""

        nodes = []
        ownpath = self.metadata.get("augeaspath")

        directives = self.parser.find_dir(name, start=ownpath, exclude=exclude)
        already_parsed: Set[str] = set()
        for directive in directives:
            # Remove the /arg part from the Augeas path
            directive = directive.partition("/arg")[0]
            # find_dir returns an object for each _parameter_ of a directive
            # so we need to filter out duplicates.
            if directive not in already_parsed:
                nodes.append(self._create_directivenode(directive))
                already_parsed.add(directive)

        return nodes

    def find_comments(self, comment: str) -> List["AugeasCommentNode"]:
        """
        Recursive search of DirectiveNodes from the sequence of children.

        :param str comment: Comment content to search for.
        """

        nodes: List["AugeasCommentNode"] = []
        ownpath = self.metadata.get("augeaspath")

        comments = self.parser.find_comments(comment, start=ownpath)
        for com in comments:
            nodes.append(self._create_commentnode(com))

        return nodes

    def delete_child(self, child: "AugeasParserNode") -> None:
        """
        Deletes a ParserNode from the sequence of children, and raises an
        exception if it's unable to do so.
        :param AugeasParserNode child: A node to delete.
        """
        if not self.parser.aug.remove(child.metadata["augeaspath"]):

            raise errors.PluginError(
                ("Could not delete child node, the Augeas path: {} doesn't " +
                 "seem to exist.").format(child.metadata["augeaspath"])
            )

    def unsaved_files(self) -> Set[str]:
        """Returns a list of unsaved filepaths"""
        return self.parser.unsaved_files()

    def parsed_paths(self) -> List[str]:
        """
        Returns a list of file paths that have currently been parsed into the parser
        tree. The returned list may include paths with wildcard characters, for
        example: ['/etc/apache2/conf.d/*.load']

        This is typically called on the root node of the ParserNode tree.

        :returns: list of file paths of files that have been parsed
        """

        res_paths: List[str] = []

        paths = self.parser.existing_paths
        for directory in paths:
            for filename in paths[directory]:
                res_paths.append(os.path.join(directory, filename))

        return res_paths

    def _create_commentnode(self, path: str) -> "AugeasCommentNode":
        """Helper function to create a CommentNode from Augeas path"""

        comment = self.parser.aug.get(path)
        metadata = {"augeasparser": self.parser, "augeaspath": path}

        # Because of the dynamic nature of AugeasParser and the fact that we're
        # not populating the complete node tree, the ancestor has a dummy value
        return AugeasCommentNode(comment=comment,
                                 ancestor=assertions.PASS,
                                 filepath=apache_util.get_file_path(path),
                                 metadata=metadata)

    def _create_directivenode(self, path: str) -> "AugeasDirectiveNode":
        """Helper function to create a DirectiveNode from Augeas path"""

        name = self.parser.get_arg(path)
        metadata: Dict[str, Union[parser.ApacheParser, str]] = {
            "augeasparser": self.parser, "augeaspath": path,
        }

        # Check if the file was included from the root config or initial state
        enabled: bool = self.parser.parsed_in_original(
            apache_util.get_file_path(path)
        )
        return AugeasDirectiveNode(name=name,
                                   ancestor=assertions.PASS,
                                   enabled=enabled,
                                   filepath=apache_util.get_file_path(path),
                                   metadata=metadata)

    def _aug_find_blocks(self, name: str) -> Set[str]:
        """Helper function to perform a search to Augeas DOM tree to search
        configuration blocks with a given name"""

        # The code here is modified from configurator.get_virtual_hosts()
        blk_paths: Set[str] = set()
        for vhost_path in list(self.parser.parser_paths):
            paths = self.parser.aug.match(
                ("/files%s//*[label()=~regexp('%s')]" %
                    (vhost_path, parser.case_i(name))))
            blk_paths.update([path for path in paths if
                              name.lower() in os.path.basename(path).lower()])
        return blk_paths

    def _aug_resolve_child_position(
        self, name: str, position: Optional[int]) -> Tuple[str, str, bool]:
        """
        Helper function that iterates through the immediate children and figures
        out the insertion path for a new AugeasParserNode.

        Augeas also generalizes indices for directives and comments, simply by
        using "directive" or "comment" respectively as their names.

        This function iterates over the existing children of the AugeasBlockNode,
        returning their insertion path, resulting Augeas path and if the new node
        should be inserted before or after the returned insertion path.

        Note: while Apache is case insensitive, Augeas is not, and blocks like
        Nameofablock and NameOfABlock have different indices.

        :param str name: Name of the AugeasBlockNode to insert, "directive" for
            AugeasDirectiveNode or "comment" for AugeasCommentNode
        :param int position: The position to insert the child AugeasParserNode to

        :returns: Tuple of insert path, resulting path and a boolean if the new
            node should be inserted before it.
        :rtype: tuple of str, str, bool
        """

        # Default to appending
        before: bool = False

        all_children: str = self.parser.aug.match("{}/*".format(
            self.metadata["augeaspath"])
        )

        # Calculate resulting_path
        # Augeas indices start at 1. We use counter to calculate the index to
        # be used in resulting_path.
        counter: int = 1
        for i, child in enumerate(all_children):
            if position is not None and i >= position:
                # We're not going to insert the new node to an index after this
                break
            childname = self._aug_get_name(child)
            if name == childname:
                counter += 1

        resulting_path: str = "{}/{}[{}]".format(
            self.metadata["augeaspath"],
            name,
            counter
        )

        # Form the correct insert_path
        # Inserting the only child and appending as the last child work
        # similarly in Augeas.
        append = not all_children or position is None or position >= len(all_children)
        if append:
            insert_path = "{}/*[last()]".format(
                self.metadata["augeaspath"]
            )
        elif position == 0:
            # Insert as the first child, before the current first one.
            insert_path = all_children[0]
            before = True
        else:
            insert_path = "{}/*[{}]".format(
                self.metadata["augeaspath"],
                position
            )

        return insert_path, resulting_path, before


interfaces.CommentNode.register(AugeasCommentNode)
interfaces.DirectiveNode.register(AugeasDirectiveNode)
interfaces.BlockNode.register(AugeasBlockNode)
