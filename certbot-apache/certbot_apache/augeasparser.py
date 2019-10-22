""" Augeas implementation of the ParserNode interfaces """

from certbot_apache import apache_util
from certbot_apache import assertions
from certbot_apache import interfaces
from certbot_apache import parser
from certbot_apache import parsernode_util as util

from certbot.compat import os
from acme.magic_typing import Set  # pylint: disable=unused-import, no-name-in-module


class AugeasParserNode(interfaces.ParserNode):
    """ Augeas implementation of ParserNode interface """

    def __init__(self, **kwargs):
        ancestor, dirty, filepath, metadata = util.parsernode_kwargs(kwargs)  # pylint: disable=unused-variable
        super(AugeasParserNode, self).__init__(**kwargs)
        self.ancestor = ancestor
        self.filepath = filepath
        self.dirty = dirty
        self.metadata = metadata
        self.parser = self.metadata.get("augeasparser")

    def save(self, msg): # pragma: no cover
        pass


class AugeasCommentNode(AugeasParserNode):
    """ Augeas implementation of CommentNode interface """

    def __init__(self, **kwargs):
        comment, kwargs = util.commentnode_kwargs(kwargs)  # pylint: disable=unused-variable
        super(AugeasCommentNode, self).__init__(**kwargs)
        # self.comment = comment
        self.comment = comment

    def __eq__(self, other):
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

    def __eq__(self, other):
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


class AugeasBlockNode(AugeasDirectiveNode):
    """ Augeas implementation of BlockNode interface """

    def __init__(self, **kwargs):
        super(AugeasBlockNode, self).__init__(**kwargs)
        self.children = ()

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
        new_metadata = {"augeasparser": self.parser}
        new_block = AugeasBlockNode(name=assertions.PASS,
                                    ancestor=self,
                                    filepath=assertions.PASS,
                                    metadata=new_metadata)
        self.children += (new_block,)
        return new_block

    def add_child_directive(self, name, parameters=None, position=None):  # pylint: disable=unused-argument
        """Adds a new DirectiveNode to the sequence of children"""
        new_metadata = {"augeasparser": self.parser}
        new_dir = AugeasDirectiveNode(name=assertions.PASS,
                                      ancestor=self,
                                      filepath=assertions.PASS,
                                      metadata=new_metadata)
        self.children += (new_dir,)
        return new_dir

    def add_child_comment(self, comment="", position=None):  # pylint: disable=unused-argument
        """Adds a new CommentNode to the sequence of children"""
        new_metadata = {"augeasparser": self.parser}
        new_comment = AugeasCommentNode(comment=assertions.PASS,
                                        ancestor=self,
                                        filepath=assertions.PASS,
                                        metadata=new_metadata)
        self.children += (new_comment,)
        return new_comment

    def find_blocks(self, name, exclude=True): # pylint: disable=unused-argument
        """Recursive search of BlockNodes from the sequence of children"""

        nodes = list()
        paths = self._aug_find_blocks(name)
        if exclude:
            paths = self.parser.exclude_dirs(paths)
        for path in paths:
            nodes.append(self._create_blocknode(path))

        return nodes

    def find_directives(self, name, exclude=True): # pylint: disable=unused-argument
        """Recursive search of DirectiveNodes from the sequence of children"""

        nodes = list()
        ownpath = self.metadata.get("augeaspath")

        directives = self.parser.find_dir(name, start=ownpath, exclude=exclude)
        already_parsed = set()  # type: Set[str]
        for directive in directives:
            # Remove the /arg part from the Augeas path
            directive = directive.partition("/arg")[0]
            # find_dir returns an object for each _parameter_ of a directive
            # so we need to filter out duplicates.
            if directive not in already_parsed:
                nodes.append(self._create_directivenode(directive))
                already_parsed.add(directive)

        return nodes

    def find_comments(self, comment, exact=False): # pylint: disable=unused-argument
        """
        Recursive search of DirectiveNodes from the sequence of children.

        Note that the argument exact is not implemented here, as it's not
        currently in use in ApacheConfigurator.
        """

        nodes = list()
        ownpath = self.metadata.get("augeaspath")

        comments = self.parser.find_comments(comment, start=ownpath)
        for com in comments:
            nodes.append(self._create_commentnode(com))

        return nodes

    def delete_child(self, child):  # pragma: no cover
        """Deletes a ParserNode from the sequence of children"""
        pass

    def unsaved_files(self):  # pragma: no cover
        """Returns a list of unsaved filepaths"""
        return [assertions.PASS]

    def _create_commentnode(self, path):
        """Helper function to create a CommentNode from Augeas path"""

        comment = self.parser.aug.get(path)
        metadata = {"augeasparser": self.parser, "augeaspath": path}

        # Because of the dynamic nature, and the fact that we're not populating
        # the complete ParserNode tree, we use the search parent as ancestor
        return AugeasCommentNode(comment=comment,
                                 ancestor=self,
                                 filepath=apache_util.get_file_path(path),
                                 metadata=metadata)

    def _create_directivenode(self, path):
        """Helper function to create a DirectiveNode from Augeas path"""

        name = self.parser.get_arg(path)
        params = tuple(self._aug_get_params(path))
        metadata = {"augeasparser": self.parser, "augeaspath": path}

        # Because of the dynamic nature, and the fact that we're not populating
        # the complete ParserNode tree, we use the search parent as ancestor
        return AugeasDirectiveNode(name=name,
                                   parameters=params,
                                   ancestor=self,
                                   filepath=apache_util.get_file_path(path),
                                   metadata=metadata)

    def _create_blocknode(self, path):
        """Helper function to create a BlockNode from Augeas path"""

        name = self._aug_get_block_name(path)
        params = tuple(self._aug_get_params(path))
        metadata = {"augeasparser": self.parser, "augeaspath": path}

        # Because of the dynamic nature, and the fact that we're not populating
        # the complete ParserNode tree, we use the search parent as ancestor
        return AugeasBlockNode(name=name,
                               parameters=params,
                               ancestor=self,
                               filepath=apache_util.get_file_path(path),
                               metadata=metadata)

    def _aug_find_blocks(self, name):
        """Helper function to perform a search to Augeas DOM tree to search
        configuration blocks with a given name"""

        # The code here is modified from configurator.get_virtual_hosts()
        blk_paths = set()
        for vhost_path in list(self.parser.parser_paths):
            paths = self.parser.aug.match(
                ("/files%s//*[label()=~regexp('%s')]" %
                    (vhost_path, parser.case_i(name))))
            blk_paths.update([path for path in paths if
                              name.lower() in os.path.basename(path).lower()])
        return blk_paths

    def _aug_get_params(self, path):
        """Helper function to get parameters for BlockNodes"""

        arg_paths = self.parser.aug.match(path + "/arg")
        return [self.parser.get_arg(apath) for apath in arg_paths]

    def _aug_get_block_name(self, path):
        """Helper function to get name of a configuration block from path."""

        # Remove the ending slash if any
        if path[-1] == "/":  # pragma: no cover
            path = path[:-1]

        # Get the block name
        name = path.split("/")[-1]

        # remove [...], it's not allowed in Apache configuration and is used
        # for indexing within Augeas
        name = name.split("[")[0]
        return name


interfaces.CommentNode.register(AugeasCommentNode)
interfaces.DirectiveNode.register(AugeasDirectiveNode)
interfaces.BlockNode.register(AugeasBlockNode)
