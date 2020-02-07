""" Dual ParserNode implementation """
from certbot_apache._internal import assertions
from certbot_apache._internal import augeasparser
from certbot_apache._internal import apacheparser


class DualNodeBase(object):
    """ Dual parser interface for in development testing. This is used as the
    base class for dual parser interface classes. This class handles runtime
    attribute value assertions."""

    def save(self, msg):  # pragma: no cover
        """ Call save for both parsers """
        self.primary.save(msg)
        self.secondary.save(msg)

    def __getattr__(self, aname):
        """ Attribute value assertion """
        firstval = getattr(self.primary, aname)
        secondval = getattr(self.secondary, aname)
        exclusions = [
            # Metadata will inherently be different, as ApacheParserNode does
            # not have Augeas paths and so on.
            aname == "metadata",
            callable(firstval)
        ]
        if not any(exclusions):
            assertions.assertEqualSimple(firstval, secondval)
        return firstval

    def find_ancestors(self, name):
        """ Traverses the ancestor tree and returns ancestors matching name """
        return self._find_helper(DualBlockNode, "find_ancestors", name)

    def _find_helper(self, nodeclass, findfunc, search, **kwargs):
        """A helper for find_* functions. The function specific attributes should
        be passed as keyword arguments.

        :param interfaces.ParserNode nodeclass: The node class for results.
        :param str findfunc: Name of the find function to call
        :param str search: The search term
        """

        primary_res = getattr(self.primary, findfunc)(search, **kwargs)
        secondary_res = getattr(self.secondary, findfunc)(search, **kwargs)

        # The order of search results for Augeas implementation cannot be
        # assured.

        pass_primary = assertions.isPassNodeList(primary_res)
        pass_secondary = assertions.isPassNodeList(secondary_res)
        new_nodes = list()

        if pass_primary and pass_secondary:
            # Both unimplemented
            new_nodes.append(nodeclass(primary=primary_res[0],
                                       secondary=secondary_res[0]))  # pragma: no cover
        elif pass_primary:
            for c in secondary_res:
                new_nodes.append(nodeclass(primary=primary_res[0],
                                           secondary=c))
        elif pass_secondary:
            for c in primary_res:
                new_nodes.append(nodeclass(primary=c,
                                           secondary=secondary_res[0]))
        else:
            assert len(primary_res) == len(secondary_res)
            matches = self._create_matching_list(primary_res, secondary_res)
            for p, s in matches:
                new_nodes.append(nodeclass(primary=p, secondary=s))

        return new_nodes


class DualCommentNode(DualNodeBase):
    """ Dual parser implementation of CommentNode interface """

    def __init__(self, **kwargs):
        """ This initialization implementation allows ordinary initialization
        of CommentNode objects as well as creating a DualCommentNode object
        using precreated or fetched CommentNode objects if provided as optional
        arguments primary and secondary.

        Parameters other than the following are from interfaces.CommentNode:

        :param CommentNode primary: Primary pre-created CommentNode, mainly
            used when creating new DualParser nodes using add_* methods.
        :param CommentNode secondary: Secondary pre-created CommentNode
        """

        kwargs.setdefault("primary", None)
        kwargs.setdefault("secondary", None)
        primary = kwargs.pop("primary")
        secondary = kwargs.pop("secondary")

        if primary or secondary:
            assert primary and secondary
            self.primary = primary
            self.secondary = secondary
        else:
            self.primary = augeasparser.AugeasCommentNode(**kwargs)
            self.secondary = apacheparser.ApacheCommentNode(**kwargs)

        assertions.assertEqual(self.primary, self.secondary)


class DualDirectiveNode(DualNodeBase):
    """ Dual parser implementation of DirectiveNode interface """

    def __init__(self, **kwargs):
        """ This initialization implementation allows ordinary initialization
        of DirectiveNode objects as well as creating a DualDirectiveNode object
        using precreated or fetched DirectiveNode objects if provided as optional
        arguments primary and secondary.

        Parameters other than the following are from interfaces.DirectiveNode:

        :param DirectiveNode primary: Primary pre-created DirectiveNode, mainly
            used when creating new DualParser nodes using add_* methods.
        :param DirectiveNode secondary: Secondary pre-created DirectiveNode


        """

        kwargs.setdefault("primary", None)
        kwargs.setdefault("secondary", None)
        primary = kwargs.pop("primary")
        secondary = kwargs.pop("secondary")

        if primary or secondary:
            assert primary and secondary
            self.primary = primary
            self.secondary = secondary
        else:
            self.primary = augeasparser.AugeasDirectiveNode(**kwargs)
            self.secondary = apacheparser.ApacheDirectiveNode(**kwargs)

        assertions.assertEqual(self.primary, self.secondary)

    def set_parameters(self, parameters):
        """ Sets parameters and asserts that both implementation successfully
        set the parameter sequence """

        self.primary.set_parameters(parameters)
        self.secondary.set_parameters(parameters)
        assertions.assertEqual(self.primary, self.secondary)


class DualBlockNode(DualNodeBase):
    """ Dual parser implementation of BlockNode interface """

    def __init__(self, **kwargs):
        """ This initialization implementation allows ordinary initialization
        of BlockNode objects as well as creating a DualBlockNode object
        using precreated or fetched BlockNode objects if provided as optional
        arguments primary and secondary.

        Parameters other than the following are from interfaces.BlockNode:

        :param BlockNode primary: Primary pre-created BlockNode, mainly
            used when creating new DualParser nodes using add_* methods.
        :param BlockNode secondary: Secondary pre-created BlockNode
        """

        kwargs.setdefault("primary", None)
        kwargs.setdefault("secondary", None)
        primary = kwargs.pop("primary")
        secondary = kwargs.pop("secondary")

        if primary or secondary:
            assert primary and secondary
            self.primary = primary
            self.secondary = secondary
        else:
            self.primary = augeasparser.AugeasBlockNode(**kwargs)
            self.secondary = apacheparser.ApacheBlockNode(**kwargs)

        assertions.assertEqual(self.primary, self.secondary)

    def add_child_block(self, name, parameters=None, position=None):
        """ Creates a new child BlockNode, asserts that both implementations
        did it in a similar way, and returns a newly created DualBlockNode object
        encapsulating both of the newly created objects """

        primary_new = self.primary.add_child_block(name, parameters, position)
        secondary_new = self.secondary.add_child_block(name, parameters, position)
        assertions.assertEqual(primary_new, secondary_new)
        new_block = DualBlockNode(primary=primary_new, secondary=secondary_new)
        return new_block

    def add_child_directive(self, name, parameters=None, position=None):
        """ Creates a new child DirectiveNode, asserts that both implementations
        did it in a similar way, and returns a newly created DualDirectiveNode
        object encapsulating both of the newly created objects """

        primary_new = self.primary.add_child_directive(name, parameters, position)
        secondary_new = self.secondary.add_child_directive(name, parameters, position)
        assertions.assertEqual(primary_new, secondary_new)
        new_dir = DualDirectiveNode(primary=primary_new, secondary=secondary_new)
        return new_dir

    def add_child_comment(self, comment="", position=None):
        """ Creates a new child CommentNode, asserts that both implementations
        did it in a similar way, and returns a newly created DualCommentNode
        object encapsulating both of the newly created objects """

        primary_new = self.primary.add_child_comment(comment, position)
        secondary_new = self.secondary.add_child_comment(comment, position)
        assertions.assertEqual(primary_new, secondary_new)
        new_comment = DualCommentNode(primary=primary_new, secondary=secondary_new)
        return new_comment

    def _create_matching_list(self, primary_list, secondary_list):
        """ Matches the list of primary_list to a list of secondary_list and
        returns a list of tuples. This is used to create results for find_
        methods.

        This helper function exists, because we cannot ensure that the list of
        search results returned by primary.find_* and secondary.find_* are ordered
        in a same way. The function pairs the same search results from both
        implementations to a list of tuples.
        """

        matched = list()
        for p in primary_list:
            match = None
            for s in secondary_list:
                try:
                    assertions.assertEqual(p, s)
                    match = s
                    break
                except AssertionError:
                    continue
            if match:
                matched.append((p, match))
            else:
                raise AssertionError("Could not find a matching node.")
        return matched

    def find_blocks(self, name, exclude=True):
        """
        Performs a search for BlockNodes using both implementations and does simple
        checks for results. This is built upon the assumption that unimplemented
        find_* methods return a list with a single assertion passing object.
        After the assertion, it creates a list of newly created DualBlockNode
        instances that encapsulate the pairs of returned BlockNode objects.
        """

        return self._find_helper(DualBlockNode, "find_blocks", name,
                                 exclude=exclude)

    def find_directives(self, name, exclude=True):
        """
        Performs a search for DirectiveNodes using both implementations and
        checks the results. This is built upon the assumption that unimplemented
        find_* methods return a list with a single assertion passing object.
        After the assertion, it creates a list of newly created DualDirectiveNode
        instances that encapsulate the pairs of returned DirectiveNode objects.
        """

        return self._find_helper(DualDirectiveNode, "find_directives", name,
                                 exclude=exclude)

    def find_comments(self, comment):
        """
        Performs a search for CommentNodes using both implementations and
        checks the results. This is built upon the assumption that unimplemented
        find_* methods return a list with a single assertion passing object.
        After the assertion, it creates a list of newly created DualCommentNode
        instances that encapsulate the pairs of returned CommentNode objects.
        """

        return self._find_helper(DualCommentNode, "find_comments", comment)

    def delete_child(self, child):
        """Deletes a child from the ParserNode implementations. The actual
        ParserNode implementations are used here directly in order to be able
        to match a child to the list of children."""

        self.primary.delete_child(child.primary)
        self.secondary.delete_child(child.secondary)

    def unsaved_files(self):
        """ Fetches the list of unsaved file paths and asserts that the lists
        match """
        primary_files = self.primary.unsaved_files()
        secondary_files = self.secondary.unsaved_files()
        assertions.assertEqualSimple(primary_files, secondary_files)

        return primary_files

    def parsed_paths(self):
        """
        Returns a list of file paths that have currently been parsed into the parser
        tree. The returned list may include paths with wildcard characters, for
        example: ['/etc/apache2/conf.d/*.load']

        This is typically called on the root node of the ParserNode tree.

        :returns: list of file paths of files that have been parsed
        """

        primary_paths = self.primary.parsed_paths()
        secondary_paths = self.secondary.parsed_paths()
        assertions.assertEqualPathsList(primary_paths, secondary_paths)
        return primary_paths
