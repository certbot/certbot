""" Tests for ParserNode interface """
from certbot_apache import assertions
from certbot_apache import augeasparser


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
        if not assertions.isPass(firstval, secondval):
            assertions.assertSimple(firstval, secondval)
        return firstval


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

        if not primary:
            self.primary = augeasparser.AugeasCommentNode(**kwargs)
        else:
            self.primary = primary
        if not secondary:
            self.secondary = augeasparser.AugeasCommentNode(**kwargs)
        else:
            self.secondary = secondary

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

        if not primary:
            self.primary = augeasparser.AugeasDirectiveNode(**kwargs)
        else:
            self.primary = primary

        if not secondary:
            self.secondary = augeasparser.AugeasDirectiveNode(**kwargs)
        else:
            self.secondary = secondary

        assertions.assertEqual(self.primary, self.secondary)

    def set_parameters(self, parameters):
        """ Sets parameters and asserts that both implementation successfully
        set the parameter sequence """

        self.primary.set_parameters(parameters)
        self.secondary.set_parameters(parameters)
        assertions.assertEqual(self.primary, self.secondary)
