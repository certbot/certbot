""" Tests for ParserNode interface """
from certbot_apache import interfaces

from acme.magic_typing import Dict, Tuple  # pylint: disable=unused-import, no-name-in-module


class AugeasCommentNode(interfaces.CommentNode):
    """ Augeas implementation of CommentNode interface """
    ancestor = None
    comment = ""
    dirty = False
    _metadata = dict()  # type: Dict[str, object]

    def __init__(self, comment, ancestor=None):
        self.comment = comment
        self.ancestor = ancestor

    def save(self, msg):  # pragma: no cover
        pass

    # Apache specific functionality

    def get_metadata(self, key):
        """ Returns a metadata object

        :param str key: Metadata object name to return
        :returns: Requested metadata object
        """
        try:
            return self._metadata[key]
        except KeyError:
            return None

class AugeasDirectiveNode(interfaces.DirectiveNode):
    """ Augeas implementation of DirectiveNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    dirty = False
    enabled = True
    name = ""
    _metadata = dict()  # type: Dict[str, object]

    def __init__(self, name, parameters=tuple(), ancestor=None):
        self.name = name
        self.parameters = parameters
        self.ancestor = ancestor

    def save(self, msg):  # pragma: no cover
        pass

    def set_parameters(self, parameters):  # pragma: no cover
        self.parameters = tuple("CERTBOT_PASS_ASSERT")

    # Apache specific functionality

    def get_filename(self):
        """Returns the filename where this directive exists on disk

        :returns: File path to this node.
        :rtype: str
        """

        # Following is the real implementation when everything else is in place:
        # return apache_util.get_file_path(
        #    self.parser.aug.get("/augeas/files%s/path" % apache_util.get_file_path(path)))
        return "CERTBOT_PASS_ASSERT"

    def get_metadata(self, key):
        """ Returns a metadata object

        :param str key: Metadata object name to return
        :returns: Requested metadata object
        """
        try:
            return self._metadata[key]
        except KeyError:
            return None

    def has_parameter(self, parameter, position=None):
        """Checks if this ParserNode object has a supplied parameter. This check
        is case insensitive.

        :param str parameter: Parameter value to look for
        :param position: Optional explicit position of parameter to look for

        :returns: True if parameter is found
        :rtype: bool
        """
        if position != None:
            return parameter.lower() == self.parameters[position].lower()

        for param in self.parameters:
            if param.lower() == parameter.lower():
                return True

        return False

class AugeasBlockNode(interfaces.BlockNode):
    """ Augeas implementation of BlockNode interface """
    ancestor = None
    parameters = tuple()  # type: Tuple[str, ...]
    children = tuple()  # type: Tuple[interfaces.ParserNode, ...]
    dirty = False
    enabled = True
    name = ""
    _metadata = dict()  # type: Dict[str, object]

    def __init__(self, name, parameters=tuple(), ancestor=None):
        self.name = name
        self.parameters = parameters
        self.ancestor = ancestor

    def save(self, msg):  # pragma: no cover
        pass

    def add_child_block(self, name, parameters=None, position=None):  # pragma: no cover
        new_block = AugeasBlockNode("CERTBOT_PASS_ASSERT", ancestor=self)
        self.children += (new_block,)
        return new_block

    def add_child_directive(self, name, parameters=None, position=None):  # pragma: no cover
        new_dir = AugeasDirectiveNode("CERTBOT_PASS_ASSERT", ancestor=self)
        self.children += (new_dir,)
        return new_dir

    def add_child_comment(self, comment="", position=None):  # pragma: no cover
        new_comment = AugeasCommentNode("CERTBOT_PASS_ASSERT", ancestor=self)
        self.children += (new_comment,)
        return new_comment

    def find_blocks(self, name, exclude=True):  # pragma: no cover
        return [AugeasBlockNode("CERTBOT_PASS_ASSERT", ancestor=self)]

    def find_directives(self, name, exclude=True):  # pragma: no cover
        return [AugeasDirectiveNode("CERTBOT_PASS_ASSERT", ancestor=self)]

    def find_comments(self, comment, exact=False):  # pragma: no cover
        return [AugeasCommentNode("CERTBOT_PASS_ASSERT", ancestor=self)]

    def delete_child(self, child):  # pragma: no cover
        pass

    def set_parameters(self, parameters):  # pragma: no cover
        self.parameters = tuple("CERTBOT_PASS_ASSERT")

    def unsaved_files(self):  # pragma: no cover
        return ["CERTBOT_PASS_ASSERT"]

    # Apache specific functionality

    def get_filename(self):
        """Returns the filename where this directive exists on disk

        :returns: File path to this node.
        :rtype: str
        """

        # Following is the real implementation when everything else is in place:
        # return apache_util.get_file_path(
        #    self.parser.aug.get("/augeas/files%s/path" %
        #    apache_util.get_file_path(self.get_metadata("augeas_path")))
        return "CERTBOT_PASS_ASSERT"

    def get_metadata(self, key):
        """ Returns a metadata object

        :param str key: Metadata object name to return
        :returns: Requested metadata object
        """
        try:
            return self._metadata[key]
        except KeyError:
            return None

    def has_parameter(self, parameter, position=None):
        """Checks if this ParserNode object has a supplied parameter. This check
        is case insensitive.

        :param str parameter: Parameter value to look for
        :param position: Optional explicit position of parameter to look for

        :returns: True if parameter is found
        :rtype: bool
        """
        if position != None:
            return parameter.lower() == self.parameters[position].lower()

        for param in self.parameters:
            if param.lower() == parameter.lower():
                return True

        return False
