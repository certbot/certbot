"""Dual parser node assertions"""
from certbot_apache import interfaces


PASS = "CERTBOT_PASS_ASSERT"


def assertEqual(first, second):
    """ Equality assertion """

    if isinstance(first, interfaces.CommentNode):
        assertEqualComment(first, second)
    elif isinstance(first, interfaces.DirectiveNode):
        assertEqualDirective(first, second)

    # Do an extra interface implementation assertion, as the contents were
    # already checked for BlockNode in the assertEqualDirective
    if isinstance(first, interfaces.BlockNode):
        assert isinstance(second, interfaces.BlockNode)

    # Skip tests if filepath includes the pass value. This is done
    # because filepath is variable of the base ParserNode interface, and
    # unless the implementation is actually done, we cannot assume getting
    # correct results from boolean assertion for dirty
    if not isPass(first.filepath) and not isPass(second.filepath):
        assert first.dirty == second.dirty
        # We might want to disable this later if testing with two separate
        # (but identical) directory structures.
        assert first.filepath == second.filepath

def assertEqualComment(first, second): # pragma: no cover
    """ Equality assertion for CommentNode """

    assert isinstance(first, interfaces.CommentNode)
    assert isinstance(second, interfaces.CommentNode)

    if not isPass(first.comment) and not isPass(second.comment):
        assert first.comment == second.comment

def _assertEqualDirectiveComponents(first, second): # pragma: no cover
    """ Handles assertion for instance variables for DirectiveNode and BlockNode"""
    # Enabled value cannot be asserted, because Augeas implementation
    # is unable to figure that out.
    # assert first.enabled == second.enabled
    if not isPass(first.name) and not isPass(second.name):
        assert first.name == second.name

    if not isPass(first.parameters) and not isPass(second.parameters):
        assert first.parameters == second.parameters

def assertEqualDirective(first, second):
    """ Equality assertion for DirectiveNode """

    assert isinstance(first, interfaces.DirectiveNode)
    assert isinstance(second, interfaces.DirectiveNode)
    _assertEqualDirectiveComponents(first, second)

def isPass(value): # pragma: no cover
    """Checks if the value is set to PASS"""
    return PASS in value

def isPassDirective(block):
    """ Checks if BlockNode or DirectiveNode should pass the assertion """

    if isPass(block.name):
        return True
    if isPass(block.parameters): # pragma: no cover
        return True
    if isPass(block.filepath): # pragma: no cover
        return True
    return False

def isPassComment(comment):
    """ Checks if CommentNode should pass the assertion """

    if isPass(comment.comment):
        return True
    if isPass(comment.filepath): # pragma: no cover
        return True
    return False

def isPassNodeList(nodelist): # pragma: no cover
    """ Checks if a ParserNode in the nodelist should pass the assertion,
    this function is used for results of find_* methods. Unimplemented find_*
    methods should return a sequence containing a single ParserNode instance
    with assertion pass string."""

    try:
        node = nodelist[0]
    except IndexError:
        node = None

    if not node: # pragma: no cover
        return False

    if isinstance(node, interfaces.DirectiveNode):
        return isPassDirective(node)
    return isPassComment(node)

def assertEqualSimple(first, second):
    """ Simple assertion """
    if not isPass(first) and not isPass(second):
        assert first == second
