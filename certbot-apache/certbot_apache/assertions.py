"""Dual parser node assertions"""
from certbot_apache import interfaces


PASS = "CERTBOT_PASS_ASSERT"


def assertEqual(first, second):
    """ Equality assertion """

    if isinstance(first, interfaces.CommentNode):
        assertEqualComment(first, second)
    elif isinstance(first, interfaces.DirectiveNode):
        assertEqualDirective(first, second)

    # Skip tests if filepath includes the pass value. This is done
    # because filepath is variable of the base ParserNode interface, and
    # unless the implementation is actually done, we cannot assume getting
    # correct results from boolean assertion for dirty
    if not isPass(first.filepath, second.filepath):
        assert first.dirty == second.dirty
        # We might want to disable this later if testing with two separate
        # (but identical) directory structures.
        assert first.filepath == second.filepath

def assertEqualComment(first, second): # pragma: no cover
    """ Equality assertion for CommentNode """

    assert isinstance(first, interfaces.CommentNode)
    assert isinstance(second, interfaces.CommentNode)

    if not isPass(first.comment, second.comment):
        assert first.comment == second.comment

def _assertEqualDirectiveComponents(first, second): # pragma: no cover
    """ Handles assertion for instance variables for DirectiveNode and BlockNode"""

    # Enabled value cannot be asserted, because Augeas implementation
    # is unable to figure that out.
    # assert first.enabled == second.enabled
    if not isPass(first.name, second.name):
        assert first.name == second.name

    if not isPass(first.parameters, second.parameters):
        assert first.parameters == second.parameters

def assertEqualDirective(first, second):
    """ Equality assertion for DirectiveNode """

    assert isinstance(first, interfaces.DirectiveNode)
    assert isinstance(second, interfaces.DirectiveNode)
    _assertEqualDirectiveComponents(first, second)

def isPass(first, second): # pragma: no cover
    """ Checks if either first or second holds the assertion pass value """

    if isinstance(first, (tuple, list)):
        if PASS in first:
            return True
    if isinstance(second, (tuple, list)):
        if PASS in second:
            return True
    if PASS in [first, second]:
        return True
    return False

def assertSimple(first, second):
    """ Simple assertion """
    if not isPass(first, second):
        assert first == second
