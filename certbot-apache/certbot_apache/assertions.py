from certbot_apache import interfaces


PASS = "CERTBOT_PASS_ASSERT"


def assertEqual(first, second):
    """ Equality assertion """

    if isinstance(first, interfaces.CommentNode):
        assertEqualComment(first, second)
    elif isinstance(first, interfaces.DirectiveNode):
        assertEqualDirective(first, second)
    elif isinstance(first, interfaces.BlockNode):
        assertEqualBlock(first, second)

    # Skip tests if filepath includes the pass value. This is done
    # because filepath is variable of the base ParserNode interface, and
    # unless the implementation is actually done, we cannot assume getting
    # correct results from boolean assertion for dirty
    if not isPass(first.filepath, second.filepath):
        assert first.dirty == second.dirty
        # We might want to disable this later if testing with two separate
        # (but identical) directory structures.
        assert first.filepath == second.filepath

def assertEqualComment(first, second):
    """ Equality assertion for CommentNode """

    assert isinstance(first, interfaces.CommentNode)
    assert isinstance(second, interfaces.CommentNode)

    if not isPass(first.comment, second.comment):
        assert first.comment == second.comment

    if not isPass(first.filepath, second.filepath):
        assert first.filepath == second.filepath

def _assertEqualDirectiveComponents(first, second):
    """ Handles assertion for instance variables for DirectiveNode and BlockNode"""

    # Enabled value cannot be asserted, because Augeas implementation
    # is unable to figure that out.
    # assert first.enabled == second.enabled
    if not isPass(first.name, second.name):
        assert first.name == second.name

    if not isPass(first.filepath, second.filepath):
        assert first.filepath == second.filepath

    if not isPass(first.parameters, second.parameters):
        assert first.parameters == second.parameters

def assertEqualDirective(first, second):
    """ Equality assertion for DirectiveNode """

    assert isinstance(first, interfaces.DirectiveNode)
    assert isinstance(second, interfaces.DirectiveNode)
    _assertEqualDirectiveComponents(first, second)

def assertEqualBlock(first, second):
    """ Equality assertion for BlockNode """

    # first was checked in the assertEqual method
    assert isinstance(first, interfaces.BlockNode)
    assert isinstance(second, interfaces.BlockNode)
    _assertEqualDirectiveComponents(first, second)
    # Children cannot be asserted, because Augeas implementation will not
    # prepopulate the sequence of children.
    # assert len(first.children) == len(second.children)

def isPass(first, second):
    """ Checks if either first or second holds the assertion pass value """

    if isinstance(first, tuple) or isinstance(first, list):
        if PASS in first:
            return True
    if isinstance(second, tuple) or isinstance(second, list):
        if PASS in second:
            return True
    if PASS in [first, second]:
        return True
    return False

def isPassNodeList(nodelist):
    """ Checks if a ParserNode in the nodelist should pass the assertion,
    this function is used for results of find_* methods. Unimplemented find_*
    methods should return a sequence containing a single ParserNode instance
    with assertion pass string."""

    try:
        node = nodelist[0]
    except IndexError:
        node = None

    if not node:
        # Empty result means that the method is implemented
        return False

    if isinstance(node, interfaces.BlockNode):
        return _isPassDirective(node)
    if isinstance(node, interfaces.DirectiveNode):
        return _isPassDirective(node)
    return _isPassComment(node)

def _isPassDirective(block):
    """ Checks if BlockNode or DirectiveNode should pass the assertion """

    if block.name == PASS:
        return True
    if PASS in block.parameters:
        return True
    if block.filepath == PASS:
        return True
    return False

def _isPassComment(comment):
    """ Checks if CommentNode should pass the assertion """

    if comment.comment == PASS:
        return True
    if comment.filepath == PASS:
        return True
    return False

def assertSimple(first, second):
    """ Simple assertion """
    if not isPass(first, second):
        assert first == second

def assertSimpleList(first, second):
    """ Simple assertion that lists contain the same objects. This needs to
    be used when there's uncertainty about the ordering of the list. """

    if not isPass(first, second):
        if first:
            for f in first:
                assert f in second
