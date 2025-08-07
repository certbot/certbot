"""Dual parser node assertions"""
import fnmatch
from typing import Any
from collections.abc import Iterable
from typing import List
from typing import Optional
from typing import Union

from certbot_apache._internal import interfaces
from certbot_apache._internal.interfaces import CommentNode
from certbot_apache._internal.interfaces import DirectiveNode
from certbot_apache._internal.interfaces import ParserNode
from certbot_apache._internal.obj import VirtualHost

PASS = "CERTBOT_PASS_ASSERT"


def assertEqual(first: ParserNode, second: ParserNode) -> None:
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


def assertEqualComment(first: ParserNode, second: ParserNode) -> None:  # pragma: no cover
    """ Equality assertion for CommentNode """

    assert isinstance(first, interfaces.CommentNode)
    assert isinstance(second, interfaces.CommentNode)

    if not isPass(first.comment) and not isPass(second.comment):
        assert first.comment == second.comment


def _assertEqualDirectiveComponents(first: ParserNode,  # pragma: no cover
                                    second: ParserNode) -> None:
    """ Handles assertion for instance variables for DirectiveNode and BlockNode"""

    # Enabled value cannot be asserted, because Augeas implementation
    # is unable to figure that out.
    # assert first.enabled == second.enabled
    assert isinstance(first, DirectiveNode)
    assert isinstance(second, DirectiveNode)

    if not isPass(first.name) and not isPass(second.name):
        assert first.name == second.name

    if not isPass(first.parameters) and not isPass(second.parameters):
        assert first.parameters == second.parameters


def assertEqualDirective(first: ParserNode, second: ParserNode) -> None:
    """ Equality assertion for DirectiveNode """

    assert isinstance(first, interfaces.DirectiveNode)
    assert isinstance(second, interfaces.DirectiveNode)
    _assertEqualDirectiveComponents(first, second)


def isPass(value: Any) -> bool:  # pragma: no cover
    """Checks if the value is set to PASS"""
    if isinstance(value, bool):
        return True
    return PASS in value


def isPassDirective(block: DirectiveNode) -> bool:
    """ Checks if BlockNode or DirectiveNode should pass the assertion """

    if isPass(block.name):
        return True
    if isPass(block.parameters):  # pragma: no cover
        return True
    if isPass(block.filepath):  # pragma: no cover
        return True
    return False


def isPassComment(comment: CommentNode) -> bool:
    """ Checks if CommentNode should pass the assertion """

    if isPass(comment.comment):
        return True
    if isPass(comment.filepath):  # pragma: no cover
        return True
    return False


def isPassNodeList(nodelist: List[Union[DirectiveNode, CommentNode]]) -> bool:  # pragma: no cover
    """ Checks if a ParserNode in the nodelist should pass the assertion,
    this function is used for results of find_* methods. Unimplemented find_*
    methods should return a sequence containing a single ParserNode instance
    with assertion pass string."""

    node: Optional[Union[DirectiveNode, CommentNode]]
    try:
        node = nodelist[0]
    except IndexError:
        node = None

    if not node:  # pragma: no cover
        return False

    if isinstance(node, interfaces.DirectiveNode):
        return isPassDirective(node)
    return isPassComment(node)


def assertEqualSimple(first: Any, second: Any) -> None:
    """ Simple assertion """
    if not isPass(first) and not isPass(second):
        assert first == second


def isEqualVirtualHost(first: VirtualHost, second: VirtualHost) -> bool:
    """
    Checks that two VirtualHost objects are similar. There are some built
    in differences with the implementations: VirtualHost created by ParserNode
    implementation doesn't have "path" defined, as it was used for Augeas path
    and that cannot obviously be used in the future. Similarly the legacy
    version lacks "node" variable, that has a reference to the BlockNode for the
    VirtualHost.
    """
    return (
        first.name == second.name and
        first.aliases == second.aliases and
        first.filep == second.filep and
        first.addrs == second.addrs and
        first.ssl == second.ssl and
        first.enabled == second.enabled and
        first.modmacro == second.modmacro and
        first.ancestor == second.ancestor
    )


def assertEqualPathsList(first: Iterable[str], second: Iterable[str]) -> None:  # pragma: no cover
    """
    Checks that the two lists of file paths match. This assertion allows for wildcard
    paths.
    """
    if any(isPass(path) for path in first):
        return
    if any(isPass(path) for path in second):
        return
    for fpath in first:
        assert any(fnmatch.fnmatch(fpath, spath) for spath in second)
    for spath in second:
        assert any(fnmatch.fnmatch(fpath, spath) for fpath in first)
