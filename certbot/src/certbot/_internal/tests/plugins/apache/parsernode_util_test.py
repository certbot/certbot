""" Tests for ParserNode utils """
import sys

import pytest

from certbot._internal.plugins.apache import parsernode_util as util


def _setup_parsernode():
    """ Sets up kwargs dict for ParserNode """
    return {
        "ancestor": None,
        "dirty": False,
        "filepath": "/tmp",
    }

def _setup_commentnode():
    """ Sets up kwargs dict for CommentNode """

    pn = _setup_parsernode()
    pn["comment"] = "x"
    return pn

def _setup_directivenode():
    """ Sets up kwargs dict for DirectiveNode """

    pn = _setup_parsernode()
    pn["name"] = "Name"
    pn["parameters"] = ("first",)
    pn["enabled"] = True
    return pn

def test_unknown_parameter():
    params = _setup_parsernode()
    params["unknown"] = "unknown"
    with pytest.raises(TypeError):
        util.parsernode_kwargs(params)

    params = _setup_commentnode()
    params["unknown"] = "unknown"
    with pytest.raises(TypeError):
        util.commentnode_kwargs(params)

    params = _setup_directivenode()
    params["unknown"] = "unknown"
    with pytest.raises(TypeError):
        util.directivenode_kwargs(params)

def test_parsernode():
    params = _setup_parsernode()
    ctrl = _setup_parsernode()

    ancestor, dirty, filepath, metadata = util.parsernode_kwargs(params)
    assert ancestor == ctrl["ancestor"]
    assert dirty == ctrl["dirty"]
    assert filepath == ctrl["filepath"]
    assert metadata == {}

def test_parsernode_from_metadata():
    params = _setup_parsernode()
    params.pop("filepath")
    md = {"some": "value"}
    params["metadata"] = md

    # Just testing that error from missing required parameters is not raised
    _, _, _, metadata = util.parsernode_kwargs(params)
    assert metadata == md

def test_commentnode():
    params = _setup_commentnode()
    ctrl = _setup_commentnode()

    comment, _ = util.commentnode_kwargs(params)
    assert comment == ctrl["comment"]

def test_commentnode_from_metadata():
    params = _setup_commentnode()
    params.pop("comment")
    params["metadata"] = {}

    # Just testing that error from missing required parameters is not raised
    util.commentnode_kwargs(params)

def test_directivenode():
    params = _setup_directivenode()
    ctrl = _setup_directivenode()

    name, parameters, enabled, _ = util.directivenode_kwargs(params)
    assert name == ctrl["name"]
    assert parameters == ctrl["parameters"]
    assert enabled == ctrl["enabled"]

def test_directivenode_from_metadata():
    params = _setup_directivenode()
    params.pop("filepath")
    params.pop("name")
    params["metadata"] = {"irrelevant": "value"}

    # Just testing that error from missing required parameters is not raised
    util.directivenode_kwargs(params)

def test_missing_required():
    c_params = _setup_commentnode()
    c_params.pop("comment")
    with pytest.raises(TypeError):
        util.commentnode_kwargs(c_params)

    d_params = _setup_directivenode()
    d_params.pop("ancestor")
    with pytest.raises(TypeError):
        util.directivenode_kwargs(d_params)

    p_params = _setup_parsernode()
    p_params.pop("filepath")
    with pytest.raises(TypeError):
        util.parsernode_kwargs(p_params)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
