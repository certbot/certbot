"""ParserNode utils"""


def validate_kwargs(kwargs, required_names):
    """
    Ensures that the kwargs dict has all the expected values.

    :param dict kwargs: Dictionary of keyword arguments to validate.
    :param list required_names: List of required parameter names.
    """

    validated_kwargs = dict()
    for name in required_names:
        try:
            validated_kwargs[name] = kwargs.pop(name)
        except KeyError:
            raise TypeError("Required keyword argument: {} undefined.".format(name))

    # Raise exception if unknown key word arguments are found.
    if kwargs:
        unknown = ", ".join(kwargs.keys())
        raise TypeError("Unknown keyword argument(s): {}".format(unknown))
    return validated_kwargs


def parsernode_kwargs(kwargs):
    """
    Validates keyword arguments for ParserNode.

    :param dict kwargs: Keyword argument dictionary to validate.

    :returns: Tuple of validated and prepared arguments.
    """
    kwargs.setdefault("dirty", False)
    kwargs = validate_kwargs(kwargs, ["ancestor", "dirty", "filepath"])
    return kwargs["ancestor"], kwargs["dirty"], kwargs["filepath"]


def commentnode_kwargs(kwargs):
    """
    Validates keyword arguments for CommentNode and sets the default values for
    optional kwargs.

    :param dict kwargs: Keyword argument dictionary to validate.

    :returns: Tuple of validated and prepared arguments and the remaining kwargs.
    """
    kwargs.setdefault("dirty", False)
    kwargs = validate_kwargs(kwargs, ["ancestor", "dirty", "filepath", "comment"])

    comment = kwargs.pop("comment")
    return comment, kwargs


def node_kwargs(kwargs):
    """
    Validates keyword arguments for DirectiveNode and BlockNode and sets the
    default values for optional kwargs.

    :param dict kwargs: Keyword argument dictionary to validate.

    :returns: Tuple of validated and prepared arguments.
    """
    kwargs.setdefault("dirty", False)
    kwargs.setdefault("enabled", True)
    kwargs.setdefault("parameters", ())

    kwargs = validate_kwargs(kwargs, ["ancestor", "dirty", "filepath", "name",
                                      "parameters", "enabled"])

    name = kwargs.pop("name")
    parameters = kwargs.pop("parameters")
    enabled = kwargs.pop("enabled")
    return name, parameters, enabled, kwargs
