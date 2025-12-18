"""ParserNode utils"""
from typing import Any
from typing import Iterable
from typing import Optional

from certbot._internal.plugins.apache.interfaces import ParserNode


def validate_kwargs(kwargs: dict[str, Any], required_names: Iterable[str]) -> dict[str, Any]:
    """
    Ensures that the kwargs dict has all the expected values. This function modifies
    the kwargs dictionary, and hence the returned dictionary should be used instead
    in the caller function instead of the original kwargs.

    :param dict kwargs: Dictionary of keyword arguments to validate.
    :param list required_names: List of required parameter names.
    """

    validated_kwargs: dict[str, Any] = {}
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


def parsernode_kwargs(kwargs: dict[str, Any]
                      ) -> tuple[Optional[ParserNode], bool, Optional[str], dict[str, Any]]:
    """
    Validates keyword arguments for ParserNode. This function modifies the kwargs
    dictionary, and hence the returned dictionary should be used instead in the
    caller function instead of the original kwargs.

    If metadata is provided, the otherwise required argument "filepath" may be
    omitted if the implementation is able to extract its value from the metadata.
    This usecase is handled within this function. Filepath defaults to None.

    :param dict kwargs: Keyword argument dictionary to validate.

    :returns: Tuple of validated and prepared arguments.
    """

    # As many values of ParserNode instances can be derived from the metadata,
    # (ancestor being a common exception here) make sure we permit it here as well.
    if "metadata" in kwargs:
        # Filepath can be derived from the metadata in Augeas implementation.
        # Default is None, as in this case the responsibility of populating this
        # variable lies on the implementation.
        kwargs.setdefault("filepath", None)

    kwargs.setdefault("dirty", False)
    kwargs.setdefault("metadata", {})

    kwargs = validate_kwargs(kwargs, ["ancestor", "dirty", "filepath", "metadata"])
    return kwargs["ancestor"], kwargs["dirty"], kwargs["filepath"], kwargs["metadata"]


def commentnode_kwargs(kwargs: dict[str, Any]) -> tuple[Optional[str], dict[str, str]]:
    """
    Validates keyword arguments for CommentNode and sets the default values for
    optional kwargs. This function modifies the kwargs dictionary, and hence the
    returned dictionary should be used instead in the caller function instead of
    the original kwargs.

    If metadata is provided, the otherwise required argument "comment" may be
    omitted if the implementation is able to extract its value from the metadata.
    This usecase is handled within this function.

    :param dict kwargs: Keyword argument dictionary to validate.

    :returns: Tuple of validated and prepared arguments and ParserNode kwargs.
    """

    # As many values of ParserNode instances can be derived from the metadata,
    # (ancestor being a common exception here) make sure we permit it here as well.
    if "metadata" in kwargs:
        kwargs.setdefault("comment", None)
        # Filepath can be derived from the metadata in Augeas implementation.
        # Default is None, as in this case the responsibility of populating this
        # variable lies on the implementation.
        kwargs.setdefault("filepath", None)

    kwargs.setdefault("dirty", False)
    kwargs.setdefault("metadata", {})

    kwargs = validate_kwargs(kwargs, ["ancestor", "dirty", "filepath", "comment",
                                      "metadata"])

    comment = kwargs.pop("comment")
    return comment, kwargs


def directivenode_kwargs(kwargs: dict[str, Any]
                         ) -> tuple[Optional[str], tuple[str, ...], bool, dict[str, Any]]:
    """
    Validates keyword arguments for DirectiveNode and BlockNode and sets the
    default values for optional kwargs. This function modifies the kwargs
    dictionary, and hence the returned dictionary should be used instead in the
    caller function instead of the original kwargs.

    If metadata is provided, the otherwise required argument "name" may be
    omitted if the implementation is able to extract its value from the metadata.
    This usecase is handled within this function.

    :param dict kwargs: Keyword argument dictionary to validate.

    :returns: Tuple of validated and prepared arguments and ParserNode kwargs.
    """

    # As many values of ParserNode instances can be derived from the metadata,
    # (ancestor being a common exception here) make sure we permit it here as well.
    if "metadata" in kwargs:
        kwargs.setdefault("name", None)
        # Filepath can be derived from the metadata in Augeas implementation.
        # Default is None, as in this case the responsibility of populating this
        # variable lies on the implementation.
        kwargs.setdefault("filepath", None)

    kwargs.setdefault("dirty", False)
    kwargs.setdefault("enabled", True)
    kwargs.setdefault("parameters", ())
    kwargs.setdefault("metadata", {})

    kwargs = validate_kwargs(kwargs, ["ancestor", "dirty", "filepath", "name",
                                      "parameters", "enabled", "metadata"])

    name = kwargs.pop("name")
    parameters = kwargs.pop("parameters")
    enabled = kwargs.pop("enabled")
    return name, parameters, enabled, kwargs
