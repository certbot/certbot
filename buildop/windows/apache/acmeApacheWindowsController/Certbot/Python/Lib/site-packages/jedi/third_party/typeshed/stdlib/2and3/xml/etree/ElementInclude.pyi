# Stubs for xml.etree.ElementInclude (Python 3.4)

from typing import Union, Optional, Callable
from xml.etree.ElementTree import Element

XINCLUDE: str
XINCLUDE_INCLUDE: str
XINCLUDE_FALLBACK: str

class FatalIncludeError(SyntaxError): ...

def default_loader(href: Union[str, bytes, int], parse: str, encoding: Optional[str] = ...) -> Union[str, Element]: ...

# TODO: loader is of type default_loader ie it takes a callable that has the
# same signature as default_loader. But default_loader has a keyword argument
# Which can't be represented using Callable...
def include(elem: Element, loader: Optional[Callable[..., Union[str, Element]]] = ...) -> None: ...
