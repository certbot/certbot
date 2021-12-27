"""ACME utilities."""
import re
from typing import Any
from typing import Callable
from typing import Dict
from typing import Mapping


def map_keys(dikt: Mapping[Any, Any], func: Callable[[Any], Any]) -> Dict[Any, Any]:
    """Map dictionary keys."""
    return {func(key): value for key, value in dikt.items()}


# this is taken from python-requests:
def parse_header_links(value):
    """Return a list of parsed link headers proxies.

    i.e. Link: <http:/.../front.jpeg>; rel=front; type="image/jpeg",<http://.../back.jpeg>; rel=back;type="image/jpeg"

    :rtype: list
    """

    links = []

    replace_chars = ' \'"'

    value = value.strip(replace_chars)
    if not value:
        return links

    for val in re.split(', *<', value):
        try:
            url, params = val.split(';', 1)
        except ValueError:
            url, params = val, ''

        link = {'url': url.strip('<> \'"')}

        for param in params.split(';'):
            try:
                key, value = param.split('=')
            except ValueError:
                break

            link[key.strip(replace_chars)] = value.strip(replace_chars)

        links.append(link)

    return links

def extract_links(response):
    result = {}
    value = response.headers.get('Link')
    if not value:
        return result
    links = parse_header_links(value)
    for link in links:
        key = link.get('rel')
        if key:
            result[key] = link
    return result
