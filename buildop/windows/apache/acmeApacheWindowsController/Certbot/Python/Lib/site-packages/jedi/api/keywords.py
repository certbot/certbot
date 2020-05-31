import pydoc

from jedi.inference.utils import ignored
from jedi.inference.names import AbstractArbitraryName

try:
    from pydoc_data import topics as pydoc_topics
except ImportError:
    # Python 2
    try:
        import pydoc_topics
    except ImportError:
        # This is for Python 3 embeddable version, which dont have
        # pydoc_data module in its file python3x.zip.
        pydoc_topics = None


class KeywordName(AbstractArbitraryName):
    api_type = u'keyword'

    def py__doc__(self):
        return imitate_pydoc(self.string_name)


def imitate_pydoc(string):
    """
    It's not possible to get the pydoc's without starting the annoying pager
    stuff.
    """
    if pydoc_topics is None:
        return ''

    # str needed because of possible unicode stuff in py2k (pydoc doesn't work
    # with unicode strings)
    string = str(string)
    h = pydoc.help
    with ignored(KeyError):
        # try to access symbols
        string = h.symbols[string]
        string, _, related = string.partition(' ')

    def get_target(s):
        return h.topics.get(s, h.keywords.get(s))

    while isinstance(string, str):
        string = get_target(string)

    try:
        # is a tuple now
        label, related = string
    except TypeError:
        return ''

    try:
        return pydoc_topics.topics[label].strip() if pydoc_topics else ''
    except KeyError:
        return ''
