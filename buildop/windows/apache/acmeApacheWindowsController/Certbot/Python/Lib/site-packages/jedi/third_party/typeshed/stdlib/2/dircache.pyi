# Source: https://hg.python.org/cpython/file/2.7/Lib/dircache.py

from typing import List, MutableSequence, Text, Union

def reset() -> None: ...
def listdir(path: Text) -> List[str]: ...

opendir = listdir

def annotate(head: Text, list: Union[MutableSequence[str], MutableSequence[Text], MutableSequence[Union[str, Text]]]) -> None: ...
