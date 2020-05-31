from typing import Any, Optional, List, Type

import threading
import sys
import weakref
import array
import itertools

from multiprocessing import TimeoutError, cpu_count
from multiprocessing.dummy.connection import Pipe
from threading import Lock, RLock, Semaphore, BoundedSemaphore
from threading import Event
from Queue import Queue


class DummyProcess(threading.Thread):
    _children: weakref.WeakKeyDictionary[Any, Any]
    _parent: threading.Thread
    _pid: None
    _start_called: bool
    def __init__(self, group=..., target=..., name=..., args=..., kwargs=...) -> None: ...
    @property
    def exitcode(self) -> Optional[int]: ...


Process = DummyProcess

# This should be threading._Condition but threading.pyi exports it as Condition
class Condition(threading.Condition):
    notify_all: Any

class Namespace(object):
    def __init__(self, **kwds) -> None: ...

class Value(object):
    _typecode: Any
    _value: Any
    value: Any
    def __init__(self, typecode, value, lock=...) -> None: ...
    def _get(self) -> Any: ...
    def _set(self, value) -> None: ...

JoinableQueue = Queue

def Array(typecode, sequence, lock=...) -> array.array[Any]: ...
def Manager() -> Any: ...
def Pool(processes=..., initializer=..., initargs=...) -> Any: ...
def active_children() -> List[Any]: ...
def current_process() -> threading.Thread: ...
def freeze_support() -> None: ...
def shutdown() -> None: ...
