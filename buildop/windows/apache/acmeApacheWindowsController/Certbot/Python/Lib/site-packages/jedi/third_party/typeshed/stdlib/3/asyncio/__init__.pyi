import sys
from typing import Type

from asyncio.coroutines import (
    coroutine as coroutine,
    iscoroutinefunction as iscoroutinefunction,
    iscoroutine as iscoroutine,
)
from asyncio.protocols import (
    BaseProtocol as BaseProtocol,
    Protocol as Protocol,
    DatagramProtocol as DatagramProtocol,
    SubprocessProtocol as SubprocessProtocol,
)
from asyncio.streams import (
    StreamReader as StreamReader,
    StreamWriter as StreamWriter,
    StreamReaderProtocol as StreamReaderProtocol,
    open_connection as open_connection,
    start_server as start_server,
)
from asyncio.subprocess import (
    create_subprocess_exec as create_subprocess_exec,
    create_subprocess_shell as create_subprocess_shell,
)
from asyncio.transports import (
    BaseTransport as BaseTransport,
    ReadTransport as ReadTransport,
    WriteTransport as WriteTransport,
    Transport as Transport,
    DatagramTransport as DatagramTransport,
    SubprocessTransport as SubprocessTransport,
)
from asyncio.futures import (
    Future as Future,
    wrap_future as wrap_future,
)
from asyncio.tasks import (
    FIRST_COMPLETED as FIRST_COMPLETED,
    FIRST_EXCEPTION as FIRST_EXCEPTION,
    ALL_COMPLETED as ALL_COMPLETED,
    as_completed as as_completed,
    ensure_future as ensure_future,
    gather as gather,
    run_coroutine_threadsafe as run_coroutine_threadsafe,
    shield as shield,
    sleep as sleep,
    wait as wait,
    wait_for as wait_for,
    Task as Task,
)
from asyncio.base_events import (
    BaseEventLoop as BaseEventLoop,
    Server as Server
)
from asyncio.events import (
    AbstractEventLoopPolicy as AbstractEventLoopPolicy,
    AbstractEventLoop as AbstractEventLoop,
    AbstractServer as AbstractServer,
    Handle as Handle,
    TimerHandle as TimerHandle,
    get_event_loop_policy as get_event_loop_policy,
    set_event_loop_policy as set_event_loop_policy,
    get_event_loop as get_event_loop,
    set_event_loop as set_event_loop,
    new_event_loop as new_event_loop,
    get_child_watcher as get_child_watcher,
    set_child_watcher as set_child_watcher,
)
from asyncio.queues import (
    Queue as Queue,
    PriorityQueue as PriorityQueue,
    LifoQueue as LifoQueue,
    QueueFull as QueueFull,
    QueueEmpty as QueueEmpty,
)
from asyncio.locks import (
    Lock as Lock,
    Event as Event,
    Condition as Condition,
    Semaphore as Semaphore,
    BoundedSemaphore as BoundedSemaphore,
)

from asyncio.futures import isfuture as isfuture
from asyncio.events import (
    _set_running_loop as _set_running_loop,
    _get_running_loop as _get_running_loop,
)
if sys.platform == 'win32':
    from asyncio.windows_events import *
else:
    from asyncio.streams import (
        open_unix_connection as open_unix_connection,
        start_unix_server as start_unix_server,
    )
    DefaultEventLoopPolicy: Type[AbstractEventLoopPolicy]

if sys.version_info >= (3, 7):
    from asyncio.events import (
        get_running_loop as get_running_loop,
    )
    from asyncio.tasks import (
        all_tasks as all_tasks,
        create_task as create_task,
        current_task as current_task,
    )
    from asyncio.runners import (
        run as run,
    )

if sys.platform != 'win32':
    # This is already imported above on Windows.
    SelectorEventLoop: Type[AbstractEventLoop]

# TODO: AbstractChildWatcher (UNIX only)

if sys.version_info >= (3, 8):
    from asyncio.exceptions import (
        CancelledError as CancelledError,
        IncompleteReadError as IncompleteReadError,
        InvalidStateError as InvalidStateError,
        LimitOverrunError as LimitOverrunError,
        SendfileNotAvailableError as SendfileNotAvailableError,
        TimeoutError as TimeoutError,
    )
else:
    from asyncio.events import (
        SendfileNotAvailableError as SendfileNotAvailableError
    )
    from asyncio.futures import (
        CancelledError as CancelledError,
        TimeoutError as TimeoutError,
        InvalidStateError as InvalidStateError,
    )
    from asyncio.streams import (
        IncompleteReadError as IncompleteReadError,
        LimitOverrunError as LimitOverrunError,
    )
