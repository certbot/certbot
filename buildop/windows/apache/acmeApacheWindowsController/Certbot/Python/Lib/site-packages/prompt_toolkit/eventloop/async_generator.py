"""
Implementation for async generators.
"""
from asyncio import Queue, get_event_loop
from typing import AsyncGenerator, Callable, Iterable, TypeVar, Union

from .utils import run_in_executor_with_context

__all__ = [
    "generator_to_async_generator",
]


_T = TypeVar("_T")


class _Done:
    pass


async def generator_to_async_generator(
    get_iterable: Callable[[], Iterable[_T]]
) -> AsyncGenerator[_T, None]:
    """
    Turn a generator or iterable into an async generator.

    This works by running the generator in a background thread.

    :param get_iterable: Function that returns a generator or iterable when
        called.
    """
    quitting = False
    _done = _Done()
    q: Queue[Union[_T, _Done]] = Queue()
    loop = get_event_loop()

    def runner() -> None:
        """
        Consume the generator in background thread.
        When items are received, they'll be pushed to the queue.
        """
        try:
            for item in get_iterable():
                loop.call_soon_threadsafe(q.put_nowait, item)

                # When this async generator was cancelled (closed), stop this
                # thread.
                if quitting:
                    break

        finally:
            loop.call_soon_threadsafe(q.put_nowait, _done)

    # Start background thread.
    run_in_executor_with_context(runner)

    try:
        while True:
            item = await q.get()
            if isinstance(item, _Done):
                break
            else:
                yield item
    finally:
        # When this async generator is closed (GeneratorExit exception, stop
        # the background thread as well. - we don't need that anymore.)
        quitting = True
