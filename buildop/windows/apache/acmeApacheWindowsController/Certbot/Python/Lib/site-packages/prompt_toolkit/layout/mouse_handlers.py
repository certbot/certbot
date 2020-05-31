from collections import defaultdict
from itertools import product
from typing import Callable, DefaultDict, Tuple

from prompt_toolkit.mouse_events import MouseEvent

__all__ = [
    "MouseHandlers",
]


class MouseHandlers:
    """
    Two dimensional raster of callbacks for mouse events.
    """

    def __init__(self) -> None:
        def dummy_callback(mouse_event: MouseEvent) -> None:
            """
            :param mouse_event: `MouseEvent` instance.
            """

        # Map (x,y) tuples to handlers.
        self.mouse_handlers: DefaultDict[
            Tuple[int, int], Callable[[MouseEvent], None]
        ] = defaultdict(lambda: dummy_callback)

    def set_mouse_handler_for_range(
        self,
        x_min: int,
        x_max: int,
        y_min: int,
        y_max: int,
        handler: Callable[[MouseEvent], None],
    ) -> None:
        """
        Set mouse handler for a region.
        """
        for x, y in product(range(x_min, x_max), range(y_min, y_max)):
            self.mouse_handlers[x, y] = handler
