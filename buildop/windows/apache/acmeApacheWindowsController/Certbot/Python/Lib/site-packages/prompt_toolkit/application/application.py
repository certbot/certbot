import asyncio
import os
import re
import signal
import sys
import time
from asyncio import (
    AbstractEventLoop,
    CancelledError,
    Future,
    Task,
    ensure_future,
    get_event_loop,
    new_event_loop,
    set_event_loop,
    sleep,
)
from subprocess import Popen
from traceback import format_tb
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    Generic,
    Hashable,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
    overload,
)

from prompt_toolkit.buffer import Buffer
from prompt_toolkit.cache import SimpleCache
from prompt_toolkit.clipboard import Clipboard, InMemoryClipboard
from prompt_toolkit.enums import EditingMode
from prompt_toolkit.eventloop import (
    get_traceback_from_context,
    run_in_executor_with_context,
)
from prompt_toolkit.eventloop.utils import call_soon_threadsafe
from prompt_toolkit.filters import Condition, Filter, FilterOrBool, to_filter
from prompt_toolkit.formatted_text import AnyFormattedText
from prompt_toolkit.input.base import Input
from prompt_toolkit.input.typeahead import get_typeahead, store_typeahead
from prompt_toolkit.key_binding.bindings.page_navigation import (
    load_page_navigation_bindings,
)
from prompt_toolkit.key_binding.defaults import load_key_bindings
from prompt_toolkit.key_binding.emacs_state import EmacsState
from prompt_toolkit.key_binding.key_bindings import (
    Binding,
    ConditionalKeyBindings,
    GlobalOnlyKeyBindings,
    KeyBindings,
    KeyBindingsBase,
    KeysTuple,
    merge_key_bindings,
)
from prompt_toolkit.key_binding.key_processor import KeyPressEvent, KeyProcessor
from prompt_toolkit.key_binding.vi_state import ViState
from prompt_toolkit.keys import Keys
from prompt_toolkit.layout.containers import Container, Window
from prompt_toolkit.layout.controls import BufferControl, UIControl
from prompt_toolkit.layout.dummy import create_dummy_layout
from prompt_toolkit.layout.layout import Layout, walk
from prompt_toolkit.output import ColorDepth, Output
from prompt_toolkit.renderer import Renderer, print_formatted_text
from prompt_toolkit.search import SearchState
from prompt_toolkit.styles import (
    BaseStyle,
    DummyStyle,
    DummyStyleTransformation,
    DynamicStyle,
    StyleTransformation,
    default_pygments_style,
    default_ui_style,
    merge_styles,
)
from prompt_toolkit.utils import Event, in_main_thread

from .current import get_app_session, set_app
from .run_in_terminal import in_terminal, run_in_terminal

try:
    import contextvars
except ImportError:
    import prompt_toolkit.eventloop.dummy_contextvars as contextvars  # type: ignore


__all__ = [
    "Application",
]


E = KeyPressEvent
_AppResult = TypeVar("_AppResult")
ApplicationEventHandler = Callable[["Application[_AppResult]"], None]


class Application(Generic[_AppResult]):
    """
    The main Application class!
    This glues everything together.

    :param layout: A :class:`~prompt_toolkit.layout.Layout` instance.
    :param key_bindings:
        :class:`~prompt_toolkit.key_binding.KeyBindingsBase` instance for
        the key bindings.
    :param clipboard: :class:`~prompt_toolkit.clipboard.Clipboard` to use.
    :param on_abort: What to do when Control-C is pressed.
    :param on_exit: What to do when Control-D is pressed.
    :param full_screen: When True, run the application on the alternate screen buffer.
    :param color_depth: Any :class:`~.ColorDepth` value, a callable that
        returns a :class:`~.ColorDepth` or `None` for default.
    :param erase_when_done: (bool) Clear the application output when it finishes.
    :param reverse_vi_search_direction: Normally, in Vi mode, a '/' searches
        forward and a '?' searches backward. In Readline mode, this is usually
        reversed.
    :param min_redraw_interval: Number of seconds to wait between redraws. Use
        this for applications where `invalidate` is called a lot. This could cause
        a lot of terminal output, which some terminals are not able to process.

        `None` means that every `invalidate` will be scheduled right away
        (which is usually fine).

        When one `invalidate` is called, but a scheduled redraw of a previous
        `invalidate` call has not been executed yet, nothing will happen in any
        case.

    :param max_render_postpone_time: When there is high CPU (a lot of other
        scheduled calls), postpone the rendering max x seconds.  '0' means:
        don't postpone. '.5' means: try to draw at least twice a second.

    :param refresh_interval: Automatically invalidate the UI every so many
        seconds. When `None` (the default), only invalidate when `invalidate`
        has been called.

    Filters:

    :param mouse_support: (:class:`~prompt_toolkit.filters.Filter` or
        boolean). When True, enable mouse support.
    :param paste_mode: :class:`~prompt_toolkit.filters.Filter` or boolean.
    :param editing_mode: :class:`~prompt_toolkit.enums.EditingMode`.

    :param enable_page_navigation_bindings: When `True`, enable the page
        navigation key bindings. These include both Emacs and Vi bindings like
        page-up, page-down and so on to scroll through pages. Mostly useful for
        creating an editor or other full screen applications. Probably, you
        don't want this for the implementation of a REPL. By default, this is
        enabled if `full_screen` is set.

    Callbacks (all of these should accept a
    :class:`~prompt_toolkit.application.Application` object as input.)

    :param on_reset: Called during reset.
    :param on_invalidate: Called when the UI has been invalidated.
    :param before_render: Called right before rendering.
    :param after_render: Called right after rendering.

    I/O:
    (Note that the preferred way to change the input/output is by creating an
    `AppSession` with the required input/output objects. If you need multiple
    applications running at the same time, you have to create a separate
    `AppSession` using a `with create_app_session():` block.

    :param input: :class:`~prompt_toolkit.input.Input` instance.
    :param output: :class:`~prompt_toolkit.output.Output` instance. (Probably
                   Vt100_Output or Win32Output.)

    Usage:

        app = Application(...)
        app.run()

        # Or
        await app.run_async()
    """

    def __init__(
        self,
        layout: Optional[Layout] = None,
        style: Optional[BaseStyle] = None,
        include_default_pygments_style: FilterOrBool = True,
        style_transformation: Optional[StyleTransformation] = None,
        key_bindings: Optional[KeyBindingsBase] = None,
        clipboard: Optional[Clipboard] = None,
        full_screen: bool = False,
        color_depth: Union[
            ColorDepth, Callable[[], Union[ColorDepth, None]], None
        ] = None,
        mouse_support: FilterOrBool = False,
        enable_page_navigation_bindings: Optional[
            FilterOrBool
        ] = None,  # Can be None, True or False.
        paste_mode: FilterOrBool = False,
        editing_mode: EditingMode = EditingMode.EMACS,
        erase_when_done: bool = False,
        reverse_vi_search_direction: FilterOrBool = False,
        min_redraw_interval: Union[float, int, None] = None,
        max_render_postpone_time: Union[float, int, None] = 0.01,
        refresh_interval: Optional[float] = None,
        on_reset: Optional[ApplicationEventHandler] = None,
        on_invalidate: Optional[ApplicationEventHandler] = None,
        before_render: Optional[ApplicationEventHandler] = None,
        after_render: Optional[ApplicationEventHandler] = None,
        # I/O.
        input: Optional[Input] = None,
        output: Optional[Output] = None,
    ):

        # If `enable_page_navigation_bindings` is not specified, enable it in
        # case of full screen applications only. This can be overridden by the user.
        if enable_page_navigation_bindings is None:
            enable_page_navigation_bindings = Condition(lambda: self.full_screen)

        paste_mode = to_filter(paste_mode)
        mouse_support = to_filter(mouse_support)
        reverse_vi_search_direction = to_filter(reverse_vi_search_direction)
        enable_page_navigation_bindings = to_filter(enable_page_navigation_bindings)
        include_default_pygments_style = to_filter(include_default_pygments_style)

        if layout is None:
            layout = create_dummy_layout()

        if style_transformation is None:
            style_transformation = DummyStyleTransformation()

        self.style = style
        self.style_transformation = style_transformation

        # Key bindings.
        self.key_bindings = key_bindings
        self._default_bindings = load_key_bindings()
        self._page_navigation_bindings = load_page_navigation_bindings()

        self.layout = layout
        self.clipboard = clipboard or InMemoryClipboard()
        self.full_screen: bool = full_screen
        self._color_depth = color_depth
        self.mouse_support = mouse_support

        self.paste_mode = paste_mode
        self.editing_mode = editing_mode
        self.erase_when_done = erase_when_done
        self.reverse_vi_search_direction = reverse_vi_search_direction
        self.enable_page_navigation_bindings = enable_page_navigation_bindings
        self.min_redraw_interval = min_redraw_interval
        self.max_render_postpone_time = max_render_postpone_time
        self.refresh_interval = refresh_interval

        # Events.
        self.on_invalidate = Event(self, on_invalidate)
        self.on_reset = Event(self, on_reset)
        self.before_render = Event(self, before_render)
        self.after_render = Event(self, after_render)

        # I/O.
        session = get_app_session()
        self.output = output or session.output
        self.input = input or session.input

        # List of 'extra' functions to execute before a Application.run.
        self.pre_run_callables: List[Callable[[], None]] = []

        self._is_running = False
        self.future: Optional[Future[_AppResult]] = None
        self.loop: Optional[AbstractEventLoop] = None
        self.context: Optional[contextvars.Context] = None

        #: Quoted insert. This flag is set if we go into quoted insert mode.
        self.quoted_insert = False

        #: Vi state. (For Vi key bindings.)
        self.vi_state = ViState()
        self.emacs_state = EmacsState()

        #: When to flush the input (For flushing escape keys.) This is important
        #: on terminals that use vt100 input. We can't distinguish the escape
        #: key from for instance the left-arrow key, if we don't know what follows
        #: after "\x1b". This little timer will consider "\x1b" to be escape if
        #: nothing did follow in this time span.
        #: This seems to work like the `ttimeoutlen` option in Vim.
        self.ttimeoutlen = 0.5  # Seconds.

        #: Like Vim's `timeoutlen` option. This can be `None` or a float.  For
        #: instance, suppose that we have a key binding AB and a second key
        #: binding A. If the uses presses A and then waits, we don't handle
        #: this binding yet (unless it was marked 'eager'), because we don't
        #: know what will follow. This timeout is the maximum amount of time
        #: that we wait until we call the handlers anyway. Pass `None` to
        #: disable this timeout.
        self.timeoutlen = 1.0

        #: The `Renderer` instance.
        # Make sure that the same stdout is used, when a custom renderer has been passed.
        self._merged_style = self._create_merged_style(include_default_pygments_style)

        self.renderer = Renderer(
            self._merged_style,
            self.output,
            self.input,
            full_screen=full_screen,
            mouse_support=mouse_support,
            cpr_not_supported_callback=self.cpr_not_supported_callback,
        )

        #: Render counter. This one is increased every time the UI is rendered.
        #: It can be used as a key for caching certain information during one
        #: rendering.
        self.render_counter = 0

        # Invalidate flag. When 'True', a repaint has been scheduled.
        self._invalidated = False
        self._invalidate_events: List[
            Event[object]
        ] = []  # Collection of 'invalidate' Event objects.
        self._last_redraw_time = 0.0  # Unix timestamp of last redraw. Used when
        # `min_redraw_interval` is given.

        #: The `InputProcessor` instance.
        self.key_processor = KeyProcessor(_CombinedRegistry(self))

        # If `run_in_terminal` was called. This will point to a `Future` what will be
        # set at the point when the previous run finishes.
        self._running_in_terminal = False
        self._running_in_terminal_f: Optional[Future[None]] = None

        # Trigger initialize callback.
        self.reset()

    def _create_merged_style(self, include_default_pygments_style: Filter) -> BaseStyle:
        """
        Create a `Style` object that merges the default UI style, the default
        pygments style, and the custom user style.
        """
        dummy_style = DummyStyle()
        pygments_style = default_pygments_style()

        @DynamicStyle
        def conditional_pygments_style() -> BaseStyle:
            if include_default_pygments_style():
                return pygments_style
            else:
                return dummy_style

        return merge_styles(
            [
                default_ui_style(),
                conditional_pygments_style,
                DynamicStyle(lambda: self.style),
            ]
        )

    @property
    def color_depth(self) -> ColorDepth:
        """
        Active :class:`.ColorDepth`.
        """
        depth = self._color_depth

        if callable(depth):
            return depth() or ColorDepth.default()

        if depth is None:
            return ColorDepth.default()

        return depth

    @property
    def current_buffer(self) -> Buffer:
        """
        The currently focused :class:`~.Buffer`.

        (This returns a dummy :class:`.Buffer` when none of the actual buffers
        has the focus. In this case, it's really not practical to check for
        `None` values or catch exceptions every time.)
        """
        return self.layout.current_buffer or Buffer(
            name="dummy-buffer"
        )  # Dummy buffer.

    @property
    def current_search_state(self) -> SearchState:
        """
        Return the current :class:`.SearchState`. (The one for the focused
        :class:`.BufferControl`.)
        """
        ui_control = self.layout.current_control
        if isinstance(ui_control, BufferControl):
            return ui_control.search_state
        else:
            return SearchState()  # Dummy search state.  (Don't return None!)

    def reset(self) -> None:
        """
        Reset everything, for reading the next input.
        """
        # Notice that we don't reset the buffers. (This happens just before
        # returning, and when we have multiple buffers, we clearly want the
        # content in the other buffers to remain unchanged between several
        # calls of `run`. (And the same is true for the focus stack.)

        self.exit_style = ""

        self.background_tasks: List[Task[None]] = []

        self.renderer.reset()
        self.key_processor.reset()
        self.layout.reset()
        self.vi_state.reset()
        self.emacs_state.reset()

        # Trigger reset event.
        self.on_reset.fire()

        # Make sure that we have a 'focusable' widget focused.
        # (The `Layout` class can't determine this.)
        layout = self.layout

        if not layout.current_control.is_focusable():
            for w in layout.find_all_windows():
                if w.content.is_focusable():
                    layout.current_window = w
                    break

    def invalidate(self) -> None:
        """
        Thread safe way of sending a repaint trigger to the input event loop.
        """
        if not self._is_running:
            # Don't schedule a redraw if we're not running.
            # Otherwise, `get_event_loop()` in `call_soon_threadsafe` can fail.
            # See: https://github.com/dbcli/mycli/issues/797
            return

        # Never schedule a second redraw, when a previous one has not yet been
        # executed. (This should protect against other threads calling
        # 'invalidate' many times, resulting in 100% CPU.)
        if self._invalidated:
            return
        else:
            self._invalidated = True

        # Trigger event.
        self.on_invalidate.fire()

        def redraw() -> None:
            self._invalidated = False
            self._redraw()

        def schedule_redraw() -> None:
            call_soon_threadsafe(
                redraw, max_postpone_time=self.max_render_postpone_time, loop=self.loop
            )

        if self.min_redraw_interval:
            # When a minimum redraw interval is set, wait minimum this amount
            # of time between redraws.
            diff = time.time() - self._last_redraw_time
            if diff < self.min_redraw_interval:

                async def redraw_in_future() -> None:
                    await sleep(cast(float, self.min_redraw_interval) - diff)
                    schedule_redraw()

                self.create_background_task(redraw_in_future())
            else:
                schedule_redraw()
        else:
            schedule_redraw()

    @property
    def invalidated(self) -> bool:
        " True when a redraw operation has been scheduled. "
        return self._invalidated

    def _redraw(self, render_as_done: bool = False) -> None:
        """
        Render the command line again. (Not thread safe!) (From other threads,
        or if unsure, use :meth:`.Application.invalidate`.)

        :param render_as_done: make sure to put the cursor after the UI.
        """

        def run_in_context() -> None:
            # Only draw when no sub application was started.
            if self._is_running and not self._running_in_terminal:
                if self.min_redraw_interval:
                    self._last_redraw_time = time.time()

                # Render
                self.render_counter += 1
                self.before_render.fire()

                if render_as_done:
                    if self.erase_when_done:
                        self.renderer.erase()
                    else:
                        # Draw in 'done' state and reset renderer.
                        self.renderer.render(self, self.layout, is_done=render_as_done)
                else:
                    self.renderer.render(self, self.layout)

                self.layout.update_parents_relations()

                # Fire render event.
                self.after_render.fire()

                self._update_invalidate_events()

        # NOTE: We want to make sure this Application is the active one. The
        #       invalidate function is often called from a context where this
        #       application is not the active one. (Like the
        #       `PromptSession._auto_refresh_context`).
        if self.context is not None:
            self.context.run(run_in_context)

    def _start_auto_refresh_task(self) -> None:
        """
        Start a while/true loop in the background for automatic invalidation of
        the UI.
        """
        if self.refresh_interval not in (None, 0):

            async def auto_refresh(refresh_interval) -> None:
                while True:
                    await sleep(refresh_interval)
                    self.invalidate()

            self.create_background_task(auto_refresh(self.refresh_interval))

    def _update_invalidate_events(self) -> None:
        """
        Make sure to attach 'invalidate' handlers to all invalidate events in
        the UI.
        """
        # Remove all the original event handlers. (Components can be removed
        # from the UI.)
        for ev in self._invalidate_events:
            ev -= self._invalidate_handler

        # Gather all new events.
        # (All controls are able to invalidate themselves.)
        def gather_events() -> Iterable[Event[object]]:
            for c in self.layout.find_all_controls():
                for ev in c.get_invalidate_events():
                    yield ev

        self._invalidate_events = list(gather_events())

        for ev in self._invalidate_events:
            ev += self._invalidate_handler

    def _invalidate_handler(self, sender: object) -> None:
        """
        Handler for invalidate events coming from UIControls.

        (This handles the difference in signature between event handler and
        `self.invalidate`. It also needs to be a method -not a nested
        function-, so that we can remove it again .)
        """
        self.invalidate()

    def _on_resize(self) -> None:
        """
        When the window size changes, we erase the current output and request
        again the cursor position. When the CPR answer arrives, the output is
        drawn again.
        """
        # Erase, request position (when cursor is at the start position)
        # and redraw again. -- The order is important.
        self.renderer.erase(leave_alternate_screen=False)
        self._request_absolute_cursor_position()
        self._redraw()

    def _pre_run(self, pre_run: Optional[Callable[[], None]] = None) -> None:
        " Called during `run`. "
        if pre_run:
            pre_run()

        # Process registered "pre_run_callables" and clear list.
        for c in self.pre_run_callables:
            c()
        del self.pre_run_callables[:]

    async def run_async(
        self,
        pre_run: Optional[Callable[[], None]] = None,
        set_exception_handler: bool = True,
    ) -> _AppResult:
        """
        Run the prompt_toolkit :class:`~prompt_toolkit.application.Application`
        until :meth:`~prompt_toolkit.application.Application.exit` has been
        called. Return the value that was passed to
        :meth:`~prompt_toolkit.application.Application.exit`.

        This is the main entry point for a prompt_toolkit
        :class:`~prompt_toolkit.application.Application` and usually the only
        place where the event loop is actually running.

        :param pre_run: Optional callable, which is called right after the
            "reset" of the application.
        :param set_exception_handler: When set, in case of an exception, go out
            of the alternate screen and hide the application, display the
            exception, and wait for the user to press ENTER.
        """
        assert not self._is_running, "Application is already running."

        async def _run_async() -> _AppResult:
            " Coroutine. "
            loop = get_event_loop()
            f = loop.create_future()
            self.future = f  # XXX: make sure to set this before calling '_redraw'.
            self.loop = loop
            self.context = contextvars.copy_context()

            # Counter for cancelling 'flush' timeouts. Every time when a key is
            # pressed, we start a 'flush' timer for flushing our escape key. But
            # when any subsequent input is received, a new timer is started and
            # the current timer will be ignored.
            flush_task: Optional[asyncio.Task[None]] = None

            # Reset.
            self.reset()
            self._pre_run(pre_run)

            # Feed type ahead input first.
            self.key_processor.feed_multiple(get_typeahead(self.input))
            self.key_processor.process_keys()

            def read_from_input() -> None:
                nonlocal flush_task

                # Ignore when we aren't running anymore. This callback will
                # removed from the loop next time. (It could be that it was
                # still in the 'tasks' list of the loop.)
                # Except: if we need to process incoming CPRs.
                if not self._is_running and not self.renderer.waiting_for_cpr:
                    return

                # Get keys from the input object.
                keys = self.input.read_keys()

                # Feed to key processor.
                self.key_processor.feed_multiple(keys)
                self.key_processor.process_keys()

                # Quit when the input stream was closed.
                if self.input.closed:
                    f.set_exception(EOFError)
                else:
                    # Automatically flush keys.
                    if flush_task:
                        flush_task.cancel()
                    flush_task = self.create_background_task(auto_flush_input())

            async def auto_flush_input() -> None:
                # Flush input after timeout.
                # (Used for flushing the enter key.)
                # This sleep can be cancelled, in that case we won't flush yet.
                await sleep(self.ttimeoutlen)
                flush_input()

            def flush_input() -> None:
                if not self.is_done:
                    # Get keys, and feed to key processor.
                    keys = self.input.flush_keys()
                    self.key_processor.feed_multiple(keys)
                    self.key_processor.process_keys()

                    if self.input.closed:
                        f.set_exception(EOFError)

            # Enter raw mode.
            with self.input.raw_mode():
                with self.input.attach(read_from_input):
                    # Draw UI.
                    self._request_absolute_cursor_position()
                    self._redraw()
                    self._start_auto_refresh_task()

                    has_sigwinch = hasattr(signal, "SIGWINCH") and in_main_thread()
                    if has_sigwinch:
                        previous_winch_handler = signal.getsignal(signal.SIGWINCH)
                        loop.add_signal_handler(signal.SIGWINCH, self._on_resize)

                    # Wait for UI to finish.
                    try:
                        result = await f
                    finally:
                        # In any case, when the application finishes. (Successful,
                        # or because of an error.)
                        try:
                            self._redraw(render_as_done=True)
                        finally:
                            # _redraw has a good chance to fail if it calls widgets
                            # with bad code. Make sure to reset the renderer anyway.
                            self.renderer.reset()

                            # Unset `is_running`, this ensures that possibly
                            # scheduled draws won't paint during the following
                            # yield.
                            self._is_running = False

                            # Detach event handlers for invalidate events.
                            # (Important when a UIControl is embedded in
                            # multiple applications, like ptterm in pymux. An
                            # invalidate should not trigger a repaint in
                            # terminated applications.)
                            for ev in self._invalidate_events:
                                ev -= self._invalidate_handler
                            self._invalidate_events = []

                            # Wait for CPR responses.
                            if self.input.responds_to_cpr:
                                await self.renderer.wait_for_cpr_responses()

                            if has_sigwinch:
                                loop.remove_signal_handler(signal.SIGWINCH)
                                signal.signal(signal.SIGWINCH, previous_winch_handler)

                            # Wait for the run-in-terminals to terminate.
                            previous_run_in_terminal_f = self._running_in_terminal_f

                            if previous_run_in_terminal_f:
                                await previous_run_in_terminal_f

                            # Store unprocessed input as typeahead for next time.
                            store_typeahead(
                                self.input, self.key_processor.empty_queue()
                            )

                return result

        async def _run_async2() -> _AppResult:
            self._is_running = True

            # Make sure to set `_invalidated` to `False` to begin with,
            # otherwise we're not going to paint anything. This can happen if
            # this application had run before on a different event loop, and a
            # paint was scheduled using `call_soon_threadsafe` with
            # `max_postpone_time`.
            self._invalidated = False

            loop = get_event_loop()
            if set_exception_handler:
                previous_exc_handler = loop.get_exception_handler()
                loop.set_exception_handler(self._handle_exception)

            try:
                with set_app(self):
                    try:
                        result = await _run_async()
                    finally:
                        # Wait for the background tasks to be done. This needs to
                        # go in the finally! If `_run_async` raises
                        # `KeyboardInterrupt`, we still want to wait for the
                        # background tasks.
                        await self.cancel_and_wait_for_background_tasks()

                        # Set the `_is_running` flag to `False`. Normally this
                        # happened already in the finally block in `run_async`
                        # above, but in case of exceptions, that's not always the
                        # case.
                        self._is_running = False
                    return result
            finally:
                if set_exception_handler:
                    loop.set_exception_handler(previous_exc_handler)

        return await _run_async2()

    def run(
        self,
        pre_run: Optional[Callable[[], None]] = None,
        set_exception_handler: bool = True,
    ) -> _AppResult:
        """
        A blocking 'run' call that waits until the UI is finished.

        This will start the current asyncio event loop. If no loop is set for
        the current thread, then it will create a new loop.

        :param pre_run: Optional callable, which is called right after the
            "reset" of the application.
        :param set_exception_handler: When set, in case of an exception, go out
            of the alternate screen and hide the application, display the
            exception, and wait for the user to press ENTER.
        """
        # We don't create a new event loop by default, because we want to be
        # sure that when this is called multiple times, each call of `run()`
        # goes through the same event loop. This way, users can schedule
        # background-tasks that keep running across multiple prompts.
        try:
            loop = get_event_loop()
        except RuntimeError:
            # Possibly we are not running in the main thread, where no event
            # loop is set by default. Or somebody called `asyncio.run()`
            # before, which closes the existing event loop. We can create a new
            # loop.
            loop = new_event_loop()
            set_event_loop(loop)

        return loop.run_until_complete(
            self.run_async(pre_run=pre_run, set_exception_handler=set_exception_handler)
        )

    def _handle_exception(
        self, loop: AbstractEventLoop, context: Dict[str, Any]
    ) -> None:
        """
        Handler for event loop exceptions.
        This will print the exception, using run_in_terminal.
        """
        # For Python 2: we have to get traceback at this point, because
        # we're still in the 'except:' block of the event loop where the
        # traceback is still available. Moving this code in the
        # 'print_exception' coroutine will loose the exception.
        tb = get_traceback_from_context(context)
        formatted_tb = "".join(format_tb(tb))

        async def in_term() -> None:
            async with in_terminal():
                # Print output. Similar to 'loop.default_exception_handler',
                # but don't use logger. (This works better on Python 2.)
                print("\nUnhandled exception in event loop:")
                print(formatted_tb)
                print("Exception %s" % (context.get("exception"),))

                await _do_wait_for_enter("Press ENTER to continue...")

        ensure_future(in_term())

    def create_background_task(
        self, coroutine: Awaitable[None]
    ) -> "asyncio.Task[None]":
        """
        Start a background task (coroutine) for the running application.
        If asyncio had nurseries like Trio, we would create a nursery in
        `Application.run_async`, and run the given coroutine in that nursery.
        """
        task = get_event_loop().create_task(coroutine)
        self.background_tasks.append(task)
        return task

    async def cancel_and_wait_for_background_tasks(self) -> None:
        """
        Cancel all background tasks, and wait for the cancellation to be done.
        If any of the background tasks raised an exception, this will also
        propagate the exception.

        (If we had nurseries like Trio, this would be the `__aexit__` of a
        nursery.)
        """
        for task in self.background_tasks:
            task.cancel()

        for task in self.background_tasks:
            try:
                await task
            except CancelledError:
                pass

    def cpr_not_supported_callback(self) -> None:
        """
        Called when we don't receive the cursor position response in time.
        """
        if not self.input.responds_to_cpr:
            return  # We know about this already.

        def in_terminal() -> None:
            self.output.write(
                "WARNING: your terminal doesn't support cursor position requests (CPR).\r\n"
            )
            self.output.flush()

        run_in_terminal(in_terminal)

    @overload
    def exit(self) -> None:
        " Exit without arguments. "

    @overload
    def exit(self, *, result: _AppResult, style: str = "") -> None:
        " Exit with `_AppResult`. "

    @overload
    def exit(
        self, *, exception: Union[BaseException, Type[BaseException]], style: str = ""
    ) -> None:
        " Exit with exception. "

    def exit(
        self,
        result: Optional[_AppResult] = None,
        exception: Optional[Union[BaseException, Type[BaseException]]] = None,
        style: str = "",
    ) -> None:
        """
        Exit application.

        :param result: Set this result for the application.
        :param exception: Set this exception as the result for an application. For
            a prompt, this is often `EOFError` or `KeyboardInterrupt`.
        :param style: Apply this style on the whole content when quitting,
            often this is 'class:exiting' for a prompt. (Used when
            `erase_when_done` is not set.)
        """
        assert result is None or exception is None

        if self.future is None:
            raise Exception("Application is not running. Application.exit() failed.")

        if self.future.done():
            raise Exception("Return value already set. Application.exit() failed.")

        self.exit_style = style

        if exception is not None:
            self.future.set_exception(exception)
        else:
            self.future.set_result(cast(_AppResult, result))

    def _request_absolute_cursor_position(self) -> None:
        """
        Send CPR request.
        """
        # Note: only do this if the input queue is not empty, and a return
        # value has not been set. Otherwise, we won't be able to read the
        # response anyway.
        if not self.key_processor.input_queue and not self.is_done:
            self.renderer.request_absolute_cursor_position()

    async def run_system_command(
        self,
        command: str,
        wait_for_enter: bool = True,
        display_before_text: AnyFormattedText = "",
        wait_text: str = "Press ENTER to continue...",
    ) -> None:
        """
        Run system command (While hiding the prompt. When finished, all the
        output will scroll above the prompt.)

        :param command: Shell command to be executed.
        :param wait_for_enter: FWait for the user to press enter, when the
            command is finished.
        :param display_before_text: If given, text to be displayed before the
            command executes.
        :return: A `Future` object.
        """
        async with in_terminal():
            # Try to use the same input/output file descriptors as the one,
            # used to run this application.
            try:
                input_fd = self.input.fileno()
            except AttributeError:
                input_fd = sys.stdin.fileno()
            try:
                output_fd = self.output.fileno()
            except AttributeError:
                output_fd = sys.stdout.fileno()

            # Run sub process.
            def run_command() -> None:
                self.print_text(display_before_text)
                p = Popen(command, shell=True, stdin=input_fd, stdout=output_fd)
                p.wait()

            await run_in_executor_with_context(run_command)

            # Wait for the user to press enter.
            if wait_for_enter:
                await _do_wait_for_enter(wait_text)

    def suspend_to_background(self, suspend_group: bool = True) -> None:
        """
        (Not thread safe -- to be called from inside the key bindings.)
        Suspend process.

        :param suspend_group: When true, suspend the whole process group.
            (This is the default, and probably what you want.)
        """
        # Only suspend when the operating system supports it.
        # (Not on Windows.)
        if hasattr(signal, "SIGTSTP"):

            def run() -> None:
                # Send `SIGSTP` to own process.
                # This will cause it to suspend.

                # Usually we want the whole process group to be suspended. This
                # handles the case when input is piped from another process.
                if suspend_group:
                    os.kill(0, signal.SIGTSTP)
                else:
                    os.kill(os.getpid(), signal.SIGTSTP)

            run_in_terminal(run)

    def print_text(
        self, text: AnyFormattedText, style: Optional[BaseStyle] = None
    ) -> None:
        """
        Print a list of (style_str, text) tuples to the output.
        (When the UI is running, this method has to be called through
        `run_in_terminal`, otherwise it will destroy the UI.)

        :param text: List of ``(style_str, text)`` tuples.
        :param style: Style class to use. Defaults to the active style in the CLI.
        """
        print_formatted_text(
            output=self.output,
            formatted_text=text,
            style=style or self._merged_style,
            color_depth=self.color_depth,
            style_transformation=self.style_transformation,
        )

    @property
    def is_running(self) -> bool:
        " `True` when the application is currently active/running. "
        return self._is_running

    @property
    def is_done(self) -> bool:
        if self.future:
            return self.future.done()
        return False

    def get_used_style_strings(self) -> List[str]:
        """
        Return a list of used style strings. This is helpful for debugging, and
        for writing a new `Style`.
        """
        attrs_for_style = self.renderer._attrs_for_style

        if attrs_for_style:
            return sorted(
                [
                    re.sub(r"\s+", " ", style_str).strip()
                    for style_str in attrs_for_style.keys()
                ]
            )

        return []


class _CombinedRegistry(KeyBindingsBase):
    """
    The `KeyBindings` of key bindings for a `Application`.
    This merges the global key bindings with the one of the current user
    control.
    """

    def __init__(self, app: Application[_AppResult]) -> None:
        self.app = app
        self._cache: SimpleCache[
            Tuple[Window, FrozenSet[UIControl]], KeyBindingsBase
        ] = SimpleCache()

    @property
    def _version(self) -> Hashable:
        """ Not needed - this object is not going to be wrapped in another
        KeyBindings object. """
        raise NotImplementedError

    def bindings(self) -> List[Binding]:
        """ Not needed - this object is not going to be wrapped in another
        KeyBindings object. """
        raise NotImplementedError

    def _create_key_bindings(
        self, current_window: Window, other_controls: List[UIControl]
    ) -> KeyBindingsBase:
        """
        Create a `KeyBindings` object that merges the `KeyBindings` from the
        `UIControl` with all the parent controls and the global key bindings.
        """
        key_bindings = []
        collected_containers = set()

        # Collect key bindings from currently focused control and all parent
        # controls. Don't include key bindings of container parent controls.
        container: Container = current_window
        while True:
            collected_containers.add(container)
            kb = container.get_key_bindings()
            if kb is not None:
                key_bindings.append(kb)

            if container.is_modal():
                break

            parent = self.app.layout.get_parent(container)
            if parent is None:
                break
            else:
                container = parent

        # Include global bindings (starting at the top-model container).
        for c in walk(container):
            if c not in collected_containers:
                kb = c.get_key_bindings()
                if kb is not None:
                    key_bindings.append(GlobalOnlyKeyBindings(kb))

        # Add App key bindings
        if self.app.key_bindings:
            key_bindings.append(self.app.key_bindings)

        # Add mouse bindings.
        key_bindings.append(
            ConditionalKeyBindings(
                self.app._page_navigation_bindings,
                self.app.enable_page_navigation_bindings,
            )
        )
        key_bindings.append(self.app._default_bindings)

        # Reverse this list. The current control's key bindings should come
        # last. They need priority.
        key_bindings = key_bindings[::-1]

        return merge_key_bindings(key_bindings)

    @property
    def _key_bindings(self) -> KeyBindingsBase:
        current_window = self.app.layout.current_window
        other_controls = list(self.app.layout.find_all_controls())
        key = current_window, frozenset(other_controls)

        return self._cache.get(
            key, lambda: self._create_key_bindings(current_window, other_controls)
        )

    def get_bindings_for_keys(self, keys: KeysTuple) -> List[Binding]:
        return self._key_bindings.get_bindings_for_keys(keys)

    def get_bindings_starting_with_keys(self, keys: KeysTuple) -> List[Binding]:
        return self._key_bindings.get_bindings_starting_with_keys(keys)


async def _do_wait_for_enter(wait_text: AnyFormattedText) -> None:
    """
    Create a sub application to wait for the enter key press.
    This has two advantages over using 'input'/'raw_input':
    - This will share the same input/output I/O.
    - This doesn't block the event loop.
    """
    from prompt_toolkit.shortcuts import PromptSession

    key_bindings = KeyBindings()

    @key_bindings.add("enter")
    def _ok(event: E) -> None:
        event.app.exit()

    @key_bindings.add(Keys.Any)
    def _ignore(event: E) -> None:
        " Disallow typing. "
        pass

    session: PromptSession[None] = PromptSession(
        message=wait_text, key_bindings=key_bindings
    )
    await session.app.run_async()
