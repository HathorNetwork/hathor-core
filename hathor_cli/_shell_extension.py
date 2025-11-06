# Copyright 2025 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
IPython extension that adapts logging handlers to play nicely with the interactive prompt.

When loaded, all stream-based logging handlers are updated so their output is rendered
through prompt_toolkit's ``run_in_terminal`` helper, which ensures log lines appear
above the current input without corrupting the prompt. The original streams are restored
when the extension is unloaded.
"""

from __future__ import annotations

import io
import logging
import threading
from contextlib import suppress
from typing import Any, Callable, Iterable

get_app_or_none: Callable[[], Any] | None = None
pt_utils: Any | None = None

try:
    from prompt_toolkit.application import get_app_or_none as _get_app_or_none
    from prompt_toolkit.shortcuts import utils as _pt_utils
except ImportError:
    pass
else:
    get_app_or_none = _get_app_or_none
    pt_utils = _pt_utils

_original_streams: dict[logging.StreamHandler, Any] = {}
_installed = False


class PromptToolkitLogStream(io.TextIOBase):
    """Proxy stream that forwards writes through prompt_toolkit."""

    def __init__(self, inner: Any):
        super().__init__()
        self._inner = inner
        self._encoding_override: str | None = None
        self._errors_override: str | None = None

    def _run_in_terminal(self, func: Callable[[], None]) -> None:
        if pt_utils is None:
            func()
            return

        app = get_app_or_none() if get_app_or_none is not None else None
        if app is None:
            func()
            return
        loop = getattr(app, 'loop', None)
        if loop is None:
            func()
            return

        event = threading.Event()
        handled = False

        def run_and_signal() -> None:
            nonlocal handled
            try:
                if not handled:
                    pt_utils.run_in_terminal(func, in_executor=False)
            finally:
                handled = True
                event.set()

        loop.call_soon_threadsafe(run_and_signal)
        if not event.wait(timeout=5):
            handled = True
            func()

    def write(self, data: str) -> int:
        if not data:
            return 0

        def _write() -> None:
            self._inner.write(data)

        self._run_in_terminal(_write)
        return len(data)

    def flush(self) -> None:
        def _flush() -> None:
            self._inner.flush()

        self._run_in_terminal(_flush)

    @property
    def encoding(self) -> str:
        if self._encoding_override is not None:
            return self._encoding_override
        return getattr(self._inner, 'encoding', 'utf-8') or 'utf-8'

    @encoding.setter
    def encoding(self, value: str) -> None:
        self._encoding_override = value

    @property
    def errors(self) -> str:
        if self._errors_override is not None:
            return self._errors_override
        return getattr(self._inner, 'errors', 'strict') or 'strict'

    @errors.setter
    def errors(self, value: str) -> None:
        self._errors_override = value

    def fileno(self) -> int:
        if hasattr(self._inner, 'fileno') and callable(getattr(self._inner, 'fileno')):
            return self._inner.fileno()
        raise io.UnsupportedOperation('fileno not available')

    def isatty(self) -> bool:
        if hasattr(self._inner, 'isatty') and callable(getattr(self._inner, 'isatty')):
            return self._inner.isatty()
        return False

    def close(self) -> None:
        # Do not close the underlying stream.
        pass

    @property
    def closed(self) -> bool:
        return False

    def readable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False

    def writable(self) -> bool:
        return True


def _iter_stream_handlers() -> Iterable[logging.StreamHandler]:
    """Yield every stream handler currently registered."""
    root = logging.getLogger()
    for handler in root.handlers:
        if isinstance(handler, logging.StreamHandler):
            yield handler

    for logger in logging.Logger.manager.loggerDict.values():
        if isinstance(logger, logging.PlaceHolder):
            continue
        if not isinstance(logger, logging.Logger):
            continue
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                yield handler


def _install_prompt_toolkit_streams() -> None:
    if pt_utils is None:
        return

    for handler in _iter_stream_handlers():
        current_stream = getattr(handler, 'stream', None)
        if current_stream is None or isinstance(current_stream, PromptToolkitLogStream):
            continue

        proxy = PromptToolkitLogStream(current_stream)
        _original_streams[handler] = current_stream
        handler.stream = proxy


def load_ipython_extension(shell: Any) -> None:
    """Called by IPython when the extension is loaded."""
    global _installed

    if pt_utils is None:
        shell.write_err('prompt_toolkit not available; logs will use standard output.\n')
        return

    if _installed:
        return

    _install_prompt_toolkit_streams()
    _installed = True


def unload_ipython_extension(shell: Any) -> None:
    """Called by IPython when the extension is unloaded."""
    restore_logging_streams()


def restore_logging_streams() -> None:
    """Restore the original logging streams."""
    global _installed
    for handler, stream in list(_original_streams.items()):
        with suppress(Exception):
            handler.stream = stream
    _original_streams.clear()
    _installed = False
