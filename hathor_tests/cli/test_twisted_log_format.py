# Copyright 2026 Hathor Labs
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

"""Reproducer for incident #242 — logger side effect (Alert 4).

`hathor_cli/util.py::twisted_structlog_observer` runs
`event['log_format'].format(**event)`. Twisted log events sometimes include
its own format extension `{previous()}`, which `str.format` does not
understand: it tries to look up a key literally named ``previous()`` in the
event dict and raises `KeyError: 'previous()'`. That swallows the real
exception (Bug A) and replaces the log line with a generic
"error when logging event" entry on stderr.

The fix should extract the format step as a top-level helper
`_format_twisted_event(event) -> str` that handles Twisted's `{name()}`
extension safely, and have the inner observer delegate to it.
"""


def test_format_twisted_event_handles_previous_extension() -> None:
    """The helper must substitute Twisted's `{name()}` callable extension.

    In production, `runUntilCurrent` emits `'while handling timed call {previous()}'`
    and binds `previous` to a zero-arg callable. Plain `str.format(**event)`
    raises `KeyError: 'previous()'` because it treats `previous()` as a literal
    dict key. The helper must use Twisted's renderer so the callable runs.
    """
    from hathor_cli.util import _format_twisted_event

    event: dict[str, object] = {
        'log_format': 'while handling timed call {previous()}',
        'previous': lambda: '<DelayedCall sentinel>',
        'log_level': None,
        'log_namespace': 'twisted.internet.base',
        'log_source': None,
        'log_time': 1776941231.7607915,
    }

    result = _format_twisted_event(event)

    assert result == 'while handling timed call <DelayedCall sentinel>'


def test_format_twisted_event_preserves_simple_format() -> None:
    """Plain `{key}` substitutions still work after the fix."""
    from hathor_cli.util import _format_twisted_event

    event: dict[str, object] = {
        'log_format': 'connection from {peer}',
        'peer': '127.0.0.1:1234',
        'log_level': None,
    }

    assert _format_twisted_event(event) == 'connection from 127.0.0.1:1234'
