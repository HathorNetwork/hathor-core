# Copyright 2021 Hathor Labs
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

import json
import logging
import sys
import traceback
from argparse import ArgumentParser
from collections import OrderedDict
from datetime import datetime
from enum import IntEnum, auto
from typing import Any, NamedTuple

import configargparse
import structlog
from structlog.typing import EventDict
from typing_extensions import assert_never


def create_parser(*, prefix: str | None = None, add_help: bool = True) -> ArgumentParser:
    return configargparse.ArgumentParser(auto_env_var_prefix=prefix or 'hathor_', add_help=add_help)


# docs at http://www.structlog.org/en/stable/api.html#structlog.dev.ConsoleRenderer
class ConsoleRenderer(structlog.dev.ConsoleRenderer):
    def __call__(self, _, __, event_dict):
        from io import StringIO

        from structlog.dev import _pad

        sio = StringIO()

        ts = event_dict.pop('timestamp', None)
        if ts is not None:
            sio.write(
                # can be a number if timestamp is UNIXy
                self._styles.timestamp
                + str(ts)
                + self._styles.reset
                + ' '
            )
        level = event_dict.pop('level', None)
        if level is not None:
            sio.write(
                '['
                + self._level_to_color[level]
                + _pad(level, self._longest_level)
                + self._styles.reset
                + '] '
            )

        logger_name = event_dict.pop('logger', None)
        if logger_name is not None:
            sio.write(
                '['
                + self._styles.logger_name
                + self._styles.bright
                + logger_name
                + self._styles.reset
                + '] '
            )

        event = str(event_dict.pop('event'))
        if event_dict:
            event = _pad(event, self._pad_event) + self._styles.reset + ' '
        else:
            event += self._styles.reset
        sio.write(self._styles.bright + event)

        stack = event_dict.pop('stack', None)
        exc = event_dict.pop('exception', None)
        sio.write(
            ' '.join(
                self._styles.kv_key
                + key
                + self._styles.reset
                + '='
                + self._styles.kv_value
                + self._repr(event_dict[key])
                + self._styles.reset
                for key in sorted(event_dict.keys())
            )
        )

        if stack is not None:
            sio.write('\n' + stack)
            if exc is not None:
                sio.write('\n\n' + '=' * 79 + '\n')
        if exc is not None:
            sio.write('\n' + exc)

        return sio.getvalue()

    @staticmethod
    def get_default_level_styles(colors=True):
        import colorama
        if not colors:
            return structlog.dev.ConsoleRenderer.get_default_level_styles(False)
        return {
            'critical': colorama.Style.BRIGHT + colorama.Fore.RED,
            'exception': colorama.Fore.RED,
            'error': colorama.Fore.RED,
            'warn': colorama.Fore.YELLOW,
            'warning': colorama.Fore.YELLOW,
            'info': colorama.Fore.GREEN,
            'debug': colorama.Style.BRIGHT + colorama.Fore.CYAN,
            'notset': colorama.Back.RED,
        }

    def _repr(self, val):
        if isinstance(val, datetime):
            return str(val)
        else:
            return super()._repr(val)


class LoggingOutput(IntEnum):
    NULL = auto()
    PRETTY = auto()
    JSON = auto()


class LoggingOptions(NamedTuple):
    debug: bool
    sentry: bool


def process_logging_output(argv: list[str]) -> LoggingOutput:
    """Extract logging output before argv parsing."""
    parser = create_parser(add_help=False)

    log_args = parser.add_mutually_exclusive_group()
    log_args.add_argument('--json-logs', action='store_true')
    log_args.add_argument('--disable-logs', action='store_true')

    args, remaining_argv = parser.parse_known_args(argv)
    argv.clear()
    argv.extend(remaining_argv)

    if args.json_logs:
        return LoggingOutput.JSON

    if args.disable_logs:
        return LoggingOutput.NULL

    return LoggingOutput.PRETTY


def process_logging_options(argv: list[str]) -> LoggingOptions:
    """Extract logging-specific options that are processed before argv parsing."""
    parser = create_parser(add_help=False)
    parser.add_argument('--debug', action='store_true')

    args, remaining_argv = parser.parse_known_args(argv)
    argv.clear()
    argv.extend(remaining_argv)

    sentry = '--sentry-dsn' in argv
    return LoggingOptions(debug=args.debug, sentry=sentry)


def setup_logging(
    *,
    logging_output: LoggingOutput,
    logging_options: LoggingOptions,
    capture_stdout: bool = False,
    _test_logging: bool = False,
    extra_log_info: dict[str, str] | None = None,
) -> None:
    import logging
    import logging.config

    import twisted
    from twisted.logger import LogLevel

    # Mappings to Python's logging module
    twisted_to_logging_level = {
        LogLevel.debug: logging.DEBUG,
        LogLevel.info: logging.INFO,
        LogLevel.warn: logging.WARNING,
        LogLevel.error: logging.ERROR,
        LogLevel.critical: logging.CRITICAL,
    }

    # common timestamper for structlog loggers and foreign (stdlib and twisted) loggers
    timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S")

    # processors for foreign loggers
    pre_chain = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        timestamper,
    ]

    match logging_output:
        case LoggingOutput.NULL:
            handlers = ['null']
        case LoggingOutput.PRETTY:
            handlers = ['pretty']
        case LoggingOutput.JSON:
            handlers = ['json']
        case _:
            assert_never(logging_output)

    # Flag to enable debug level for both sync-v1 and sync-v2.
    debug_sync = False and logging_options.debug

    # See: https://docs.python.org/3/library/logging.config.html#configuration-dictionary-schema
    logging.config.dictConfig({
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'plain': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': ConsoleRenderer(colors=False),
                    'foreign_pre_chain': pre_chain,
                },
                'colored': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': ConsoleRenderer(colors=True),
                    'foreign_pre_chain': pre_chain,
                },
                'json': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': structlog.processors.JSONRenderer(),
                    'foreign_pre_chain': pre_chain,
                },
            },
            'handlers': {
                'pretty': {
                    'level': 'DEBUG',
                    'class': 'logging.StreamHandler',
                    'formatter': 'colored',
                },
                'json': {
                    'level': 'DEBUG',
                    'class': 'logging.StreamHandler',
                    'formatter': 'json',
                },
                'null': {
                    'class': 'logging.NullHandler',
                },
                # 'file': {
                #     'level': 'DEBUG',
                #     'class': 'logging.handlers.WatchedFileHandler',
                #     'filename': 'test.log',
                #     'formatter': 'plain',
                # },
            },
            'loggers': {
                # set twisted verbosity one level lower than hathor's
                'twisted': {
                    'handlers': handlers,
                    'level': 'INFO' if logging_options.debug else 'WARN',
                    'propagate': False,
                },
                'tornado': {  # used by ipykernel's zmq
                    'handlers': handlers,
                    'level': 'INFO' if logging_options.debug else 'WARN',
                    'propagate': False,
                },
                'hathor.p2p.sync_v2': {
                    'handlers': handlers,
                    'level': 'DEBUG' if debug_sync else 'INFO',
                    'propagate': False,
                },
                '': {
                    'handlers': handlers,
                    'level': 'DEBUG' if logging_options.debug else 'INFO',
                },
            }
    })

    def kwargs_formatter(_, __, event_dict):
        if event_dict and event_dict.get('event') and isinstance(event_dict['event'], str):
            try:
                event_dict['event'] = event_dict['event'].format(**event_dict)
            except KeyError:
                # The event string may contain '{}'s that are not used for formatting, resulting in a KeyError in the
                # event_dict. In this case, we don't format it.
                pass
        return event_dict

    extra_log_info = extra_log_info or {}

    def add_extra_log_info(_logger: logging.Logger, _method_name: str, event_dict: EventDict) -> EventDict:
        for key, value in extra_log_info.items():
            assert key not in event_dict, 'extra log info conflicting with existing log key'
            event_dict[key] = value
        return event_dict

    processors: list[Any] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        add_extra_log_info,
    ]

    if logging_options.sentry:
        from structlog_sentry import SentryProcessor
        processors.append(SentryProcessor(level=logging.ERROR))

    processors.extend([
        structlog.stdlib.PositionalArgumentsFormatter(),
        kwargs_formatter,
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ])

    structlog.configure(
        processors=processors,
        context_class=OrderedDict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    twisted_logger = structlog.get_logger('twisted')

    def twisted_structlog_observer(event):
        try:
            level = twisted_to_logging_level.get(event.get('log_level'), logging.INFO)
            kwargs = {}
            msg = ''
            if not msg and event.get('log_format', None):
                msg = event['log_format'].format(**event)
            if not msg and event.get('format', None):
                msg = event['format'] % event
            failure = event.get('log_failure')
            if failure is not None:
                kwargs['exc_info'] = (failure.type, failure.value, failure.getTracebackObject())
            twisted_logger.log(level, msg, **kwargs)
        except Exception:
            new_event = dict(
                event='error when logging event',
                original_event=event,
                traceback=traceback.format_exc()
            )
            new_event_json = json.dumps(new_event, default=str)
            print(new_event_json, file=sys.stderr)

    # start logging to std logger so structlog can catch it
    twisted.python.log.startLoggingWithObserver(twisted_structlog_observer, setStdout=capture_stdout)

    if _test_logging:
        logger = structlog.get_logger()
        logger.debug('Test: debug.')
        logger.info('Test: info.')
        logger.warning('Test: warning.')
        logger.error('Test error.')
        logger.critical('Test: critical.')


def check_or_exit(condition: bool, message: str) -> None:
    """Will exit printing `message` if `condition` is False."""
    if not condition:
        print(message)
        sys.exit(2)

def create_file_logger(log_file: str, log_level: int = logging.DEBUG) -> structlog.BoundLogger:
    """Create a structlog logger that logs to a specific file.
       This logger should be used for special cases where we want to log to a file instead of stdout.

    :param log_file: Path to the log file.
    :return: A structlog logger instance.
    """
    # Create a file handler

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)

    # Define a logging format
    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)

    # Create a logger instance
    logger = logging.getLogger(f"file_logger_{log_file}")
    logger.setLevel(log_level)
    logger.addHandler(file_handler)

    # Create a structlog logger with a custom configuration
    custom_logger = structlog.wrap_logger(
        logger,
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            ConsoleRenderer(),
        ],
    )

    return custom_logger