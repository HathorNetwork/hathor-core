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

import sys
from argparse import ArgumentParser
from collections import OrderedDict
from datetime import datetime
from typing import Any, List

import configargparse
import structlog


def create_parser() -> ArgumentParser:
    return configargparse.ArgumentParser(auto_env_var_prefix='hathor_')


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


def setup_logging(
            debug: bool = False,
            capture_stdout: bool = False,
            json_logging: bool = False,
            *,
            sentry: bool = False,
            _test_logging: bool = False,
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

    if json_logging:
        handlers = ['json']
    else:
        handlers = ['pretty']

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
                    'level': 'INFO' if debug else 'WARN',
                    'propagate': False,
                },
                '': {
                    'handlers': handlers,
                    'level': 'DEBUG' if debug else 'INFO',
                },
            }
    })

    def kwargs_formatter(_, __, event_dict):
        if event_dict and event_dict.get('event') and isinstance(event_dict['event'], str):
            event_dict['event'] = event_dict['event'].format(**event_dict)
        return event_dict

    processors: List[Any] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
    ]

    if sentry:
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
        except Exception as e:
            print('error when logging event', e)
            for k, v in event.items():
                print(k, v)

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
