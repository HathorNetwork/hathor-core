from argparse import ArgumentParser

import configargparse


def create_parser() -> ArgumentParser:
    return configargparse.ArgumentParser(auto_env_var_prefix='hathor_')


def setup_logging(debug: bool = False, capture_stdout: bool = True, *, _test_logging: bool = False) -> None:
    import logging.config

    import colorama
    import structlog
    import twisted

    logger = structlog.get_logger()

    # common timestamper for structlog loggers and foreign (stdlib and twisted) loggers
    timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S")

    # processors for foreign loggers
    pre_chain = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        timestamper,
    ]

    level_styles = {
        'critical': colorama.Style.BRIGHT + colorama.Fore.RED,
        'exception': colorama.Fore.RED,
        'error': colorama.Fore.RED,
        # 'warn': colorama.Fore.YELLOW,
        'warning': colorama.Fore.YELLOW,
        'info': colorama.Fore.GREEN,
        'debug': colorama.Style.BRIGHT + colorama.Fore.CYAN,
        'notset': colorama.Back.RED,
    }

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

            event = event_dict.pop('event')
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
                    'processor': ConsoleRenderer(colors=True, level_styles=level_styles),
                    'foreign_pre_chain': pre_chain,
                },
            },
            'handlers': {
                'default': {
                    'level': 'DEBUG',
                    'class': 'logging.StreamHandler',
                    'formatter': 'colored',
                },
                # 'file': {
                #     'level': 'DEBUG',
                #     'class': 'logging.handlers.WatchedFileHandler',
                #     'filename': 'test.log',
                #     'formatter': 'plain',
                # },
            },
            'loggers': {
                '': {
                    # 'handlers': ['default', 'file'],
                    'handlers': ['default'],
                    'level': 'DEBUG' if debug else 'INFO',
                    'propagate': True,
                },
            }
    })

    def kwargs_formatter(_, __, event_dict):
        if event_dict and event_dict.get('event') and isinstance(event_dict['event'], str):
            event_dict['event'] = event_dict['event'].format(**event_dict)
        return event_dict

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            kwargs_formatter,
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
            # structlog.twisted.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    twisted.python.log.startLoggingWithObserver(twisted.logger.STDLibLogObserver(), setStdout=capture_stdout)

    if _test_logging:
        logger.debug('Test: debug.')
        logger.info('Test: info.')
        logger.warning('Test: warning.')
        logger.error('Test error.')
        logger.critical('Test: critical.')
