#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import functools
from typing import Callable, ParamSpec, TypeVar, final

"""
This module defines error handling for Nano Contract execution.

It contains four specific exception types that inherit from `BaseException`, NOT from `Exception`.
This allows them to pass through `except Exception` blocks which is essential in user code boundaries.

It also contains two decorators, `@internal_code_called_from_user_code` and `@user_code_called_from_internal_code`
that MUST be used in user code boundaries.
They are responsible for handling and wrapping the exceptions accordingly.

The four exception types are:

1. NCInternalException
2. NCUserException
3. __NCUnhandledInternalException__
4. __NCUnhandledUserException__

When raised, __NCUnhandledInternalException__ will crash the full node. All the others will just fail
a Nano Contract transaction. They are described in more detail below.

Underscores are used in exception names to signal they require special care.
"""

T = TypeVar('T')
P = ParamSpec('P')


class __NCTransactionFail__(BaseException):
    """A super type for all exceptions that fail an NC transaction execution."""


class NCInternalException(__NCTransactionFail__):  # skip-inherit-from-nc-tx-fail
    """
    This exception represents known internal errors that can happen during contract execution,
    such as raising when a contract balance is insufficient to fulfill an action.

    It may be raised directly or subclassed by Hathor internal code. When raised, it will fail the NC transaction.
    It cannot be raised or subclassed by user code in blueprints.
    """


class NCUserException(__NCTransactionFail__):  # skip-inherit-from-nc-tx-fail
    """
    This exception represents known user errors that can happen during contract execution,
    such as raising when the business rule of a blueprint is violated.

    It may be raised directly or subclassed by user code in blueprints. When raised, it will fail the NC transaction.
    It cannot be raised or subclassed by Hathor internal code.
    """


@final
class __NCUnhandledInternalException__(BaseException):
    """
    This exception represents unhandled internal errors that can happen during contract execution,
    such as an AssertionError.

    It cannot be raised directly or subclassed by any code. When raised,
    it will reach the consensus entrypoint and crash the full node.
    """


@final
class __NCUnhandledUserException__(__NCTransactionFail__):  # skip-inherit-from-nc-tx-fail
    """
    This exception represents unhandled user errors that can happen during contract execution,
    such as when a blueprint code divides by zero, raising ZeroDivisionError.

    It cannot be raised directly or subclassed by any code. When raised, it will fail the NC transaction.
    """


def internal_code_called_from_user_code(f: Callable[P, T]) -> Callable[P, T]:
    """
    Mark a function/method as internal Hathor code that may be called from user code in blueprints, such as syscalls.
    It wraps exceptions accordingly.
    """
    @functools.wraps(f)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return f(*args, **kwargs)
        except Exception as e:
            # Unhandled exceptions are considered bugs in our code, such as AssertionError.
            # They are bubbled up wrapped in an __NCUnhandledInternalException__ which does not inherit from Exception
            # and will eventually crash the full node when it reaches the consensus entrypoint.
            raise __NCUnhandledInternalException__ from e  # skip-raise-nc-unhandled-exception
        except BaseException:
            # All other exceptions are bubbled up untouched.
            # This includes the four exception classes defined in this file.
            # If they reach another user code boundary, they will continue to bubble up.
            # If they are unhandled, they will reach the consensus entrypoint crashing the full node.
            raise

    return wrapper


def user_code_called_from_internal_code(f: Callable[P, T]) -> Callable[P, T]:
    """
    Mark a function/method as user code from blueprints that is called from internal Hathor code,
    such as when we call `exec()`.
    It wraps exceptions accordingly.
    """
    @functools.wraps(f)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return f(*args, **kwargs)
        except Exception as e:
            # Unhandled exceptions may be bugs in user code, such as ZeroDivisionError.
            # They are bubbled up wrapped in an __NCUnhandledUserException__ which does not inherit from Exception
            # and will eventually fail the NC transaction when it reaches the consensus entrypoint.
            raise __NCUnhandledUserException__ from e  # skip-raise-nc-unhandled-exception
        except BaseException:
            # All other exceptions are bubbled up untouched.
            # This includes the four exception classes defined in this file.
            # If they reach another user code boundary, they will continue to bubble up.
            # If they are unhandled, they will reach the consensus entrypoint crashing the full node.
            raise

    return wrapper
