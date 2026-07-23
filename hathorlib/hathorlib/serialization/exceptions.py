# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import struct

from hathorlib.exceptions import HathorError


class SerializationError(HathorError):
    pass


class UnsupportedTypeError(SerializationError):
    pass


class TooLongError(SerializationError):
    pass


class OutOfDataError(SerializationError, struct.error):
    pass


class BadDataError(SerializationError):
    pass
