# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.exception import HathorError


class InvalidXPub(HathorError):
    """Raised when an invalid xpub is provided."""


class LimitExceeded(HathorError):
    """Raised when a limit is exceeded."""


class InvalidAddress(HathorError):
    """Raised when an invalid address is provided."""
