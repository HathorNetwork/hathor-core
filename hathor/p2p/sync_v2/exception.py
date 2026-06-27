# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

class StreamingError(Exception):
    """Base error for sync-v2 streaming."""
    pass


class TooManyVerticesReceivedError(StreamingError):
    """Raised when the other peer has sent too many vertices."""
    pass


class TooManyRepeatedVerticesError(StreamingError):
    """Raised when the other peer has sent too many repeated vertices."""
    pass


class BlockNotConnectedToPreviousBlock(StreamingError):
    """Raised when the received block is not connected to the previous one."""
    pass


class InvalidVertexError(StreamingError):
    """Raised when the received vertex fails validation."""
    pass


class UnexpectedVertex(StreamingError):
    """Raised when we are not expecting the received vertex."""
    pass
