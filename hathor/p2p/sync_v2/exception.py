# Copyright 2023 Hathor Labs
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

class StreamingError(Exception):
    """Base error for sync-v2 streaming."""
    pass


class TooManyVerticesReceivedError(StreamingError):
    """Raised when the other peer sent too many vertices."""
    pass


class TooManyRepeatedVerticesError(StreamingError):
    """Raised when the other peer sent too many repeated vertices."""
    pass


class BlockNotConnectedToPreviousBlock(StreamingError):
    """Raised when the received block is not connected to the previous one."""
    pass


class InvalidVertexError(StreamingError):
    """Raised when the received vertex fails validation."""
    pass
