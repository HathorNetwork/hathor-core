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

from typing import Optional

from pydantic import NonNegativeInt

from hathor.utils.pydantic import BaseModel


class StreamRequest(BaseModel):
    """Class that represents a client request to stream events.

    Args:
        last_received_event_id: The ID of the last event successfully processed by the requesting client.
        window_size: The amount of events the client is able to process.
    """
    last_received_event_id: Optional[NonNegativeInt]
    window_size: NonNegativeInt
