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

import json as _json


def json_dumpb(obj: object) -> bytes:
    """Compact formating obj as JSON to UTF-8 encoded bytes."""
    return json_dumps(obj).encode('utf-8')


def json_dumps(obj: object) -> str:
    """Compact formating obj as JSON to UTF-8 encoded string."""
    return _json.dumps(obj, separators=(',', ':'), ensure_ascii=False)
