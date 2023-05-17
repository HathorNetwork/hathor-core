#  Copyright 2023 Hathor Labs
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

# The number of blocks in the feature activation evaluation interval.
# Equivalent to 14 days (40320 * 30 seconds = 14 days)
EVALUATION_INTERVAL = 40320

# The number of bits used in the first byte of a block's version field. The 4 left-most bits are not used.
MAX_SIGNAL_BITS = 4
