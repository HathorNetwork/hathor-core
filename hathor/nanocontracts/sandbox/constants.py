# Copyright 2024 Hathor Labs
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

"""Constants for CPython sandbox configuration."""

import sys

# Filename used for all blueprint code compilation.
# This is registered with the sandbox for scope tracking.
BLUEPRINT_FILENAME = '<blueprint>'

# CPython sandbox compile flag for operation counting.
# This enables SANDBOX_COUNT opcodes in compiled code.
PyCF_SANDBOX_COUNT = 0x8000

# Whether the CPython sandbox is available.
# True when running on a Python build with sandbox support.
SANDBOX_AVAILABLE = hasattr(sys, 'sandbox')
