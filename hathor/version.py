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

import os

BASE_VERSION = '0.53.0'

DEFAULT_VERSION_SUFFIX = "-local"
BUILD_VERSION_FILE_PATH = "./BUILD_VERSION"


def _get_build_version():
    if not os.path.isfile(BUILD_VERSION_FILE_PATH):
        return None

    with open(BUILD_VERSION_FILE_PATH, 'r') as f:
        build_version = f.readline()

        return build_version


def _get_version():
    local_version = BASE_VERSION + DEFAULT_VERSION_SUFFIX
    return _get_build_version() or local_version


__version__ = _get_version()
