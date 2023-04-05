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
import re
from typing import Optional

from structlog import get_logger

BASE_VERSION = '0.53.0'

DEFAULT_VERSION_SUFFIX = "-local"
BUILD_VERSION_FILE_PATH = "./BUILD_VERSION"

# Valid formats: 1.2.3, 1.2.3-rc.1 and nightly-ab49c20f
BUILD_VERSION_REGEX = r"^(\d+\.\d+\.\d+(-rc\.\d+)?|nightly-[a-f0-9]{7,8})$"


logger = get_logger()


def _get_build_version() -> Optional[str]:
    """Try to get the build version from BUILD_VERSION_FILE_PATH and validate it.

    :return: The build version or None, if there is no file or the version is invalid.
    """
    if not os.path.isfile(BUILD_VERSION_FILE_PATH):
        return None

    with open(BUILD_VERSION_FILE_PATH, 'r') as f:
        build_version = f.readline()
        match = re.match(BUILD_VERSION_REGEX, build_version)

        if match:
            return build_version
        else:
            logger.warn("A build version with an invalid format was found. Ignoring it.", build_version=build_version)
            return None


def _get_version() -> str:
    """Get the current hathor-core version from the build version or the default one with a local suffix

    :return: The current hathor-core version
    """
    local_version = BASE_VERSION + DEFAULT_VERSION_SUFFIX
    return _get_build_version() or local_version


__version__ = _get_version()
