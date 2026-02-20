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
import subprocess
from typing import Optional

from structlog import get_logger

BASE_VERSION = '0.70.0'

DEFAULT_VERSION_SUFFIX = "local"
BUILD_VERSION_FILE_PATH = "./BUILD_VERSION"

from hathorlib.version import BUILD_VERSION_REGEX  # noqa: F401


logger = get_logger()


def _get_build_version() -> Optional[str]:
    """Try to get the build version from BUILD_VERSION_FILE_PATH and validate it.

    :return: The build version or None, if there is no file or the version is invalid.
    """
    if not os.path.isfile(BUILD_VERSION_FILE_PATH):
        return None

    with open(BUILD_VERSION_FILE_PATH, 'r') as f:
        build_version = f.readline().strip()
        match = re.match(BUILD_VERSION_REGEX, build_version)

        if match:
            return build_version
        else:
            logger.warn("A build version with an invalid format was found. Ignoring it.", build_version=build_version)
            return None


def _get_git_revision_short_hash() -> Optional[str]:
    try:
        return subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']).decode('ascii').strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warn((
            "Error while trying to get local git head. There is either no git available or we aren't in a git repo. "
            "Will report local version without any git info."
        ))
        return None


def _get_local_version() -> str:
    git_head = _get_git_revision_short_hash()

    if git_head:
        return f"{BASE_VERSION}-{git_head}-{DEFAULT_VERSION_SUFFIX}"

    return f"{BASE_VERSION}-{DEFAULT_VERSION_SUFFIX}"


def _get_version() -> str:
    """Get the current hathor-core version from the build version or the default one with a local suffix

    :return: The current hathor-core version
    """
    return _get_build_version() or _get_local_version()


__version__ = _get_version()
