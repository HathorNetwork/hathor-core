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
import os
from pathlib import Path
from typing import Any, Union

import yaml

from hathor.utils.dict import deep_merge

_EXTENDS_KEY = 'extends'


def dict_from_yaml(*, filepath: Union[Path, str]) -> dict[str, Any]:
    """Takes a filepath to a yaml file and returns a dictionary with its contents."""
    if not os.path.isfile(filepath):
        raise ValueError(f"'{filepath}' is not a file")

    with open(filepath, 'r') as file:
        contents = yaml.safe_load(file)

        if contents is None:
            return {}

        if not isinstance(contents, dict):
            raise ValueError(f"'{filepath}' cannot be parsed as a dictionary")

        return contents


def dict_from_extended_yaml(*, filepath: Union[Path, str]) -> dict[str, Any]:
    """
    Takes a filepath to a yaml file and returns a dictionary with its contents.
    Supports extending another yaml file via the 'extends' key in the file.

    Note: the 'extends' key is reserved and will not be present in the returned dictionary.
    To opt-out of the extension feature, use dict_from_yaml().
    """
    extension_dict = dict_from_yaml(filepath=filepath)
    base_file = extension_dict.pop(_EXTENDS_KEY, None)

    if not base_file:
        return extension_dict

    root_path = Path(filepath).parent
    base_filepath = root_path / str(base_file)

    if not os.path.isfile(base_filepath):
        raise ValueError(f"'{base_filepath}' is not a file")

    assert base_filepath.resolve() != Path(filepath).resolve(), 'cannot extend self'

    base_dict = dict_from_yaml(filepath=base_filepath)

    deep_merge(base_dict, extension_dict)

    return base_dict
