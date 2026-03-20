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
from typing import Any, Optional, TypeVar, Union

import yaml
from pydantic import BaseModel

from hathorlib.utils.dict import deep_merge

_EXTENDS_KEY = 'extends'

T = TypeVar('T', bound=BaseModel)


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


def dict_from_extended_yaml(*, filepath: Union[Path, str], custom_root: Optional[Path] = None) -> dict[str, Any]:
    """
    Takes a filepath to a yaml file and returns a dictionary with its contents.

    Supports extending another yaml file via the 'extends' key in the file. The 'extends' value can be an absolute path
    to a yaml file, or a path relative to the base yaml file. The custom_root arg can be provided to set a custom root
    for relative paths, taking lower precedence.

    Note: the 'extends' key is reserved and will not be present in the returned dictionary.
    To opt-out of the extension feature, use dict_from_yaml().
    """
    extension_dict = dict_from_yaml(filepath=filepath)
    file_to_extend = extension_dict.pop(_EXTENDS_KEY, None)

    if not file_to_extend:
        return extension_dict

    filepath_to_extend = Path(filepath).parent / str(file_to_extend)

    if not os.path.isfile(filepath_to_extend) and custom_root:
        filepath_to_extend = custom_root / str(file_to_extend)

    try:
        dict_to_extend = dict_from_extended_yaml(filepath=filepath_to_extend, custom_root=custom_root)
    except RecursionError as e:
        raise ValueError('Cannot parse yaml with recursive extensions.') from e

    extended_dict = deep_merge(dict_to_extend, extension_dict)

    return extended_dict


def model_from_extended_yaml(model: type[T], *, filepath: str, custom_root: Optional[Path] = None) -> T:
    """Takes a pydantic model and a filepath to a yaml file and returns a validated model instance."""
    settings_dict = dict_from_extended_yaml(filepath=filepath, custom_root=custom_root)

    return model.model_validate(settings_dict)
