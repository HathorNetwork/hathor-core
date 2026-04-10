# Copyright 2026 Hathor Labs
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
import importlib
from pathlib import Path
from typing import TypeVar, Union

from pydantic import BaseModel

T = TypeVar('T', bound=BaseModel)


def parse_hex_str(hex_str: Union[str, bytes]) -> bytes:
    """Parse a raw hex string into bytes."""
    if isinstance(hex_str, str):
        return bytes.fromhex(hex_str.lstrip('x'))

    if not isinstance(hex_str, bytes):
        raise ValueError(f'expected \'str\' or \'bytes\', got {hex_str}')

    return hex_str


def load_yaml_settings(model: type[T], filepath: str) -> T:
    """
    Load a settings model (pydantic based) and a filepath to a yaml file and returns a validated instance.
    YAML settings may use the `extends` key to merge definition with another existing file.
    """
    from hathorlib.utils.yaml import model_from_extended_yaml
    return model_from_extended_yaml(model, filepath=filepath, custom_root=Path(__file__).parent)


def load_module_settings(model: type[T], module_path: str) -> T:
    """Load module"""
    settings_module = importlib.import_module(module_path)
    settings = getattr(settings_module, 'SETTINGS')
    return model.model_validate(settings)
