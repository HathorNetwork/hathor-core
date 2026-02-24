"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""
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
