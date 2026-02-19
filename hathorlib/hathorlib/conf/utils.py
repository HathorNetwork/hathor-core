"""
Copyright (c) Hathor Labs and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
"""
import importlib
from pydantic import BaseModel

from typing import Union, TypeVar


T = TypeVar('T', bound=BaseModel)


def parse_hex_str(hex_str: Union[str, bytes]) -> bytes:
    """Parse a raw hex string into bytes."""
    if isinstance(hex_str, str):
        return bytes.fromhex(hex_str.lstrip('x'))

    if not isinstance(hex_str, bytes):
        raise ValueError(f'expected \'str\' or \'bytes\', got {hex_str}')

    return hex_str


def _load_module_settings(model: type[T], module_path: str) -> T:
    settings_module = importlib.import_module(module_path)
    settings = getattr(settings_module, 'SETTINGS')
    return model.model_validate(settings)


def _load_yaml_settings(model: type[T], filepath: str) -> T:
    from hathorlib.utils.yaml import model_from_yaml
    return model_from_yaml(model, filepath=filepath)
