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

import platform
import sys
from pathlib import Path

import pytest

from hathor.utils.yaml import dict_from_extended_yaml, dict_from_yaml


def _get_absolute_filepath(filepath: str) -> Path:
    parent_dir = Path(__file__).parent

    return parent_dir / filepath


def test_dict_from_yaml_invalid_filepath():
    with pytest.raises(ValueError) as e:
        dict_from_yaml(filepath='fake_file.yml')

    assert str(e.value) == "'fake_file.yml' is not a file"


def test_dict_from_yaml_empty():
    filepath = _get_absolute_filepath('fixtures/empty.yml')
    result = dict_from_yaml(filepath=filepath)

    assert result == {}


def test_dict_from_yaml_invalid_contents():
    filepath = _get_absolute_filepath('fixtures/number.yml')

    with pytest.raises(ValueError) as e:
        dict_from_yaml(filepath=filepath)

    assert str(e.value) == f"'{filepath}' cannot be parsed as a dictionary"


def test_dict_from_yaml_valid():
    filepath = _get_absolute_filepath('fixtures/valid.yml')
    result = dict_from_yaml(filepath=filepath)

    assert result == dict(a=1, b=dict(c=2, d=3))


def test_dict_from_extended_yaml_invalid_filepath():
    with pytest.raises(ValueError) as e:
        dict_from_extended_yaml(filepath='fake_file.yml')

    assert str(e.value) == "'fake_file.yml' is not a file"


def test_dict_from_extended_yaml_empty():
    filepath = _get_absolute_filepath('fixtures/empty.yml')
    result = dict_from_extended_yaml(filepath=filepath)

    assert result == {}


def test_dict_from_extended_yaml_invalid_contents():
    filepath = _get_absolute_filepath('fixtures/number.yml')

    with pytest.raises(ValueError) as e:
        dict_from_extended_yaml(filepath=filepath)

    assert str(e.value) == f"'{filepath}' cannot be parsed as a dictionary"


def test_dict_from_extended_yaml_valid():
    filepath = _get_absolute_filepath('fixtures/valid.yml')
    result = dict_from_extended_yaml(filepath=filepath)

    assert result == dict(a=1, b=dict(c=2, d=3))


def test_dict_from_extended_yaml_empty_extends():
    filepath = _get_absolute_filepath('fixtures/empty_extends.yml')
    result = dict_from_extended_yaml(filepath=filepath)

    assert result == dict(a='aa', b=dict(d='dd', e='ee'))


def test_dict_from_extended_yaml_invalid_extends():
    filepath = _get_absolute_filepath('fixtures/invalid_extends.yml')

    with pytest.raises(ValueError) as e:
        dict_from_extended_yaml(filepath=filepath)

    assert "unknown_file.yml' is not a file" in str(e.value)


@pytest.mark.skipif(
    sys.platform == 'win32' and platform.python_version().startswith('3.10.'),
    reason='The recursion fails before RecursionError is raised in Windows with Python 3.10'
)
def test_dict_from_extended_yaml_recursive_extends():
    filepath = _get_absolute_filepath('fixtures/self_extends.yml')

    with pytest.raises(ValueError) as e:
        dict_from_extended_yaml(filepath=filepath)

    assert str(e.value) == 'Cannot parse yaml with recursive extensions.'


def test_dict_from_extended_yaml_valid_extends():
    filepath = _get_absolute_filepath('fixtures/valid_extends.yml')
    result = dict_from_extended_yaml(filepath=filepath)

    assert result == dict(a='aa', b=dict(c=2, d='dd', e='ee'))


def test_dict_from_yaml_mainnet_extends():
    from hathor.conf import MAINNET_SETTINGS_FILEPATH

    filepath = _get_absolute_filepath('fixtures/mainnet_extends.yml')
    mainnet_dict = dict_from_yaml(filepath=MAINNET_SETTINGS_FILEPATH)
    result = dict_from_extended_yaml(filepath=filepath, custom_root=Path(MAINNET_SETTINGS_FILEPATH).parent)

    assert result == dict(**mainnet_dict, a='aa', b=dict(d='dd', e='ee'))
