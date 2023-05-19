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
from pathlib import Path

import pytest

from hathor.utils.yaml import dict_from_yaml, dict_from_extended_yaml


def test_dict_from_yaml_invalid_filepath():
    with pytest.raises(ValueError) as e:
        dict_from_yaml(filepath='fake_file.yml')

    assert str(e.value) == "'fake_file.yml' is not a file"


def test_dict_from_yaml_empty():
    parent_dir = Path(__file__).parent
    filepath = parent_dir / 'fixtures/empty.yml'

    result = dict_from_yaml(filepath=filepath)

    assert result == {}


def test_dict_from_yaml_invalid_contents():
    parent_dir = Path(__file__).parent
    filepath = parent_dir / 'fixtures/number.yml'

    with pytest.raises(ValueError) as e:
        dict_from_yaml(filepath=filepath)

    assert str(e.value) == f"'{filepath}' cannot be parsed as a dictionary"


def test_dict_from_yaml_valid():
    parent_dir = Path(__file__).parent
    filepath = parent_dir / 'fixtures/valid.yml'

    result = dict_from_yaml(filepath=filepath)

    assert result == dict(a=1, b=dict(c=2, d=3))


def test_dict_from_extended_yaml_invalid_filepath():
    with pytest.raises(ValueError) as e:
        dict_from_extended_yaml(filepath='fake_file.yml')

    assert str(e.value) == "'fake_file.yml' is not a file"


def test_dict_from_extended_yaml_empty():
    parent_dir = Path(__file__).parent
    filepath = parent_dir / 'fixtures/empty.yml'

    result = dict_from_extended_yaml(filepath=filepath)

    assert result == {}


def test_dict_from_extended_yaml_invalid_contents():
    parent_dir = Path(__file__).parent
    filepath = parent_dir / 'fixtures/number.yml'

    with pytest.raises(ValueError) as e:
        dict_from_extended_yaml(filepath=filepath)

    assert str(e.value) == f"'{filepath}' cannot be parsed as a dictionary"


def test_dict_from_extended_yaml_valid():
    parent_dir = Path(__file__).parent
    filepath = parent_dir / 'fixtures/valid.yml'

    result = dict_from_extended_yaml(filepath=filepath)

    assert result == dict(a=1, b=dict(c=2, d=3))


def test_dict_from_extended_yaml_empty_extends():
    parent_dir = Path(__file__).parent
    filepath = parent_dir / 'fixtures/empty_extends.yml'

    result = dict_from_extended_yaml(filepath=filepath)

    assert result == dict(a='aa', b=dict(d='dd', e='ee'))


def test_dict_from_extended_yaml_invalid_extends():
    parent_dir = Path(__file__).parent
    filepath = parent_dir / 'fixtures/invalid_extends.yml'

    with pytest.raises(ValueError) as e:
        dict_from_extended_yaml(filepath=filepath)

    assert "/fixtures/unknown_file.yml' is not a file" in str(e.value)


def test_dict_from_extended_yaml_self_extends():
    parent_dir = Path(__file__).parent
    filepath = parent_dir / 'fixtures/self_extends.yml'

    with pytest.raises(AssertionError) as e:
        dict_from_extended_yaml(filepath=filepath)

    assert str(e.value) == 'cannot extend self'


def test_dict_from_extended_yaml_valid_extends():
    parent_dir = Path(__file__).parent
    filepath = parent_dir / 'fixtures/valid_extends.yml'

    result = dict_from_extended_yaml(filepath=filepath)

    assert result == dict(a='aa', b=dict(c=2, d='dd', e='ee'))

