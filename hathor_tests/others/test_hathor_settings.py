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
from typing import Any
from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

from hathor.checkpoint import Checkpoint
from hathor.conf import MAINNET_SETTINGS_FILEPATH
from hathor.conf.mainnet import SETTINGS as MAINNET_SETTINGS
from hathor.conf.settings import DECIMAL_PLACES, GENESIS_TOKEN_UNITS, GENESIS_TOKENS, HathorSettings
from hathorlib.conf.utils import load_yaml_settings


@pytest.mark.parametrize('filepath', ['fixtures/valid_hathor_settings_fixture.yml'])
def test_valid_hathor_settings_from_yaml(filepath):
    parent_dir = Path(__file__).parent
    settings_filepath = str(parent_dir / filepath)

    expected_hathor_settings = HathorSettings(
        P2PKH_VERSION_BYTE=b'\x28',
        MULTISIG_VERSION_BYTE=b'\x64',
        NETWORK_NAME='testing',
        BOOTSTRAP_DNS=['mainnet.hathor.network'],
        ENABLE_PEER_WHITELIST=True,
        WHITELIST_URL='https://hathor-public-files.s3.amazonaws.com/whitelist_peer_ids',
        MIN_TX_WEIGHT_K=0,
        MIN_TX_WEIGHT_COEFFICIENT=0,
        MIN_TX_WEIGHT=8,
        GENESIS_OUTPUT_SCRIPT=bytes.fromhex('76a9147fd4ae0e4fb2d2854e76d359029d8078bb99649e88ac'),
        GENESIS_BLOCK_TIMESTAMP=1578075305,
        GENESIS_BLOCK_NONCE=2591358,
        GENESIS_BLOCK_HASH=bytes.fromhex('000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc'),
        GENESIS_TX1_NONCE=7715,
        GENESIS_TX1_HASH=bytes.fromhex('0002d4d2a15def7604688e1878ab681142a7b155cbe52a6b4e031250ae96db0a'),
        GENESIS_TX2_NONCE=3769,
        GENESIS_TX2_HASH=bytes.fromhex('0002ad8d1519daaddc8e1a37b14aac0b045129c01832281fb1c02d873c7abbf9'),
        CHECKPOINTS=[
            Checkpoint(100_000, bytes.fromhex('0000000000001247073138556b4f60fff3ff6eec6521373ccee5a6526a7c10af')),
            Checkpoint(200_000, bytes.fromhex('00000000000001bf13197340ae0807df2c16f4959da6054af822550d7b20e19e')),
        ],
        SOFT_VOIDED_TX_IDS=[
            bytes.fromhex('0000000012a922a6887497bed9c41e5ed7dc7213cae107db295602168266cd02'),
            bytes.fromhex('000000001980b413ad5b5c5152338093aecfb1f5a7563d4e7fef8fb240a50bb9'),
        ],
        REWARD_SPEND_MIN_BLOCKS=10,
        SLOW_ASSERTS=True,
        MAX_TX_WEIGHT_DIFF_ACTIVATION=0.0,
        BLOCKS_PER_HALVING=120,
        MIN_BLOCK_WEIGHT=2,
        MIN_SHARE_WEIGHT=2,
        MAX_TX_WEIGHT_DIFF=25.0,
        BLOCK_DIFFICULTY_N_BLOCKS=20,
    )

    assert expected_hathor_settings == load_yaml_settings(HathorSettings, filepath=settings_filepath)


@pytest.mark.parametrize(
    ['filepath', 'error'],
    [
        ('fixtures/invalid_byte_hathor_settings_fixture.yml', "Value error, expected 'str' or 'bytes', got 64"),
        (
            'fixtures/invalid_features_hathor_settings_fixture.yml',
            'Value error, timeout_height should be a multiple of evaluation_interval: 2001 % 1000 != 0'
        )
    ]
)
def test_invalid_hathor_settings_from_yaml(filepath, error):
    parent_dir = Path(__file__).parent
    settings_filepath = str(parent_dir / filepath)

    with pytest.raises(ValidationError) as e:
        load_yaml_settings(HathorSettings, filepath=settings_filepath)

    errors = e.value.errors()
    assert errors[0]['msg'] == error


@pytest.mark.parametrize('filepath', ['fixtures/missing_hathor_settings_fixture.yml'])
def test_missing_hathor_settings_from_yaml(filepath):
    parent_dir = Path(__file__).parent
    settings_filepath = str(parent_dir / filepath)

    with pytest.raises(ValidationError) as e:
        load_yaml_settings(HathorSettings, filepath=settings_filepath)

    assert "validation error for HathorSettings\nNETWORK_NAME" in str(e.value)


def test_tokens() -> None:
    yaml_mock = Mock()
    required_settings = dict(P2PKH_VERSION_BYTE='x01', MULTISIG_VERSION_BYTE='x02', NETWORK_NAME='test')

    def mock_settings(mock: Mock, settings_: dict[str, Any]) -> None:
        mock.return_value = required_settings | settings_

    with patch('hathorlib.utils.yaml.dict_from_extended_yaml', yaml_mock):
        # Test default values passes
        mock_settings(yaml_mock, dict(
            GENESIS_TOKENS=GENESIS_TOKENS,
            GENESIS_TOKEN_UNITS=GENESIS_TOKEN_UNITS,
            DECIMAL_PLACES=DECIMAL_PLACES,
        ))
        load_yaml_settings(HathorSettings, filepath='some_path')

        # Test failures
        mock_settings(yaml_mock, dict(
            GENESIS_TOKENS=GENESIS_TOKENS + 1,
            GENESIS_TOKEN_UNITS=GENESIS_TOKEN_UNITS,
            DECIMAL_PLACES=DECIMAL_PLACES,
        ))
        with pytest.raises(ValidationError) as e:
            load_yaml_settings(HathorSettings, filepath='some_path')
        assert (
            'invalid tokens: GENESIS_TOKENS=100000000001, GENESIS_TOKEN_UNITS=1000000000, DECIMAL_PLACES=2'
        ) in str(e.value)

        mock_settings(yaml_mock, dict(
            GENESIS_TOKENS=GENESIS_TOKENS,
            GENESIS_TOKEN_UNITS=GENESIS_TOKEN_UNITS + 1,
            DECIMAL_PLACES=DECIMAL_PLACES,
        ))
        with pytest.raises(ValidationError) as e:
            load_yaml_settings(HathorSettings, filepath='some_path')
        assert (
            'invalid tokens: GENESIS_TOKENS=100000000000, GENESIS_TOKEN_UNITS=1000000001, DECIMAL_PLACES=2'
        ) in str(e.value)

        mock_settings(yaml_mock, dict(
            GENESIS_TOKENS=GENESIS_TOKENS,
            GENESIS_TOKEN_UNITS=GENESIS_TOKEN_UNITS,
            DECIMAL_PLACES=DECIMAL_PLACES + 1,
        ))
        with pytest.raises(ValidationError) as e:
            load_yaml_settings(HathorSettings, filepath='some_path')
        assert (
            'invalid tokens: GENESIS_TOKENS=100000000000, GENESIS_TOKEN_UNITS=1000000000, DECIMAL_PLACES=3'
        ) in str(e.value)


def test_token_deposit_percentage() -> None:
    yaml_mock = Mock()
    required_settings = dict(P2PKH_VERSION_BYTE='x01', MULTISIG_VERSION_BYTE='x02', NETWORK_NAME='test')

    def mock_settings(mock: Mock, settings_: dict[str, Any]) -> None:
        mock.return_value = required_settings | settings_

    with patch('hathorlib.utils.yaml.dict_from_extended_yaml', yaml_mock.dict_from_extended_yaml):
        # Test default value passes (0.01 results in FEE_DIVISOR=100)
        mock_settings(yaml_mock, dict(TOKEN_DEPOSIT_PERCENTAGE=0.01))
        load_yaml_settings(HathorSettings, filepath='some_path')

        # Test fails when TOKEN_DEPOSIT_PERCENTAGE results in non-integer FEE_DIVISOR (0.03 -> 33.333...)
        mock_settings(yaml_mock, dict(TOKEN_DEPOSIT_PERCENTAGE=0.03))
        with pytest.raises(ValidationError) as e:
            load_yaml_settings(HathorSettings, filepath='some_path')
        assert 'TOKEN_DEPOSIT_PERCENTAGE must result in an integer FEE_DIVISOR' in str(e.value)
        assert 'TOKEN_DEPOSIT_PERCENTAGE=0.03' in str(e.value)

        # Test fails when TOKEN_DEPOSIT_PERCENTAGE results in non-integer FEE_DIVISOR (0.07 -> 14.285...)
        mock_settings(yaml_mock, dict(TOKEN_DEPOSIT_PERCENTAGE=0.07))
        with pytest.raises(ValidationError) as e:
            load_yaml_settings(HathorSettings, filepath='some_path')
        assert 'TOKEN_DEPOSIT_PERCENTAGE must result in an integer FEE_DIVISOR' in str(e.value)
        assert 'TOKEN_DEPOSIT_PERCENTAGE=0.07' in str(e.value)


def test_consensus_algorithm() -> None:
    required_settings = dict(P2PKH_VERSION_BYTE='x01', MULTISIG_VERSION_BYTE='x02', NETWORK_NAME='test')
    yaml_mock = Mock(return_value=required_settings)

    def mock_settings(mock: Mock, settings_: dict[str, Any]) -> None:
        mock.return_value = required_settings | settings_
        # mock = Mock(return_value=required_settings | settings_)

    with patch('hathorlib.utils.yaml.dict_from_extended_yaml', yaml_mock):
        # Test passes when PoA is disabled with default settings
        mock_settings(yaml_mock, dict())
        load_yaml_settings(HathorSettings, filepath='some_path')

        # Test fails when PoA is enabled with default settings
        mock_settings(yaml_mock, dict(
            CONSENSUS_ALGORITHM=dict(
                type='PROOF_OF_AUTHORITY',
                signers=(dict(public_key=b'some_signer'),)
            )
        ))
        with pytest.raises(ValidationError) as e:
            load_yaml_settings(HathorSettings, filepath='some_path')
        assert 'PoA networks do not support block rewards' in str(e.value)

        # Test passes when PoA is enabled without block rewards
        mock_settings(yaml_mock, dict(
            BLOCKS_PER_HALVING=None,
            INITIAL_TOKEN_UNITS_PER_BLOCK=0,
            MINIMUM_TOKEN_UNITS_PER_BLOCK=0,
            CONSENSUS_ALGORITHM=dict(type='PROOF_OF_AUTHORITY', signers=(dict(public_key=b'some_signer'),)),
        ))
        load_yaml_settings(HathorSettings, filepath='some_path')

        # Test fails when no signer is provided
        mock_settings(yaml_mock, dict(
            BLOCKS_PER_HALVING=None,
            INITIAL_TOKEN_UNITS_PER_BLOCK=0,
            MINIMUM_TOKEN_UNITS_PER_BLOCK=0,
            CONSENSUS_ALGORITHM=dict(type='PROOF_OF_AUTHORITY', signers=()),
        ))
        with pytest.raises(ValidationError) as e:
            load_yaml_settings(HathorSettings, filepath='some_path')
        assert 'At least one signer must be provided in PoA networks' in str(e.value)

        # Test fails when PoA is enabled with BLOCKS_PER_HALVING
        mock_settings(yaml_mock, dict(
            BLOCKS_PER_HALVING=123,
            INITIAL_TOKEN_UNITS_PER_BLOCK=0,
            MINIMUM_TOKEN_UNITS_PER_BLOCK=0,
            CONSENSUS_ALGORITHM=dict(type='PROOF_OF_AUTHORITY', signers=(dict(public_key=b'some_signer'),)),
        ))
        with pytest.raises(ValidationError) as e:
            load_yaml_settings(HathorSettings, filepath='some_path')
        assert 'PoA networks do not support block rewards' in str(e.value)

        # Test fails when PoA is enabled with INITIAL_TOKEN_UNITS_PER_BLOCK
        mock_settings(yaml_mock, dict(
            BLOCKS_PER_HALVING=None,
            INITIAL_TOKEN_UNITS_PER_BLOCK=123,
            MINIMUM_TOKEN_UNITS_PER_BLOCK=0,
            CONSENSUS_ALGORITHM=dict(type='PROOF_OF_AUTHORITY', signers=(dict(public_key=b'some_signer'),)),
        ))
        with pytest.raises(ValidationError) as e:
            load_yaml_settings(HathorSettings, filepath='some_path')
        assert 'PoA networks do not support block rewards' in str(e.value)

        # Test fails when PoA is enabled with MINIMUM_TOKEN_UNITS_PER_BLOCK
        mock_settings(yaml_mock, dict(
            BLOCKS_PER_HALVING=None,
            INITIAL_TOKEN_UNITS_PER_BLOCK=0,
            MINIMUM_TOKEN_UNITS_PER_BLOCK=123,
            CONSENSUS_ALGORITHM=dict(type='PROOF_OF_AUTHORITY', signers=(dict(public_key=b'some_signer'),)),
        ))
        with pytest.raises(ValidationError) as e:
            load_yaml_settings(HathorSettings, filepath='some_path')
        assert 'PoA networks do not support block rewards' in str(e.value)


# TODO: Tests below are temporary while settings via python coexist with settings via yaml, just to make sure
#  the conversion was made correctly. After python settings are removed, this file can be removed too.


def test_mainnet_settings_migration():
    assert MAINNET_SETTINGS == load_yaml_settings(HathorSettings, filepath=MAINNET_SETTINGS_FILEPATH)
