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
from pydantic import ValidationError

from hathor.checkpoint import Checkpoint
from hathor.conf import MAINNET_SETTINGS_FILEPATH, TESTNET_SETTINGS_FILEPATH, UNITTESTS_SETTINGS_FILEPATH
from hathor.conf.mainnet import SETTINGS as MAINNET_SETTINGS
from hathor.conf.settings import HathorSettings
from hathor.conf.testnet import SETTINGS as TESTNET_SETTINGS
from hathor.conf.unittests import SETTINGS as UNITTESTS_SETTINGS

VALID_HATHOR_SETTINGS_FIXTURE_FILE = 'resources/valid_hathor_settings_fixture.yml'
INVALID_HATHOR_SETTINGS_FIXTURE_FILE = 'resources/invalid_hathor_settings_fixture.yml'
MISSING_HATHOR_SETTINGS_FIXTURE_FILE = 'resources/missing_hathor_settings_fixture.yml'


def test_valid_hathor_settings_from_yaml(hathor_settings):
    parent_dir = Path(__file__).parent
    settings_filepath = str(parent_dir / VALID_HATHOR_SETTINGS_FIXTURE_FILE)

    assert hathor_settings == HathorSettings.from_yaml(filepath=settings_filepath)


def test_invalid_hathor_settings_from_yaml():
    parent_dir = Path(__file__).parent
    settings_filepath = str(parent_dir / INVALID_HATHOR_SETTINGS_FIXTURE_FILE)

    with pytest.raises(ValidationError):
        HathorSettings.from_yaml(filepath=settings_filepath)


def test_missing_hathor_settings_from_yaml():
    parent_dir = Path(__file__).parent
    settings_filepath = str(parent_dir / MISSING_HATHOR_SETTINGS_FIXTURE_FILE)

    with pytest.raises(TypeError):
        HathorSettings.from_yaml(filepath=settings_filepath)


@pytest.fixture
def hathor_settings():
    return HathorSettings(
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
        GENESIS_TIMESTAMP=1578075305,
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
        ENABLE_EVENT_QUEUE_FEATURE=True,
        MAX_TX_WEIGHT_DIFF_ACTIVATION=0.0,
        BLOCKS_PER_HALVING=120,
        MIN_BLOCK_WEIGHT=2,
        MIN_SHARE_WEIGHT=2,
        MAX_TX_WEIGHT_DIFF=25.0,
        BLOCK_DIFFICULTY_N_BLOCKS=20,
    )


# TODO: Tests below are temporary while settings via python coexist with settings via yaml, just to make sure
#  the conversion was made correctly. After python settings are removed, this file can be removed too.


def test_mainnet_settings_migration():
    assert MAINNET_SETTINGS == HathorSettings.from_yaml(filepath=MAINNET_SETTINGS_FILEPATH)


def test_testnet_settings_migration():
    assert TESTNET_SETTINGS == HathorSettings.from_yaml(filepath=TESTNET_SETTINGS_FILEPATH)


def test_unittests_settings_migration():
    assert UNITTESTS_SETTINGS == HathorSettings.from_yaml(filepath=UNITTESTS_SETTINGS_FILEPATH)
