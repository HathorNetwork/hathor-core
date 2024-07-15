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

from unittest.mock import Mock

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.consensus import poa
from hathor.consensus.consensus_settings import PoaSettings
from hathor.consensus.poa.poa_signer import PoaSigner, PoaSignerFile
from hathor.crypto.util import get_address_b58_from_public_key, get_private_key_bytes, get_public_key_bytes_compressed
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import BlockIsMissingSignal, BlockIsSignaling, FeatureService
from hathor.transaction import Block, TransactionMetadata, TxOutput
from hathor.transaction.exceptions import BlockMustSignalError, PoaValidationError
from hathor.transaction.poa import PoaBlock
from hathor.transaction.storage import TransactionMemoryStorage, TransactionStorage
from hathor.verification.block_verifier import BlockVerifier
from hathor.verification.poa_block_verifier import PoaBlockVerifier


def test_calculate_feature_activation_bit_counts_genesis():
    settings = get_global_settings()
    storage = TransactionMemoryStorage(settings=settings)
    genesis_block = storage.get_transaction(settings.GENESIS_BLOCK_HASH)
    assert isinstance(genesis_block, Block)
    result = genesis_block.get_feature_activation_bit_counts()

    assert result == [0, 0, 0, 0]


@pytest.fixture
def block_mocks() -> list[Block]:
    settings = get_global_settings()
    blocks: list[Block] = []
    feature_activation_bits = [
        0b0000,  # 0: boundary block
        0b1010,
        0b1110,
        0b1110,

        0b0011,  # 4: boundary block
        0b0111,
        0b1111,
        0b0101,

        0b0000,  # 8: boundary block
        0b0000,
    ]

    for i, bits in enumerate(feature_activation_bits):
        genesis_hash = settings.GENESIS_BLOCK_HASH
        block_hash = genesis_hash if i == 0 else b'some_hash'

        storage = Mock(spec_set=TransactionStorage)
        storage.get_metadata = Mock(return_value=None)

        block = Block(hash=block_hash, storage=storage, signal_bits=bits)
        blocks.append(block)

        get_block_parent_mock = Mock(return_value=blocks[i - 1])
        setattr(block, 'get_block_parent', get_block_parent_mock)

    return blocks


@pytest.mark.parametrize(
    ['block_height', 'expected_counts'],
    [
        (0, [0, 0, 0, 0]),
        (1, [0, 1, 0, 1]),
        (2, [0, 2, 1, 2]),
        (3, [0, 3, 2, 3]),
        (4, [1, 1, 0, 0]),
        (5, [2, 2, 1, 0]),
        (6, [3, 3, 2, 1]),
        (7, [4, 3, 3, 1]),
        (8, [0, 0, 0, 0]),
        (9, [0, 0, 0, 0]),
    ]
)
def test_calculate_feature_activation_bit_counts(
    block_mocks: list[Block],
    block_height: int,
    expected_counts: list[int]
) -> None:
    block = block_mocks[block_height]
    result = block.get_feature_activation_bit_counts()

    assert result == expected_counts


def test_get_height():
    block_hash = b'some_hash'
    block_height = 10
    metadata = TransactionMetadata(hash=block_hash, height=block_height)

    storage = Mock(spec_set=TransactionStorage)
    storage.get_metadata = Mock(side_effect=lambda _hash: metadata if _hash == block_hash else None)

    block = Block(hash=block_hash, storage=storage)

    assert block.get_height() == block_height


@pytest.mark.parametrize(
    ['signal_bits', 'expected_bit_list'],
    [
        (0x00, [0, 0, 0, 0]),  # 0
        (0x01, [1, 0, 0, 0]),  # 1
        (0xF1, [1, 0, 0, 0]),  # 1
        (0x07, [1, 1, 1, 0]),  # 7
        (0xF7, [1, 1, 1, 0]),  # 7
        (0x0F, [1, 1, 1, 1]),  # 0xF
        (0xFF, [1, 1, 1, 1]),  # 0xF
    ]
)
def test_get_feature_activation_bit_list(signal_bits: int, expected_bit_list: list[int]) -> None:
    block = Block(signal_bits=signal_bits)
    result = block._get_feature_activation_bit_list()

    assert result == expected_bit_list


def test_get_feature_activation_bit_value() -> None:
    block = Block(signal_bits=0b0000_0100)

    assert block.get_feature_activation_bit_value(0) == 0
    assert block.get_feature_activation_bit_value(1) == 0
    assert block.get_feature_activation_bit_value(2) == 1
    assert block.get_feature_activation_bit_value(3) == 0


def test_verify_must_signal() -> None:
    settings = Mock(spec_set=HathorSettings)
    feature_service = Mock(spec_set=FeatureService)
    feature_service.is_signaling_mandatory_features = Mock(
        return_value=BlockIsMissingSignal(feature=Feature.NOP_FEATURE_1)
    )
    verifier = BlockVerifier(settings=settings, feature_service=feature_service, daa=Mock())
    block = Block()

    with pytest.raises(BlockMustSignalError) as e:
        verifier.verify_mandatory_signaling(block)

    assert str(e.value) == "Block must signal support for feature 'NOP_FEATURE_1' during MUST_SIGNAL phase."


def test_verify_must_not_signal() -> None:
    settings = Mock(spec_set=HathorSettings)
    feature_service = Mock(spec_set=FeatureService)
    feature_service.is_signaling_mandatory_features = Mock(return_value=BlockIsSignaling())
    verifier = BlockVerifier(settings=settings, feature_service=feature_service, daa=Mock())
    block = Block()

    verifier.verify_mandatory_signaling(block)


def test_get_hashed_poa_data() -> None:
    block = PoaBlock(
        timestamp=123,
        signal_bits=0b1010,
        weight=2,
        parents=[b'\xFF' * 32, b'\xFF' * 32],
        data=b'some data',
        signer_id=b'\xAB\xCD',
        signature=b'some signature'
    )

    def clone_block() -> PoaBlock:
        return PoaBlock.create_from_struct(block.get_struct())

    # Test that each field changes the PoA data
    test_block = clone_block()
    test_block.nonce += 1
    assert poa.get_hashed_poa_data(test_block) != poa.get_hashed_poa_data(block)

    test_block = clone_block()
    test_block.timestamp += 1
    assert poa.get_hashed_poa_data(test_block) != poa.get_hashed_poa_data(block)

    test_block = clone_block()
    test_block.signal_bits += 1
    assert poa.get_hashed_poa_data(test_block) != poa.get_hashed_poa_data(block)

    test_block = clone_block()
    test_block.weight += 1
    assert poa.get_hashed_poa_data(test_block) != poa.get_hashed_poa_data(block)

    test_block = clone_block()
    test_block.parents.pop()
    assert poa.get_hashed_poa_data(test_block) != poa.get_hashed_poa_data(block)

    test_block = clone_block()
    test_block.data = b'some other data'
    assert poa.get_hashed_poa_data(test_block) != poa.get_hashed_poa_data(block)

    # Test that changing PoA fields do not change PoA data
    test_block = clone_block()
    test_block.signer_id = b'\x00\xFF'
    assert poa.get_hashed_poa_data(test_block) == poa.get_hashed_poa_data(block)

    test_block = clone_block()
    test_block.signature = b'some other signature'
    assert poa.get_hashed_poa_data(test_block) == poa.get_hashed_poa_data(block)


def test_verify_poa() -> None:
    def get_signer() -> tuple[PoaSigner, bytes]:
        private_key = ec.generate_private_key(ec.SECP256K1())
        private_key_bytes = get_private_key_bytes(private_key)  # type: ignore[arg-type]
        public_key = private_key.public_key()
        public_key_bytes = get_public_key_bytes_compressed(public_key)
        address = get_address_b58_from_public_key(public_key)
        file = PoaSignerFile.parse_obj(dict(
            private_key_hex=private_key_bytes.hex(),
            public_key_hex=public_key_bytes.hex(),
            address=address
        ))
        return file.get_signer(), public_key_bytes

    poa_signer, public_key_bytes = get_signer()
    settings = Mock(spec_set=HathorSettings)
    settings.CONSENSUS_ALGORITHM = PoaSettings.construct(signers=())
    block_verifier = PoaBlockVerifier(settings=settings)
    block = PoaBlock(
        timestamp=123,
        signal_bits=0b1010,
        weight=poa.BLOCK_WEIGHT_IN_TURN,
        parents=[b'parent1', b'parent2'],
    )
    block._metadata = Mock()
    block._metadata.height = 2

    # Test no rewards
    block.outputs = [TxOutput(123, b'')]
    with pytest.raises(PoaValidationError) as e:
        block_verifier.verify_poa(block)
    assert str(e.value) == 'blocks must not have rewards in a PoA network'
    block.outputs = []

    # Test no signers
    settings.CONSENSUS_ALGORITHM = PoaSettings.construct(signers=())
    with pytest.raises(PoaValidationError) as e:
        block_verifier.verify_poa(block)
    assert str(e.value) == 'invalid PoA signature'

    # Test no data
    settings.CONSENSUS_ALGORITHM = PoaSettings(signers=(public_key_bytes,))
    with pytest.raises(PoaValidationError) as e:
        block_verifier.verify_poa(block)
    assert str(e.value) == 'invalid PoA signature'

    # Test invalid data
    block.data = b'some_data'
    with pytest.raises(PoaValidationError) as e:
        block_verifier.verify_poa(block)
    assert str(e.value) == 'invalid PoA signature'

    # Test incorrect private key
    PoaSigner(ec.generate_private_key(ec.SECP256K1())).sign_block(block)
    with pytest.raises(PoaValidationError) as e:
        block_verifier.verify_poa(block)
    assert str(e.value) == 'invalid PoA signature'

    # Test valid signature
    poa_signer.sign_block(block)
    block_verifier.verify_poa(block)

    # Test some random weight fails
    block.weight = 123
    poa_signer.sign_block(block)
    with pytest.raises(PoaValidationError) as e:
        block_verifier.verify_poa(block)
    assert str(e.value) == 'block weight is 123, expected 2.0'

    # For this part we use two signers, so the ordering matters
    signer_and_keys: list[tuple[PoaSigner, bytes]] = [get_signer(), get_signer()]
    sorted_keys = sorted(signer_and_keys, key=lambda key_pair: key_pair[1])  # sort by public key
    settings.CONSENSUS_ALGORITHM = PoaSettings(signers=tuple([key_pair[1] for key_pair in signer_and_keys]))
    first_poa_signer, second_poa_signer = [key_pair[0] for key_pair in sorted_keys]

    # Test valid signature with two signers, in turn
    block.weight = poa.BLOCK_WEIGHT_IN_TURN
    first_poa_signer.sign_block(block)
    block_verifier.verify_poa(block)

    # And the other signature fails for the weight
    second_poa_signer.sign_block(block)
    with pytest.raises(PoaValidationError) as e:
        block_verifier.verify_poa(block)
    assert str(e.value) == 'block weight is 2.0, expected 1.0'

    # Test valid signature with two signers, out of turn
    block.weight = poa.BLOCK_WEIGHT_OUT_OF_TURN
    second_poa_signer.sign_block(block)
    block_verifier.verify_poa(block)

    # And the other signature fails for the weight
    first_poa_signer.sign_block(block)
    with pytest.raises(PoaValidationError) as e:
        block_verifier.verify_poa(block)
    assert str(e.value) == 'block weight is 1.0, expected 2.0'

    # When we increment the height, the turn inverts
    block._metadata.height += 1

    # Test valid signature with two signers, in turn
    block.weight = poa.BLOCK_WEIGHT_IN_TURN
    second_poa_signer.sign_block(block)
    block_verifier.verify_poa(block)

    # And the other signature fails for the weight
    first_poa_signer.sign_block(block)
    with pytest.raises(PoaValidationError) as e:
        block_verifier.verify_poa(block)
    assert str(e.value) == 'block weight is 2.0, expected 1.0'

    # Test valid signature with two signers, out of turn
    block.weight = poa.BLOCK_WEIGHT_OUT_OF_TURN
    first_poa_signer.sign_block(block)
    block_verifier.verify_poa(block)

    # And the other signature fails for the weight
    second_poa_signer.sign_block(block)
    with pytest.raises(PoaValidationError) as e:
        block_verifier.verify_poa(block)
    assert str(e.value) == 'block weight is 1.0, expected 2.0'
