#  Copyright 2024 Hathor Labs
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

from hathor.conf.settings import HathorSettings
from hathor.consensus import poa
from hathor.consensus.consensus_settings import PoaSettings
from hathor.consensus.poa.poa_signer import PoaSigner, PoaSignerFile
from hathor.crypto.util import get_address_b58_from_public_key, get_private_key_bytes, get_public_key_bytes_compressed
from hathor.transaction import TxOutput
from hathor.transaction.exceptions import PoaValidationError
from hathor.transaction.poa import PoaBlock
from hathor.verification.poa_block_verifier import PoaBlockVerifier


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


@pytest.mark.parametrize(
    ['n_signers', 'height', 'signer_index', 'expected'],
    [
        (1, 1, 0, True),
        (1, 2, 0, True),
        (1, 3, 0, True),

        (2, 1, 0, False),
        (2, 2, 0, True),
        (2, 3, 0, False),

        (2, 1, 1, True),
        (2, 2, 1, False),
        (2, 3, 1, True),
    ]
)
def test_is_in_turn(n_signers: int, height: int, signer_index: int, expected: bool) -> None:
    settings = PoaSettings.construct(signers=tuple(b'' for _ in range(n_signers)))

    result = poa.is_in_turn(settings=settings, height=height, signer_index=signer_index)
    assert result == expected


@pytest.mark.parametrize(
    ['n_signers', 'height', 'signer_index', 'expected'],
    [
        (1, 1, 0, poa.BLOCK_WEIGHT_IN_TURN),
        (1, 2, 0, poa.BLOCK_WEIGHT_IN_TURN),
        (1, 3, 0, poa.BLOCK_WEIGHT_IN_TURN),

        (2, 1, 0, poa.BLOCK_WEIGHT_OUT_OF_TURN),
        (2, 2, 0, poa.BLOCK_WEIGHT_IN_TURN),
        (2, 3, 0, poa.BLOCK_WEIGHT_OUT_OF_TURN),

        (2, 1, 1, poa.BLOCK_WEIGHT_IN_TURN),
        (2, 2, 1, poa.BLOCK_WEIGHT_OUT_OF_TURN),
        (2, 3, 1, poa.BLOCK_WEIGHT_IN_TURN),
    ]
)
def test_calculate_weight(n_signers: int, height: int, signer_index: int, expected: float) -> None:
    settings = PoaSettings.construct(signers=tuple(b'' for _ in range(n_signers)))
    block = Mock()
    block.get_height = Mock(return_value=height)

    result = poa.calculate_weight(settings, block, signer_index)
    assert result == expected
