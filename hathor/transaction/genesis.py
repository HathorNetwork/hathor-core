from hathor.transaction import Transaction, TxOutput
from hathor.transaction.block import Block
from hathor.constants import GENESIS_TOKENS, MAX_VALUE
import math


def genesis_transactions(tx_storage):
    TX_GENESIS1 = Transaction(
        hash=bytes.fromhex('0001569c85fffa5782c3979e7d68dce1d8d84772505a53ddd76d636585f3977d'),
        nonce=19300,
        timestamp=1539271482,
        weight=14,
        height=1,
        storage=tx_storage,
    )

    TX_GENESIS2 = Transaction(
        hash=bytes.fromhex('0000810b22f0cdc3ac6d978a4c80ea46f831b74765fefea2595cc6d4b00e207a'),
        nonce=22587,
        timestamp=1539271483,
        weight=14,
        height=1,
        storage=tx_storage,
    )

    # Genesis will have 2B tokens (we use 200B because of two decimal places)
    # We separate in outputs of 2B tokens because our value is only 4 bytes
    GENESIS_OUTPUTS = []
    num_outputs = math.ceil(GENESIS_TOKENS / MAX_VALUE)
    total_tokens = GENESIS_TOKENS
    for x in range(0, num_outputs):
        value = min(total_tokens, MAX_VALUE)
        GENESIS_OUTPUTS.append(
            TxOutput(value, bytes.fromhex('76a914fd05059b6006249543b82f36876a17c73fd2267b88ac'))
        )
        total_tokens -= value
    BLOCK_GENESIS = Block(
        hash=bytes.fromhex('0001242057660788e83008a985fa0ef60adb2652bfd70955016992a3d1ad38d7'),
        nonce=5448,
        timestamp=1539271481,
        weight=14,
        height=1,
        outputs=GENESIS_OUTPUTS,
        storage=tx_storage,
    )
    return [
        BLOCK_GENESIS,
        TX_GENESIS1,
        TX_GENESIS2
    ]


def get_genesis_output():
    # use this if to calculate the genesis output. We have to do it if:
    # - we change genesis priv/pub keys
    # - there's some change to the way we calculate hathor addresses
    import json
    import os
    import base64
    from hathor.transaction.scripts import P2PKH
    from hathor.crypto.util import get_private_key_from_bytes, get_address_from_public_key
    # read genesis keys
    filepath = os.path.join(os.getcwd(), 'hathor/wallet/genesis_keys.json')
    dict_data = None
    with open(filepath, 'r') as json_file:
        dict_data = json.loads(json_file.read())
    b64_private_key = dict_data['private_key']
    private_key_bytes = base64.b64decode(b64_private_key)
    genesis_private_key = get_private_key_from_bytes(private_key_bytes)
    address = get_address_from_public_key(genesis_private_key.public_key())
    return P2PKH.create_output_script(address).hex()
