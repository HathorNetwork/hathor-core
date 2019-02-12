from typing import List, Optional

from hathor.constants import GENESIS_TOKENS, MIN_BLOCK_WEIGHT, MIN_TX_WEIGHT
from hathor.transaction import BaseTransaction, Block, Transaction, TxOutput
from hathor.transaction.storage import TransactionStorage


def genesis_transactions(tx_storage: Optional[TransactionStorage]) -> List[BaseTransaction]:
    TX_GENESIS1 = Transaction(
        hash=bytes.fromhex('0001b424e66e654fa0300329b720170f8d83ff7c6685fab5b66056f209c95a58'),
        nonce=9160,
        timestamp=1539271482,
        weight=MIN_TX_WEIGHT,
        storage=tx_storage,
    )

    TX_GENESIS2 = Transaction(
        hash=bytes.fromhex('0001181d91e0f4deb77bcb90364d7d69c7ac7eafb445a82d2b643a2c38173868'),
        nonce=9959,
        timestamp=1539271483,
        weight=MIN_TX_WEIGHT,
        storage=tx_storage,
    )

    # Genesis will have 2B tokens (we use 200B because of two decimal places)
    GENESIS_OUTPUTS = [
        TxOutput(GENESIS_TOKENS, bytes.fromhex('76a914fd05059b6006249543b82f36876a17c73fd2267b88ac')),
    ]
    BLOCK_GENESIS = Block(
        hash=bytes.fromhex('00011851a7eddddc521901e0dba30e45d7ff57eb862649f313abe103b39c5267'),
        nonce=10923,
        timestamp=1539271481,
        weight=MIN_BLOCK_WEIGHT,
        outputs=GENESIS_OUTPUTS,
        storage=tx_storage,
    )
    return [BLOCK_GENESIS, TX_GENESIS1, TX_GENESIS2]


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
