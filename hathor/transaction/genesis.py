from typing import List, Optional

from hathor.constants import GENESIS_TOKENS, MIN_BLOCK_WEIGHT, MIN_TX_WEIGHT
from hathor.transaction import BaseTransaction, Block, Transaction, TxOutput
from hathor.transaction.storage import TransactionStorage


def genesis_transactions(tx_storage: Optional[TransactionStorage]) -> List[BaseTransaction]:
    TX_GENESIS1 = Transaction(
        hash=bytes.fromhex('0001e887c7b5ec3b4e57033d849a80d8bccbe3a749abfa87cc31c663530f3f4e'),
        nonce=23519,
        timestamp=1539271482,
        weight=MIN_TX_WEIGHT,
        storage=tx_storage,
    )

    TX_GENESIS2 = Transaction(
        hash=bytes.fromhex('00029b7f8051f6ebdc0338d02d4a8cfbd662500ee03224bbee75a6f2da0350b0'),
        nonce=11402,
        timestamp=1539271483,
        weight=MIN_TX_WEIGHT,
        storage=tx_storage,
    )

    # Genesis will have 2B tokens (we use 200B because of two decimal places)
    GENESIS_OUTPUTS = [
        TxOutput(GENESIS_TOKENS, bytes.fromhex('76a914fd05059b6006249543b82f36876a17c73fd2267b88ac')),
    ]
    BLOCK_GENESIS = Block(
        hash=bytes.fromhex('000164e1e7ec7700a18750f9f50a1a9b63f6c7268637c072ae9ee181e58eb01b'),
        nonce=60315,
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
