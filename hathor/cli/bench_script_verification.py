# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import sys
from unittest.mock import Mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_public_key_bytes_compressed, get_address_from_public_key
from hathor.transaction import Transaction, TxOutput, TxInput
from hathor.transaction.scripts import P2PKH
from hathor.verification.transaction_verifier import TransactionVerifier


def main() -> None:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--n-txs', type=str, help='Number of txs')
    parser.add_argument('--n-scripts', type=str, help='Number of scripts in each tx')
    args = parser.parse_args(sys.argv[1:])
    n_scripts = int(args.n_scripts)
    n_txs = int(args.n_txs)

    storage = Mock()
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    public_key_bytes = get_public_key_bytes_compressed(public_key)
    address = get_address_from_public_key(public_key)
    output_script = P2PKH.create_output_script(address)

    spent_tx = Transaction(
        outputs=[TxOutput(value=1, script=output_script)] * n_scripts
    )
    spent_tx.update_hash()
    storage.get_transaction = Mock(return_value=spent_tx)

    tx = Transaction(
        storage=storage,
        inputs=[TxInput(spent_tx.hash, index=i, data=b'') for i in range(n_scripts)],
    )

    data_to_sign = tx.get_sighash_all()
    hashed_data = hashlib.sha256(data_to_sign).digest()
    signature = private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))

    intput_data = P2PKH.create_input_data(public_key_bytes, signature)
    for input_ in tx.inputs:
        input_.data = intput_data

    for _ in range(n_txs):
        TransactionVerifier.verify_scripts(tx)
