# Copyright 2021 Hathor Labs
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
from typing import Optional

import base58
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.conf.get_settings import get_global_settings
from hathor.crypto.util import get_hash160, get_private_key_from_bytes
from hathor.transaction.transaction import Transaction
from hathorlib.scripts import HathorScript, Opcode


def generate_multisig_redeem_script(signatures_required: int, public_key_bytes: list[bytes]) -> bytes:
    """ Generate the redeem script for the multisig output

        <signatures_required> <pubkey 1> <pubkey 2> ... <pubkey N> <pubkey_count> <OP_CHECKMULTISIG>

        :param signatures_required: How many signatures are required to spend the outputs
        :type signatures_required: int

        :param public_key_bytes: Array of public keys that created the multisig wallet
        :type public_key_bytes: list[bytes]

        :return: The redeem script for the multisig wallet
        :rtype: bytes
    """
    settings = get_global_settings()
    if signatures_required > settings.MAX_MULTISIG_SIGNATURES:
        raise ValueError('Signatures required {} is over the limit'.format(signatures_required))
    if len(public_key_bytes) > settings.MAX_MULTISIG_PUBKEYS:
        raise ValueError('PubKeys length {} is over the limit'.format(len(public_key_bytes)))

    redeem_script = HathorScript()
    redeem_script.addOpcode(getattr(Opcode, 'OP_{}'.format(signatures_required)))
    for pubkey_bytes in public_key_bytes:
        redeem_script.pushData(pubkey_bytes)
    redeem_script.addOpcode(getattr(Opcode, 'OP_{}'.format(len(public_key_bytes))))
    redeem_script.addOpcode(Opcode.OP_CHECKMULTISIG)
    return redeem_script.data


def generate_multisig_address(redeem_script: bytes, version_byte: Optional[bytes] = None) -> str:
    """ Generate a multisig address for the multisig wallet

        <version_byte> <redeem_script_hash> <checksum>
        version_byte: MULTISIG_VERSION_BYTE
        redeem_script_hash: RIPEMD160(SHA256(redeem_script))
        checksum: first four bytes of the double SHA256 hash of the version and hash

        :param redeem_script: Redeem script to spend the multisig output
        :type redeem_script: bytes

        :param version_byte: Byte to be preppended in the address that represents the version
        :type version_byte: bytes

        :return: The multisig address
        :rtype: str(base58)
    """
    settings = get_global_settings()
    actual_version_byte: bytes = version_byte if version_byte is not None else settings.MULTISIG_VERSION_BYTE
    address = bytearray()

    address.extend(actual_version_byte)

    redeem_script_hash = get_hash160(redeem_script)
    address.extend(redeem_script_hash)

    checksum = hashlib.sha256(hashlib.sha256(address).digest()).digest()[:4]
    address.extend(checksum)

    baddress = bytes(address)
    return base58.b58encode(baddress).decode('utf-8')


def generate_signature(tx: Transaction, private_key_bytes: bytes, password: Optional[bytes] = None) -> bytes:
    """ Create a signature for the tx

        :param tx: transaction with the data to be signed
        :type tx: :py:class:`hathor.transaction.transaction.Transaction`

        :param private_key_bytes: private key to generate the signature
        :type private_key_bytes: bytes

        :param password: password to decrypt the private key
        :type password: bytes

        :return: signature of the tx
        :rtype: bytes
    """
    private_key = get_private_key_from_bytes(private_key_bytes, password=password)
    data_to_sign = tx.get_sighash_all()
    hashed_data = hashlib.sha256(data_to_sign).digest()
    signature = private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))
    return signature
