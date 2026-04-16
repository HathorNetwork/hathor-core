# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Serialization/deserialization for TransferHeader."""

from __future__ import annotations

from hathor.serialization import Deserializer, Serializer
from hathor.serialization.encoding.bytes import decode_bytes, encode_bytes
from hathor.serialization.encoding.int import decode_int, encode_int
from hathor.serialization.encoding.leb128 import decode_leb128, encode_leb128
from hathor.serialization.encoding.output_value import decode_output_value
from hathor.transaction.headers.nano_header import ADDRESS_SEQNUM_SIZE
from hathor.transaction.headers.transfer_header import InputAddress, TransferHeader, TxTransferInput, TxTransferOutput
from hathor.transaction.headers.types import VertexHeaderId
from hathor.transaction.util import VerboseCallback
from hathorlib.serialization.encoding.output_value import encode_output_value
from hathorlib.token_amount_version import TokenAmountVersion


def deserialize_transfer_header(
    deserializer: Deserializer,
    *,
    token_amount_version: TokenAmountVersion,
    verbose: VerboseCallback = None,
) -> tuple[list[InputAddress], list[TxTransferInput], list[TxTransferOutput]]:
    """Deserialize transfer header data from the deserializer."""
    header_id = bytes(deserializer.read_bytes(1))
    if verbose:
        verbose('header_id', header_id)
    assert header_id == VertexHeaderId.TRANSFER_HEADER.value

    addresses_len = decode_int(deserializer, length=1, signed=False)
    if verbose:
        verbose('addresses_len', addresses_len)

    addresses: list[InputAddress] = []
    for _ in range(addresses_len):
        address = decode_bytes(deserializer)
        seqnum = decode_leb128(deserializer.with_optional_max_bytes(ADDRESS_SEQNUM_SIZE), signed=False)
        script = decode_bytes(deserializer)
        addresses.append(InputAddress(
            address=address,
            seqnum=seqnum,
            script=script,
        ))

    inputs_len = decode_int(deserializer, length=1, signed=False)
    if verbose:
        verbose('inputs_len', inputs_len)

    inputs: list[TxTransferInput] = []
    for _ in range(inputs_len):
        address_index = decode_int(deserializer, length=1, signed=False)
        amount = decode_output_value(deserializer, token_amount_version=token_amount_version)
        token_index = decode_int(deserializer, length=1, signed=False)
        inputs.append(TxTransferInput(
            address_index=address_index,
            amount=amount,
            token_index=token_index,
        ))

    outputs_len = decode_int(deserializer, length=1, signed=False)
    if verbose:
        verbose('outputs_len', outputs_len)

    outputs: list[TxTransferOutput] = []
    for _ in range(outputs_len):
        address = decode_bytes(deserializer)
        amount = decode_output_value(deserializer, token_amount_version=token_amount_version)
        token_index = decode_int(deserializer, length=1, signed=False)
        outputs.append(TxTransferOutput(
            address=address,
            amount=amount,
            token_index=token_index,
        ))

    return addresses, inputs, outputs


def serialize_transfer_header(
    serializer: Serializer,
    header: TransferHeader,
    *,
    token_amount_version: TokenAmountVersion,
    skip_signature: bool = False,
) -> None:
    """Serialize a TransferHeader into the serializer."""
    serializer.write_bytes(VertexHeaderId.TRANSFER_HEADER.value)
    encode_int(serializer, len(header.addresses), length=1, signed=False)
    for input_address in header.addresses:
        encode_bytes(serializer, input_address.address)
        encode_leb128(serializer.with_optional_max_bytes(ADDRESS_SEQNUM_SIZE), input_address.seqnum, signed=False)
        if not skip_signature:
            encode_bytes(serializer, input_address.script)
        else:
            encode_bytes(serializer, b'')

    encode_int(serializer, len(header.inputs), length=1, signed=False)
    for txin in header.inputs:
        encode_int(serializer, txin.address_index, length=1, signed=False)
        encode_output_value(serializer, txin.amount, token_amount_version=token_amount_version)
        encode_int(serializer, txin.token_index, length=1, signed=False)

    encode_int(serializer, len(header.outputs), length=1, signed=False)
    for txout in header.outputs:
        encode_bytes(serializer, txout.address)
        encode_output_value(serializer, txout.amount, token_amount_version=token_amount_version)
        encode_int(serializer, txout.token_index, length=1, signed=False)
