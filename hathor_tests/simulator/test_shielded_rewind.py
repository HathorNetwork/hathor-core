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

import pytest

from hathor.simulator.shielded import SHIELDED_CRYPTO_AVAILABLE

pytestmark = pytest.mark.skipif(
    not SHIELDED_CRYPTO_AVAILABLE,
    reason='native CT crypto not available (feat/shielded-outputs not merged)',
)


def test_construct_serialize_rewind_round_trip() -> None:
    """Construct a real shielded output, serialize through the header, rewind, recover value.

    Requires the native CT crypto (hathor.crypto.shielded), which does not exist on
    this branch yet, so the test is skipped (see pytestmark). When that package is
    integrated, flip SHIELDED_CRYPTO_AVAILABLE, drop the skip below, and uncomment the
    body (which references the not-yet-present crypto module).
    """
    pytest.skip('native CT crypto not available')
    # from hathor.crypto.shielded.ecdh import generate_ephemeral_keypair
    # from hathor.simulator.shielded import build_shielded_output, rewind_shielded_output
    # from hathorlib.headers.shielded_outputs_header import ShieldedOutputsHeader
    # from hathorlib.transaction import Transaction
    # from hathorlib.transaction.shielded_tx_output import OutputMode
    #
    # htr_uid = b'\x00'
    # script = b'\x76\xa9\x14' + b'\x11' * 20 + b'\x88\xac'
    #
    # # Stand in for a wallet key pair (recipient).
    # recipient_privkey, recipient_pubkey = generate_ephemeral_keypair()
    #
    # amount = 1234
    # out = build_shielded_output(
    #     amount=amount,
    #     token_uid=htr_uid,
    #     token_data=0,
    #     script=script,
    #     mode=OutputMode.AMOUNT_ONLY,
    #     recipient_pubkey=recipient_pubkey,
    # )
    #
    # # Serialize through the header and back (the wire path the event stream uses).
    # header = ShieldedOutputsHeader(shielded_outputs=[out])
    # restored, _ = ShieldedOutputsHeader.deserialize(Transaction(), header.serialize())
    # restored_out = restored.shielded_outputs[0]
    #
    # secrets = rewind_shielded_output(restored_out, recipient_privkey, htr_uid)
    # assert secrets.value == amount
