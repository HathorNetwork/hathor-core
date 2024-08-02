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

from cryptography.hazmat.primitives.asymmetric import ec

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.consensus.consensus_settings import ConsensusType, PoaSettings, PoaSignerSettings
from hathor.consensus.poa import PoaSigner
from hathor.crypto.util import get_public_key_bytes_compressed


def get_signer() -> PoaSigner:
    return PoaSigner(ec.generate_private_key(ec.SECP256K1()))


def get_settings(
    *poa_signers: PoaSigner | PoaSignerSettings,
    time_between_blocks: int | None = None
) -> HathorSettings:
    signers = []
    for signer in poa_signers:
        if isinstance(signer, PoaSignerSettings):
            poa_settings = signer
        else:
            public_key = signer.get_public_key()
            public_key_bytes = get_public_key_bytes_compressed(public_key)
            poa_settings = PoaSignerSettings(public_key=public_key_bytes)
        signers.append(poa_settings)

    settings = get_global_settings()
    settings = settings._replace(
        AVG_TIME_BETWEEN_BLOCKS=time_between_blocks or settings.AVG_TIME_BETWEEN_BLOCKS,
        BLOCKS_PER_HALVING=None,
        INITIAL_TOKEN_UNITS_PER_BLOCK=0,
        MINIMUM_TOKEN_UNITS_PER_BLOCK=0,
        CONSENSUS_ALGORITHM=PoaSettings(
            type=ConsensusType.PROOF_OF_AUTHORITY,
            signers=tuple(signers),
        ),
    )
    return settings
