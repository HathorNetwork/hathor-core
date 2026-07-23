# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
    settings = settings.model_copy(update={
        'AVG_TIME_BETWEEN_BLOCKS': time_between_blocks or settings.AVG_TIME_BETWEEN_BLOCKS,
        'BLOCKS_PER_HALVING': None,
        'INITIAL_TOKEN_MAIN_UNITS_PER_BLOCK': 0,
        'MINIMUM_TOKEN_MAIN_UNITS_PER_BLOCK': 0,
        'CONSENSUS_ALGORITHM': PoaSettings(
            type=ConsensusType.PROOF_OF_AUTHORITY,
            signers=tuple(signers),
        ),
    })
    return settings
