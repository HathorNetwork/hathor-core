# Copyright 2023 Hathor Labs
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

# Re-export all types from hathorlib for backward compatibility
from hathorlib.nanocontracts.types import (  # noqa: F401
    BLUEPRINT_EXPORT_NAME,
    HATHOR_TOKEN_UID,
    NC_ALLOW_REENTRANCY,
    NC_ALLOWED_ACTIONS_ATTR,
    NC_FALLBACK_METHOD,
    NC_INITIALIZE_METHOD,
    NC_METHOD_TYPE_ATTR,
    Address,
    Amount,
    BaseAction,
    BaseAuthorityAction,
    BaseTokenAction,
    BlueprintId,
    CallerId,
    ContractId,
    NCAcquireAuthorityAction,
    NCAction,
    NCActionType,
    NCArgs,
    NCDepositAction,
    NCFee,
    NCGrantAuthorityAction,
    NCMethodType,
    NCParsedArgs,
    NCRawArgs,
    NCWithdrawalAction,
    RawSignedData,
    SignedData,
    Timestamp,
    TokenUid,
    TxOutputScript,
    VertexId,
    blueprint_id_from_bytes,
    export,
    fallback,
    public,
    set_checksig_backend,
    view,
)


def _checksig_impl(sighash_all_data: bytes, script_input: bytes, script: bytes) -> bool:
    from hathor.transaction.exceptions import ScriptError
    from hathor.transaction.scripts import ScriptExtras
    from hathor.transaction.scripts.execute import raw_script_eval
    from hathor.transaction.scripts.opcode import OpcodesVersion

    class _FakeTx:
        def get_sighash_all_data(self) -> bytes:
            return sighash_all_data

    extras = ScriptExtras(tx=_FakeTx(), version=OpcodesVersion.V2)  # type: ignore[arg-type]
    try:
        raw_script_eval(input_data=script_input, output_script=script, extras=extras)
    except ScriptError:
        return False
    else:
        return True


set_checksig_backend(_checksig_impl)
