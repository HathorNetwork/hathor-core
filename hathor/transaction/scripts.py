#  Copyright 2023 Hathor Labs
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
from dataclasses import replace
from typing import Any, Optional

from hathor.conf.lib_settings import get_lib_settings
from hathorlib import GenericVertex, Transaction, TxInput
from hathorlib.scripts import (
    ScriptExtras as LibScriptExtras,
    create_base_script as lib_create_base_script,
    create_output_script as lib_create_output_script,
    raw_script_eval as lib_raw_script_eval,
    script_eval as lib_script_eval,
)
from hathorlib.scripts.base_script import BaseScript as LibBaseScript


def script_eval(tx: Transaction, txin: TxInput, spent_tx: GenericVertex) -> None:
    lib_script_eval(tx, txin, spent_tx, get_lib_settings())


def raw_script_eval(*, input_data: bytes, output_script: bytes, extras: LibScriptExtras) -> None:
    extras_proxy = replace(extras, settings=get_lib_settings())
    lib_raw_script_eval(
        input_data=input_data,
        output_script=output_script,
        extras=extras_proxy,
    )


def create_base_script(address: str, timelock: Optional[Any] = None) -> LibBaseScript:
    return lib_create_base_script(get_lib_settings(), address, timelock)


def create_output_script(address: bytes, timelock: Optional[Any] = None) -> bytes:
    return lib_create_output_script(get_lib_settings(), address, timelock)
