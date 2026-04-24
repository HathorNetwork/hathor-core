#  Copyright 2026 Hathor Labs
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

"""Post-nano-execution completeness check — if a postponed balance check
isn't re-run (or is bypassed), the tx must be voided via NCFail."""

from unittest.mock import MagicMock

import pytest

from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.execution.block_executor import NCBlockExecutor
from hathor.verification.required_checks import required_post_nano_checks
from hathor.verification.verification_check import VerificationCheck as VC


def _make_executor() -> NCBlockExecutor:
    settings = MagicMock(spec=HathorSettings)
    settings.SKIP_VERIFICATION = set()
    executor = NCBlockExecutor.__new__(NCBlockExecutor)
    executor._settings = settings
    return executor


def _make_tx(checks: VC) -> MagicMock:
    """Minimal Transaction mock: has_shielded_outputs=False, verification_checks=`checks`."""
    from hathor.transaction import Transaction
    tx = MagicMock(spec=Transaction)
    tx.hash = b'\x01' * 32
    tx.is_genesis = False
    meta = MagicMock()
    meta.verification_checks = checks
    tx.get_metadata = MagicMock(return_value=meta)
    return tx


class TestPostNanoVoiding:
    def test_balance_recorded_passes(self) -> None:
        """Happy path: BALANCE is set post-execution → no NCFail."""
        executor = _make_executor()
        tx = _make_tx(VC.BALANCE)
        executor._assert_verification_checks_complete_after_execution(tx)

    def test_balance_postponed_but_never_promoted_raises_ncfail(self) -> None:
        """Simulates: _verify_sum_after_execution was removed or failed to
        record BALANCE. The post-nano completeness check must void the tx."""
        executor = _make_executor()
        tx = _make_tx(VC.BALANCE_POSTPONED)
        with pytest.raises(NCFail) as exc:
            executor._assert_verification_checks_complete_after_execution(tx)
        assert 'BALANCE' in str(exc.value)

    def test_no_flags_raises_ncfail(self) -> None:
        """Pathological: no balance flag at all (neither BALANCE nor POSTPONED).
        Must void — stronger signal that verification was bypassed entirely."""
        executor = _make_executor()
        tx = _make_tx(VC(0))
        with pytest.raises(NCFail):
            executor._assert_verification_checks_complete_after_execution(tx)

    def test_required_post_nano_is_balance_for_tx(self) -> None:
        """The post-nano contract is: BALANCE must be recorded. BALANCE_POSTPONED
        alone is NOT sufficient (that's the whole point of this check)."""
        from hathor.transaction import Transaction
        settings = MagicMock(spec=HathorSettings)
        settings.SKIP_VERIFICATION = set()
        tx = MagicMock(spec=Transaction)
        tx.hash = b'\x01' * 32
        tx.is_genesis = False
        req = required_post_nano_checks(tx, settings)
        assert req.all_of == VC.BALANCE
