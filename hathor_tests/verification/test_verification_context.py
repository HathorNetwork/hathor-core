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

import pytest

from hathor.transaction.exceptions import VerificationChecksMissingError
from hathor.verification.verification_check import VerificationCheck as VC
from hathor.verification.verification_context import RequiredChecks, VerificationContext


class TestVerificationContext:
    def test_starts_empty(self) -> None:
        ctx = VerificationContext()
        assert ctx.checks_run == VC(0)
        assert not ctx.has(VC.BALANCE)

    def test_record_sets_flag(self) -> None:
        ctx = VerificationContext()
        ctx.record(VC.BALANCE)
        assert ctx.has(VC.BALANCE)
        assert not ctx.has(VC.INPUTS)

    def test_record_is_idempotent(self) -> None:
        ctx = VerificationContext()
        ctx.record(VC.BALANCE)
        ctx.record(VC.BALANCE)
        assert ctx.checks_run == VC.BALANCE

    def test_record_combined_flag(self) -> None:
        ctx = VerificationContext()
        ctx.record(VC.BALANCE | VC.INPUTS)
        assert ctx.has(VC.BALANCE)
        assert ctx.has(VC.INPUTS)

    def test_check_passes_when_all_recorded(self) -> None:
        ctx = VerificationContext()
        ctx.record(VC.BALANCE)
        ctx.record(VC.INPUTS)
        ctx.check(RequiredChecks(all_of=VC.BALANCE | VC.INPUTS), stage='test')

    def test_check_raises_when_missing_all_of(self) -> None:
        ctx = VerificationContext(vertex_hash=b'\x01' * 32)
        ctx.record(VC.BALANCE)
        with pytest.raises(VerificationChecksMissingError) as exc:
            ctx.check(RequiredChecks(all_of=VC.BALANCE | VC.INPUTS), stage='test')
        assert 'INPUTS' in str(exc.value)

    def test_any_of_group_satisfied_by_either(self) -> None:
        # Classic BALANCE-or-BALANCE_POSTPONED invariant.
        group = VC.BALANCE | VC.BALANCE_POSTPONED
        req = RequiredChecks(any_of_groups=(group,))

        ctx1 = VerificationContext()
        ctx1.record(VC.BALANCE)
        ctx1.check(req, stage='test')

        ctx2 = VerificationContext()
        ctx2.record(VC.BALANCE_POSTPONED)
        ctx2.check(req, stage='test')

    def test_any_of_group_fails_when_none_recorded(self) -> None:
        group = VC.BALANCE | VC.BALANCE_POSTPONED
        ctx = VerificationContext(vertex_hash=b'\x02' * 32)
        ctx.record(VC.INPUTS)  # unrelated
        with pytest.raises(VerificationChecksMissingError):
            ctx.check(RequiredChecks(any_of_groups=(group,)), stage='test')

    def test_combined_all_and_any_of(self) -> None:
        req = RequiredChecks(
            all_of=VC.INPUTS | VC.VERSION,
            any_of_groups=(VC.BALANCE | VC.BALANCE_POSTPONED,),
        )
        ctx = VerificationContext()
        ctx.record(VC.INPUTS)
        ctx.record(VC.VERSION)
        ctx.record(VC.BALANCE_POSTPONED)
        ctx.check(req, stage='test')

    def test_required_checks_or_combines_both(self) -> None:
        a = RequiredChecks(all_of=VC.INPUTS, any_of_groups=(VC.BALANCE | VC.BALANCE_POSTPONED,))
        b = RequiredChecks(all_of=VC.VERSION, any_of_groups=(VC.POA | VC.POW,))
        combined = a | b
        assert combined.all_of == VC.INPUTS | VC.VERSION
        assert combined.any_of_groups == (
            VC.BALANCE | VC.BALANCE_POSTPONED,
            VC.POA | VC.POW,
        )
