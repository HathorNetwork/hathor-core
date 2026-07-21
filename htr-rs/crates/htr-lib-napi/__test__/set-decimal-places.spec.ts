// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

import test from 'ava'
import { UnsignedAmount } from '../index.js'

test('conflicting re-set throws instead of aborting', (t) => {
  UnsignedAmount.setDecimalPlaces(2, 18)
  // Same factor again is a no-op.
  t.notThrows(() => UnsignedAmount.setDecimalPlaces(2, 18))
  // A different factor must throw (catch_unwind converts the Rust panic).
  t.throws(() => UnsignedAmount.setDecimalPlaces(0, 4))
})
