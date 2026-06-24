import test from 'ava'
import { UnsignedAmount } from '../index.js'

test('conflicting re-set throws instead of aborting', (t) => {
  UnsignedAmount.setNormalizationFactor(2, 18)
  // Same factor again is a no-op.
  t.notThrows(() => UnsignedAmount.setNormalizationFactor(2, 18))
  // A different factor must throw (catch_unwind converts the Rust panic).
  t.throws(() => UnsignedAmount.setNormalizationFactor(0, 4))
})
