import test from 'ava'
import { TokenAmount } from '../index.js'

test('conflicting re-set throws instead of aborting', (t) => {
  TokenAmount.setNormalizationFactor(2, 18)
  // Same factor again is a no-op.
  t.notThrows(() => TokenAmount.setNormalizationFactor(2, 18))
  // A different factor must throw (catch_unwind converts the Rust panic).
  t.throws(() => TokenAmount.setNormalizationFactor(0, 4))
})
