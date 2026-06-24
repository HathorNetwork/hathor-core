import test from 'ava'
import { UnsignedAmount, SignedAmount } from '../wrapper.js'

test.before(() => {
  UnsignedAmount.setNormalizationFactor(2, 18)
})

test('native relational operators on UnsignedAmount', (t) => {
  const a = UnsignedAmount.fromV2(5n)
  const b = UnsignedAmount.fromV2(6n)
  t.true(a < b)
  t.true(b > a)
  t.true(a <= UnsignedAmount.fromV2(5n))
  t.true(a >= UnsignedAmount.fromV2(5n))
})

test('native relational operators on SignedAmount', (t) => {
  const a = new SignedAmount(-1n)
  const b = new SignedAmount(2n)
  t.true(a < b)
  t.true(b >= new SignedAmount(2n))
})

test('String() coercion uses toString, not the primitive value', (t) => {
  t.is(String(UnsignedAmount.fromV2(5n)), 'V2 { normalized: 5 }')
  t.is(`${new SignedAmount(-3n)}`, 'SignedAmount(-3)')
})

test('SignedAmount.add/sub accept a SignedAmount', (t) => {
  const bal = new SignedAmount(5n)
  t.is(bal.add(new SignedAmount(3n)).raw(), 8n)
  t.is(bal.sub(new SignedAmount(8n)).raw(), -3n)
})

test('SignedAmount.add/sub accept a V2 UnsignedAmount', (t) => {
  const bal = new SignedAmount(5n)
  const amount = UnsignedAmount.fromV2(3n)
  const sum = bal.add(amount)
  t.is(sum.raw(), 8n)
  // The result is a SignedAmount, so it can go negative on subtraction.
  t.is(bal.sub(UnsignedAmount.fromV2(8n)).raw(), -3n)
})

test('SignedAmount.add/sub normalize a V1 UnsignedAmount before combining', (t) => {
  // V1(1) normalizes to 10^16 under the (2 -> 18) factor set in test.before.
  const normalized = 10n ** 16n
  const bal = new SignedAmount(normalized)
  t.is(bal.add(UnsignedAmount.fromV1(1n)).raw(), 2n * normalized)
  t.is(bal.sub(UnsignedAmount.fromV1(1n)).raw(), 0n)
})
