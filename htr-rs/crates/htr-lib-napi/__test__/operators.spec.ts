import test from 'ava'
import { TokenAmount, TokenBalance } from '../wrapper.js'

test.before(() => {
  TokenAmount.setNormalizationFactor(2, 18)
})

test('native relational operators on TokenAmount', (t) => {
  const a = TokenAmount.fromV2(5n)
  const b = TokenAmount.fromV2(6n)
  t.true(a < b)
  t.true(b > a)
  t.true(a <= TokenAmount.fromV2(5n))
  t.true(a >= TokenAmount.fromV2(5n))
})

test('native relational operators on TokenBalance', (t) => {
  const a = new TokenBalance(-1n)
  const b = new TokenBalance(2n)
  t.true(a < b)
  t.true(b >= new TokenBalance(2n))
})

test('String() coercion uses toString, not the primitive value', (t) => {
  t.is(String(TokenAmount.fromV2(5n)), 'V2 { normalized: 5 }')
  t.is(`${new TokenBalance(-3n)}`, 'TokenBalance(-3)')
})

test('TokenBalance.add/sub accept a TokenBalance', (t) => {
  const bal = new TokenBalance(5n)
  t.is(bal.add(new TokenBalance(3n)).raw(), 8n)
  t.is(bal.sub(new TokenBalance(8n)).raw(), -3n)
})

test('TokenBalance.add/sub accept a V2 TokenAmount', (t) => {
  const bal = new TokenBalance(5n)
  const amount = TokenAmount.fromV2(3n)
  const sum = bal.add(amount)
  t.is(sum.raw(), 8n)
  // The result is a TokenBalance, so it can go negative on subtraction.
  t.is(bal.sub(TokenAmount.fromV2(8n)).raw(), -3n)
})

test('TokenBalance.add/sub normalize a V1 TokenAmount before combining', (t) => {
  // V1(1) normalizes to 10^16 under the (2 -> 18) factor set in test.before.
  const normalized = 10n ** 16n
  const bal = new TokenBalance(normalized)
  t.is(bal.add(TokenAmount.fromV1(1n)).raw(), 2n * normalized)
  t.is(bal.sub(TokenAmount.fromV1(1n)).raw(), 0n)
})
