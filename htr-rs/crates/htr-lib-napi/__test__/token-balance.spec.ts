import test from 'ava'
import { TokenBalance } from '../index.js'

test('constructor defaults to zero', (t) => {
  t.is(new TokenBalance().raw(), 0n)
  t.is(new TokenBalance(5n).raw(), 5n)
  t.is(new TokenBalance(-5n).raw(), -5n)
})

test('asBool and isZero', (t) => {
  t.false(new TokenBalance(0n).asBool())
  t.true(new TokenBalance(0n).isZero())
  t.true(new TokenBalance(1n).asBool())
  t.false(new TokenBalance(1n).isZero())
})

test('arithmetic', (t) => {
  t.is(new TokenBalance(2n).add(new TokenBalance(3n)).raw(), 5n)
  t.is(new TokenBalance(3n).sub(new TokenBalance(5n)).raw(), -2n)
  t.is(new TokenBalance(5n).neg().raw(), -5n)
})

test('comparisons', (t) => {
  const a = new TokenBalance(5n)
  const b = new TokenBalance(5n)
  const c = new TokenBalance(-1n)
  t.true(a.eq(b))
  t.false(a.ne(b))
  t.true(c.lt(a))
  t.true(a.gt(c))
  t.true(a.le(b))
  t.true(a.ge(b))
  t.is(a.compare(b), 0)
  t.is(c.compare(a), -1)
  t.is(a.compare(c), 1)
})

test('toBalance returns an equal balance', (t) => {
  t.is(new TokenBalance(7n).toBalance().raw(), 7n)
})

test('toString matches Rust Debug', (t) => {
  t.is(new TokenBalance(5n).toString(), 'TokenBalance(5)')
  t.is(`${new TokenBalance(-3n)}`, 'TokenBalance(-3)')
})

test('comparison against a foreign type throws', (t) => {
  const a = new TokenBalance(5n)
  // @ts-expect-error intentionally passing a non-TokenBalance
  t.throws(() => a.eq(5))
})

test('toAmount converts non-negative balances', (t) => {
  const a = new TokenBalance(5n).toAmount()
  t.true(a.isV2())
  t.is(a.normalized(), 5n)
  t.is(new TokenBalance(0n).toAmount().normalized(), 0n)
})

test('toAmount on a negative balance throws', (t) => {
  t.throws(() => new TokenBalance(-1n).toAmount(), { message: /negative/ })
})

// Exercises the multi-limb (> 2^64) path of the signed BigInt marshalling across the
// real napi boundary, in both sign directions.
test('large multi-limb values round-trip across the BigInt boundary', (t) => {
  const big = 2n ** 100n + 7n
  t.is(new TokenBalance(big).raw(), big)
  t.is(new TokenBalance(-big).raw(), -big)
})
