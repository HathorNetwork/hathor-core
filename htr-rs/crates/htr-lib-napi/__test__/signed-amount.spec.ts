// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

import test from 'ava'
import { SignedAmount } from '../index.js'

test('constructor defaults to zero', (t) => {
  t.is(new SignedAmount().raw(), 0n)
  t.is(new SignedAmount(5n).raw(), 5n)
  t.is(new SignedAmount(-5n).raw(), -5n)
})

test('asBool and isZero', (t) => {
  t.false(new SignedAmount(0n).asBool())
  t.true(new SignedAmount(0n).isZero())
  t.true(new SignedAmount(1n).asBool())
  t.false(new SignedAmount(1n).isZero())
})

test('arithmetic', (t) => {
  t.is(new SignedAmount(2n).add(new SignedAmount(3n)).raw(), 5n)
  t.is(new SignedAmount(3n).sub(new SignedAmount(5n)).raw(), -2n)
  t.is(new SignedAmount(5n).neg().raw(), -5n)
  // pos() is identity, mirroring Python's __pos__.
  t.is(new SignedAmount(5n).pos().raw(), 5n)
  t.is(new SignedAmount(-5n).pos().raw(), -5n)
})

test('comparisons', (t) => {
  const a = new SignedAmount(5n)
  const b = new SignedAmount(5n)
  const c = new SignedAmount(-1n)
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

test('toSigned returns the same object (identity)', (t) => {
  const a = new SignedAmount(7n)
  t.is(a.toSigned(), a) // same JS object, mirroring Python's identity
  t.is(a.toSigned().raw(), 7n)
})

test('pos returns the same object (identity)', (t) => {
  const a = new SignedAmount(5n)
  t.is(a.pos(), a)
})

test('toString matches Rust Debug', (t) => {
  t.is(new SignedAmount(5n).toString(), 'SignedAmount(5)')
  t.is(`${new SignedAmount(-3n)}`, 'SignedAmount(-3)')
})

test('comparison against a foreign type throws', (t) => {
  const a = new SignedAmount(5n)
  // @ts-expect-error intentionally passing a non-SignedAmount
  t.throws(() => a.eq(5))
})

test('toUnsigned converts non-negative balances', (t) => {
  const a = new SignedAmount(5n).toUnsigned()
  t.true(a.isV2())
  t.is(a.normalized(), 5n)
  t.is(new SignedAmount(0n).toUnsigned().normalized(), 0n)
})

test('toUnsigned on a negative balance throws', (t) => {
  t.throws(() => new SignedAmount(-1n).toUnsigned(), { message: /negative/ })
})

// Exercises the multi-limb (> 2^64) path of the signed BigInt marshalling across the
// real napi boundary, in both sign directions.
test('large multi-limb values round-trip across the BigInt boundary', (t) => {
  const big = 2n ** 100n + 7n
  t.is(new SignedAmount(big).raw(), big)
  t.is(new SignedAmount(-big).raw(), -big)
})
