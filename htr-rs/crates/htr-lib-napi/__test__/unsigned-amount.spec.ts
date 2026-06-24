import test from 'ava'
import { UnsignedAmount, TokenAmountVersion } from '../index.js'

// factor = 10^(18-2) = 10^16. Process-global OnceLock; idempotent for equal values.
const FACTOR = 10n ** 16n
test.before(() => {
  UnsignedAmount.setNormalizationFactor(2, 18)
})

test('TokenAmountVersion has V1=1 and V2=2', (t) => {
  t.is(TokenAmountVersion.V1, 1)
  t.is(TokenAmountVersion.V2, 2)
})

test('getNormalizationFactor returns 10^16', (t) => {
  t.is(UnsignedAmount.getNormalizationFactor(), FACTOR)
})

test('fromV1 scales normalized; raw keeps input', (t) => {
  const a = UnsignedAmount.fromV1(5n)
  t.true(a.isV1())
  t.false(a.isV2())
  t.is(a.raw(), 5n)
  t.is(a.normalized(), 5n * FACTOR)
})

test('fromV2 raw equals normalized', (t) => {
  const a = UnsignedAmount.fromV2(7n)
  t.true(a.isV2())
  t.is(a.raw(), 7n)
  t.is(a.normalized(), 7n)
})

test('fromVersion dispatches by version enum', (t) => {
  t.true(UnsignedAmount.fromVersion(3n, TokenAmountVersion.V1).isV1())
  t.true(UnsignedAmount.fromVersion(3n, TokenAmountVersion.V2).isV2())
})

test('zero is V2 zero', (t) => {
  const z = UnsignedAmount.zero()
  t.true(z.isV2())
  t.is(z.raw(), 0n)
})

test('asBool and isZero', (t) => {
  t.false(UnsignedAmount.zero().asBool())
  t.true(UnsignedAmount.zero().isZero())
  t.true(UnsignedAmount.fromV2(1n).asBool())
})

test('negative amount is rejected', (t) => {
  t.throws(() => UnsignedAmount.fromV2(-1n), { message: /non-negative/ })
})

test('toString matches Rust Debug', (t) => {
  t.is(UnsignedAmount.fromV2(5n).toString(), 'V2 { normalized: 5 }')
})

test('toSigned carries normalized value', (t) => {
  t.is(UnsignedAmount.fromV1(5n).toSigned().raw(), 5n * FACTOR)
  t.is(UnsignedAmount.fromV2(5n).toSigned().raw(), 5n)
})

test('toV2 lifts V1 to V2', (t) => {
  const v2 = UnsignedAmount.fromV1(5n).toV2()
  t.true(v2.isV2())
  t.is(v2.raw(), 5n * FACTOR)
})

test('toV1 on an exact multiple converts', (t) => {
  const v1 = UnsignedAmount.fromV2(5n * FACTOR).toV1()
  t.true(v1.isV1())
  t.is(v1.raw(), 5n)
})

test('toV1 on a non-multiple throws', (t) => {
  t.throws(() => UnsignedAmount.fromV2(5n * FACTOR + 1n).toV1(), { message: /would truncate/ })
})

test('maybeToV1 returns the value or null', (t) => {
  t.is(UnsignedAmount.fromV2(5n * FACTOR).maybeToV1()?.raw(), 5n)
  t.is(UnsignedAmount.fromV2(5n * FACTOR + 1n).maybeToV1(), null)
})

test('toVersion dispatches and throws on truncating V1 target', (t) => {
  t.true(UnsignedAmount.fromV1(3n).toVersion(TokenAmountVersion.V2).isV2())
  t.true(UnsignedAmount.fromV2(5n * FACTOR).toVersion(TokenAmountVersion.V1).isV1())
  t.throws(() => UnsignedAmount.fromV2(5n * FACTOR + 1n).toVersion(TokenAmountVersion.V1), {
    message: /would truncate/,
  })
})

test('add and sub return V2', (t) => {
  const sum = UnsignedAmount.fromV2(2n).add(UnsignedAmount.fromV2(3n))
  t.true(sum.isV2())
  t.is(sum.normalized(), 5n)
  t.is(UnsignedAmount.fromV2(10n).sub(UnsignedAmount.fromV2(3n)).normalized(), 7n)
})

test('sub underflow throws instead of aborting', (t) => {
  t.throws(() => UnsignedAmount.fromV2(3n).sub(UnsignedAmount.fromV2(5n)))
})

test('comparisons compare normalized across versions', (t) => {
  const v1 = UnsignedAmount.fromV1(5n) // normalized 5*FACTOR
  const v2Equal = UnsignedAmount.fromV2(5n * FACTOR)
  const v2Bigger = UnsignedAmount.fromV2(6n * FACTOR)
  t.true(v1.eq(v2Equal))
  t.false(v1.ne(v2Equal))
  t.true(v1.lt(v2Bigger))
  t.true(v2Bigger.gt(v1))
  t.true(v1.le(v2Equal))
  t.true(v1.ge(v2Equal))
  t.is(v1.compare(v2Equal), 0)
  t.is(v1.compare(v2Bigger), -1)
  t.is(v2Bigger.compare(v1), 1)
})

test('comparison against a foreign type throws', (t) => {
  // @ts-expect-error intentionally passing a non-UnsignedAmount
  t.throws(() => UnsignedAmount.fromV2(5n).eq(5))
})

// Exercises the multi-limb (> 2^64) path of the BigInt marshalling across the real
// napi boundary — the in-process Rust unit tests cover the conversion, but only this
// goes through the actual JS <-> Rust crossing.
test('large multi-limb values round-trip across the BigInt boundary', (t) => {
  const big = 2n ** 80n + 12345n
  t.is(UnsignedAmount.fromV2(big).normalized(), big)
  t.is(UnsignedAmount.fromV2(big).raw(), big)
})
