// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

import test from 'ava'
import { UnsignedAmount, TokenAmountVersion } from '../index.js'

// This file deliberately NEVER calls setDecimalPlaces. ava runs each spec file in its own
// worker process (workerThreads: false), so the process-global decimal-places OnceLock stays
// unset for every test here. Each config-dependent method must therefore throw a *catchable* error
// rather than aborting the Node process — that is the #[napi(catch_unwind)] contract. If any of
// these aborted instead (a missing catch_unwind), the ava worker would crash and the run would fail
// outright, so a passing t.throws is itself the proof that the process was not aborted.

test('config-independent constructors do not need the decimal places', (t) => {
  t.notThrows(() => UnsignedAmount.fromV2(5n))
  t.notThrows(() => UnsignedAmount.zero())
})

test('toString throws (not aborts) when the decimal places are unset', (t) => {
  // Rendering reads the decimal places, so it is a panic path like the conversions below.
  t.throws(() => UnsignedAmount.fromV2(5n).toString(), { message: /decimal places must be set/ })
})

test('parse throws (not aborts) when the decimal places are unset', (t) => {
  t.throws(() => UnsignedAmount.parse('1.5'), { message: /decimal places must be set/ })
})

test('toDebugString does not need the decimal places', (t) => {
  // The internal form is independent of the configured scale, so it stays usable for diagnostics.
  t.notThrows(() => UnsignedAmount.fromV2(5n).toDebugString())
})

test('fromV1 throws (not aborts) when the decimal places are unset', (t) => {
  t.throws(() => UnsignedAmount.fromV1(1n), { message: /decimal places must be set/ })
})

test('fromVersion(V1) throws (not aborts) when the decimal places are unset', (t) => {
  t.throws(() => UnsignedAmount.fromVersion(1n, TokenAmountVersion.V1), {
    message: /decimal places must be set/,
  })
})

test('toV1 throws (not aborts) when the decimal places are unset', (t) => {
  t.throws(() => UnsignedAmount.fromV2(5n).toV1(), { message: /decimal places must be set/ })
})

test('maybeToV1 throws (not aborts) when the decimal places are unset', (t) => {
  // An unset factor is a programming error, so this must throw rather than return null.
  t.throws(() => UnsignedAmount.fromV2(5n).maybeToV1(), {
    message: /decimal places must be set/,
  })
})

test('toVersion(V1) throws (not aborts) when the decimal places are unset', (t) => {
  t.throws(() => UnsignedAmount.fromV2(5n).toVersion(TokenAmountVersion.V1), {
    message: /decimal places must be set/,
  })
})
