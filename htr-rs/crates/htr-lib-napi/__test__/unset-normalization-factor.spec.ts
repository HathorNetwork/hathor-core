// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

import test from 'ava'
import { UnsignedAmount, TokenAmountVersion } from '../index.js'

// This file deliberately NEVER calls setNormalizationFactor. ava runs each spec file in its own
// worker process (workerThreads: false), so the process-global normalization-factor OnceLock stays
// unset for every test here. Each factor-dependent method must therefore throw a *catchable* error
// rather than aborting the Node process — that is the #[napi(catch_unwind)] contract. If any of
// these aborted instead (a missing catch_unwind), the ava worker would crash and the run would fail
// outright, so a passing t.throws is itself the proof that the process was not aborted.

test('factor-independent constructors do not need the normalization factor', (t) => {
  t.notThrows(() => UnsignedAmount.fromV2(5n))
  t.notThrows(() => UnsignedAmount.zero())
})

test('fromV1 throws (not aborts) when the factor is unset', (t) => {
  t.throws(() => UnsignedAmount.fromV1(1n), { message: /normalization factor must be set/ })
})

test('fromVersion(V1) throws (not aborts) when the factor is unset', (t) => {
  t.throws(() => UnsignedAmount.fromVersion(1n, TokenAmountVersion.V1), {
    message: /normalization factor must be set/,
  })
})

test('toV1 throws (not aborts) when the factor is unset', (t) => {
  t.throws(() => UnsignedAmount.fromV2(5n).toV1(), { message: /normalization factor must be set/ })
})

test('maybeToV1 throws (not aborts) when the factor is unset', (t) => {
  // An unset factor is a programming error, so this must throw rather than return null.
  t.throws(() => UnsignedAmount.fromV2(5n).maybeToV1(), {
    message: /normalization factor must be set/,
  })
})

test('toVersion(V1) throws (not aborts) when the factor is unset', (t) => {
  t.throws(() => UnsignedAmount.fromV2(5n).toVersion(TokenAmountVersion.V1), {
    message: /normalization factor must be set/,
  })
})
